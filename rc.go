package vauthlogin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// RC is the parsed .vauthrc, after $${env.X} expansion.
type RC struct {
	VaultAddr  string   `yaml:"vault_addr"`
	SSHAuth    *SSHAuth `yaml:"ssh_auth"`
	JWTAuth    *JWTAuth `yaml:"jwt_auth"`
	TokenCache *bool    `yaml:"token_cache"`

	// authKey is the JSON of {ssh_auth, jwt_auth} in document order, as
	// JSON.stringify would render them: it isolates the token cache.
	authKey string
}

// AuthKey renders ssh_auth and jwt_auth as JSON members, in the order of the
// parsed document. Programmatic configurations are rendered from the structs.
func (rc *RC) AuthKey() string {
	if rc.authKey != "" {
		return rc.authKey
	}
	var members []string
	if rc.SSHAuth != nil {
		members = append(members, `"ssh_auth":`+jsonMembers([][2]string{{"path", rc.SSHAuth.Path}, {"role", rc.SSHAuth.Role}}))
	}
	if rc.JWTAuth != nil {
		members = append(members, `"jwt_auth":`+jsonMembers([][2]string{{"path", rc.JWTAuth.Path}, {"jwt", rc.JWTAuth.JWT}, {"role", rc.JWTAuth.Role}}))
	}
	return strings.Join(members, ",")
}

func jsonMembers(pairs [][2]string) string {
	var out bytes.Buffer
	out.WriteByte('{')
	for _, pair := range pairs {
		if pair[1] == "" {
			continue
		}
		if out.Len() > 1 {
			out.WriteByte(',')
		}
		out.Write(jsonString(pair[0]))
		out.WriteByte(':')
		out.Write(jsonString(pair[1]))
	}
	out.WriteByte('}')
	return out.String()
}

// SSHAuth configures the Vault ssh auth plugin (nonce challenge).
type SSHAuth struct {
	Path string `yaml:"path"`
	Role string `yaml:"role"`
}

// JWTAuth configures a Vault jwt login.
type JWTAuth struct {
	Path string `yaml:"path"`
	JWT  string `yaml:"jwt"`
	Role string `yaml:"role"`
}

// Lookup resolves dotted paths ($${env.X}) in nested string maps.
type Lookup map[string]any

func (dict Lookup) get(path string) (string, bool) {
	var current any = map[string]any(dict)
	for _, part := range strings.Split(path, ".") {
		switch node := current.(type) {
		case map[string]any:
			value, ok := node[part]
			if !ok {
				return "", false
			}
			current = value
		case map[string]string:
			value, ok := node[part]
			if !ok {
				return "", false
			}
			current = value
		case Lookup:
			value, ok := node[part]
			if !ok {
				return "", false
			}
			current = value
		default:
			return "", false
		}
	}
	return stringify(current)
}

func stringify(value any) (string, bool) {
	switch v := value.(type) {
	case nil:
		return "", false
	case string:
		return v, true
	case bool:
		return strconv.FormatBool(v), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case json.Number:
		return v.String(), true
	}
	body, err := json.Marshal(value)
	if err != nil {
		return "", false
	}
	return string(body), true
}

var macroPattern = regexp.MustCompile(`(?i)\$\$([a-z0-9._-]+)|\$\$\{([^}]+)\}`)

// ReplaceEnv expands $$key and $${key} macros against dict (nyks
// string/replaceEnv semantics): unknown keys stay, expansions recurse.
func ReplaceEnv(str string, dict Lookup) string {
	for depth := 0; depth < 16; depth++ {
		touched := false
		str = macroPattern.ReplaceAllStringFunc(str, func(macro string) string {
			match := macroPattern.FindStringSubmatch(macro)
			key := match[1]
			if key == "" {
				key = match[2]
			}
			value, ok := dict.get(key)
			if !ok {
				return macro
			}
			touched = true
			return value
		})
		if !touched {
			break
		}
	}
	return str
}

// walk expands every scalar string of a YAML tree in place.
func walk(node *yaml.Node, process func(string) string) {
	if node.Kind == yaml.ScalarNode {
		if node.Tag == "!!str" || node.Tag == "" {
			node.Value = process(node.Value)
		}
		return
	}
	for _, child := range node.Content {
		walk(child, process)
	}
}

// jsonNode renders a YAML subtree as JSON.stringify would after yaml.parse.
func jsonNode(node *yaml.Node, out *bytes.Buffer) {
	switch node.Kind {
	case yaml.DocumentNode, yaml.AliasNode:
		if node.Kind == yaml.AliasNode {
			jsonNode(node.Alias, out)
		} else if len(node.Content) > 0 {
			jsonNode(node.Content[0], out)
		}
	case yaml.MappingNode:
		out.WriteByte('{')
		for i := 0; i+1 < len(node.Content); i += 2 {
			if i > 0 {
				out.WriteByte(',')
			}
			out.Write(jsonString(node.Content[i].Value))
			out.WriteByte(':')
			jsonNode(node.Content[i+1], out)
		}
		out.WriteByte('}')
	case yaml.SequenceNode:
		out.WriteByte('[')
		for i, child := range node.Content {
			if i > 0 {
				out.WriteByte(',')
			}
			jsonNode(child, out)
		}
		out.WriteByte(']')
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!int", "!!float", "!!bool":
			var value any
			if node.Decode(&value) == nil {
				if text, ok := stringify(value); ok {
					out.WriteString(text)
					return
				}
			}
			out.Write(jsonString(node.Value))
		case "!!null":
			out.WriteString("null")
		default:
			out.Write(jsonString(node.Value))
		}
	}
}

// jsonString encodes like JSON.stringify (no HTML escaping).
func jsonString(value string) []byte {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.Encode(value)
	return bytes.TrimRight(out.Bytes(), "\n")
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		node = node.Content[0]
	}
	if node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

// LocateRC returns the first existing configuration file among VAUTHRC,
// ./.vauthrc and ~/.vauthrc, or an empty string.
func LocateRC(environ map[string]string, cwd, home string) string {
	candidates := []string{environ["VAUTHRC"], filepath.Join(cwd, ".vauthrc"), filepath.Join(home, ".vauthrc")}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// ParseRC parses a .vauthrc body and expands its $${env.X} macros against
// environ. All other configuration sections are ignored.
func ParseRC(body []byte, file string, environ map[string]string) (*RC, error) {
	var document yaml.Node
	if err := yaml.Unmarshal(body, &document); err != nil {
		return nil, fmt.Errorf("Could not parse %s: %w", file, err)
	}
	if len(document.Content) == 0 {
		return &RC{}, nil
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("Could not parse %s: expected a mapping", file)
	}
	var content []*yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		switch root.Content[i].Value {
		case "vault_addr", "ssh_auth", "jwt_auth", "token_cache":
			content = append(content, root.Content[i], root.Content[i+1])
		}
	}
	root.Content = content
	walk(&document, func(value string) string {
		return ReplaceEnv(value, Lookup{"env": environ})
	})
	rc := RC{}
	if err := document.Decode(&rc); err != nil {
		return nil, fmt.Errorf("Could not parse %s: %w", file, err)
	}
	var key bytes.Buffer
	for i, name := range []string{"ssh_auth", "jwt_auth"} {
		node := mappingValue(&document, name)
		if node == nil || node.Tag == "!!null" {
			continue
		}
		if i > 0 && key.Len() > 0 {
			key.WriteByte(',')
		}
		key.Write(jsonString(name))
		key.WriteByte(':')
		jsonNode(node, &key)
	}
	rc.authKey = key.String()
	return &rc, nil
}
