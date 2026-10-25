package vauthlogin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	nyksobject "github.com/131/nyks/v6/object"
	nyksstring "github.com/131/nyks/v6/string"
	"gopkg.in/yaml.v3"
)

// RC is the private authentication view, with the complete JSON snapshot retained.
type RC struct {
	VaultAddr  string   `json:"vault_addr" yaml:"vault_addr"`
	SSHAuth    *SSHAuth `json:"ssh_auth" yaml:"ssh_auth"`
	JWTAuth    *JWTAuth `json:"jwt_auth" yaml:"jwt_auth"`
	TokenCache *bool    `json:"token_cache" yaml:"token_cache"`
	// KnownVaults lists, in ~/.vauthrc, the Vault addresses a project's
	// ./.vauthrc is allowed to select.
	KnownVaults []string `json:"known_vaults" yaml:"known_vaults"`

	// document is the unexpanded JSON-compatible configuration snapshot.
	document []byte
}

// AuthKey composes explicit authentication fields; document order is irrelevant.
func (rc *RC) AuthKey() string {
	var ssh, jwt string
	if rc.SSHAuth != nil {
		ssh = rc.SSHAuth.hash()
	}
	if rc.JWTAuth != nil {
		jwt = rc.JWTAuth.hash()
	}
	return ssh + "/" + jwt
}

// SSHAuth configures the Vault ssh auth plugin (nonce challenge).
type SSHAuth struct {
	Path string `json:"path" yaml:"path"`
	Role string `json:"role" yaml:"role"`
}

// JWTAuth configures a Vault jwt login.
type JWTAuth struct {
	Path string `json:"path" yaml:"path"`
	JWT  string `json:"jwt" yaml:"jwt"`
	Role string `json:"role" yaml:"role"`
}

func (auth SSHAuth) hash() string {
	return "ssh/" + auth.Role + "/" + auth.Path
}

func (auth JWTAuth) hash() string {
	return "jwt/" + auth.Role + "/" + auth.Path + "/" + auth.JWT
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

// KnownVault reports whether addr is the vault_addr or one of the
// known_vaults of the user's ~/.vauthrc at home, or the environment's
// VAULT_ADDR. The environment is trusted even without a readable home file.
func KnownVault(addr, home string, environ map[string]string) bool {
	addr = strings.Trim(addr, "/")
	if known := environ["VAULT_ADDR"]; known != "" && strings.Trim(known, "/") == addr {
		return true
	}
	body, err := os.ReadFile(filepath.Join(home, ".vauthrc"))
	if err != nil {
		return false
	}
	rc, err := ParseRC(body, "~/.vauthrc", environ)
	if err != nil {
		return false
	}
	for _, known := range append([]string{rc.VaultAddr}, rc.KnownVaults...) {
		if known != "" && strings.Trim(known, "/") == addr {
			return true
		}
	}
	return false
}

// YAML timestamps stay strings, as they do in the Node YAML parser.
func timestampStrings(node *yaml.Node) {
	if node.Tag == "!!timestamp" {
		node.Tag = "!!str"
	}
	for _, child := range node.Content {
		timestampStrings(child)
	}
}

// ParseRC parses a .vauthrc body and expands its $${env.X} macros against
// environ for the private authentication view; the complete JSON document is retained.
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
	timestampStrings(&document)
	var complete map[string]any
	if err := document.Decode(&complete); err != nil {
		return nil, fmt.Errorf("Could not parse %s: %w", file, err)
	}
	jsonDocument, err := json.Marshal(complete)
	if err != nil {
		return nil, fmt.Errorf("Configuration is not JSON-compatible")
	}
	auth := map[string]any{}
	for _, key := range []string{"vault_addr", "ssh_auth", "jwt_auth", "token_cache", "known_vaults"} {
		if value, ok := complete[key]; ok {
			auth[key] = value
		}
	}
	nyksobject.Walk(auth, func(value string) any {
		return nyksstring.ReplaceEnv(value, map[string]any{"env": environ})
	})
	body, err = json.Marshal(auth)
	if err != nil {
		return nil, fmt.Errorf("Could not parse %s: %w", file, err)
	}
	rc := RC{document: jsonDocument}
	if err := json.Unmarshal(body, &rc); err != nil {
		return nil, fmt.Errorf("Could not parse %s: %w", file, err)
	}
	return &rc, nil
}
