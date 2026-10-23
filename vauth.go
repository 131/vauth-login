// Package vauthlogin authenticates to Vault using ssh-agent or JWT and
// caches the token with ssh-agent-crypt. It does not resolve environments.
package vauthlogin

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	sshagentcrypt "github.com/131/ssh-agent-crypt"
	"github.com/Masterminds/semver/v3"
)

// PackageName is the npm name a project uses to pin vauth:
// `"dependencies": {"vauth-login": "^1.0.0"}` in its package.json.
const PackageName = "vauth-login"

// Version is the running version (ldflags -X or debug.ReadBuildInfo), checked
// by New against the current directory's package.json; empty or non-semver
// values ("(devel)") skip the check.
var Version string

// Vauth is a configured client. New builds one from the process environment;
// fields may be set directly for programmatic use.
type Vauth struct {
	RC         RC
	VaultAddr  string
	VaultToken string
	// Agent is the ssh-agent address; empty disables ssh authentication.
	Agent string
	// TokenCache enables the on-disk token cache in CacheDir.
	TokenCache bool
	CacheDir   string
	HomeDir    string
	// Environ is the process environment snapshot used for macros.
	Environ map[string]string
	// Stderr defaults to the process error stream.
	Stderr     io.Writer
	HTTPClient *http.Client
	// Now overrides the clock (tests).
	Now func() time.Time
	// RCFile is the configuration file New selected, if any.
	RCFile string
	// Confirm is asked once before the first request to a Vault selected by
	// a project's ./.vauthrc that ~/.vauthrc does not know; nil prompts on
	// the terminal and refuses without one.
	Confirm func(addr, file string) (bool, error)

	connected    bool
	unknownVault bool
}

// token is an established token with its remaining validity.
type token struct {
	Value         string
	TTL           float64 // seconds; 0 means unlimited
	LeaseDuration int64
	Renewable     bool
}

// CheckProjectVersion fails when manifest (a package.json) declares a
// dependency on PackageName that version does not satisfy. A missing manifest,
// dependency or unparseable version is not an error.
func CheckProjectVersion(manifest, version string) error {
	body, err := os.ReadFile(manifest)
	if err != nil {
		return nil
	}
	var pkg struct {
		Dependencies map[string]string `json:"dependencies"`
	}
	if json.Unmarshal(body, &pkg) != nil {
		return nil
	}
	required, ok := pkg.Dependencies[PackageName]
	if !ok || required == "" {
		return nil
	}
	current, err := semver.NewVersion(version)
	if err != nil {
		return nil
	}
	constraint, err := semver.NewConstraint(required)
	if err != nil {
		return fmt.Errorf("Invalid %s version requirement '%s' in %s", PackageName, required, manifest)
	}
	if !constraint.Check(current) {
		return fmt.Errorf("Unsupported %s version %s (project requires %s)", PackageName, version, required)
	}
	return nil
}

// Environ converts os.Environ() into a map.
func Environ() map[string]string {
	environ := map[string]string{}
	for _, entry := range os.Environ() {
		if key, value, ok := strings.Cut(entry, "="); ok {
			environ[key] = value
		}
	}
	return environ
}

// New loads the configuration from the environment and the first .vauthrc
// found (VAUTHRC, ./.vauthrc, ~/.vauthrc).
func New() (*Vauth, error) {
	environ := Environ()
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	if err := CheckProjectVersion(filepath.Join(cwd, "package.json"), Version); err != nil {
		return nil, err
	}
	v := &Vauth{
		Agent:      sshagentcrypt.DefaultAgentAddress(),
		TokenCache: true,
		HomeDir:    home,
		CacheDir:   filepath.Join(home, ".vauth", "tokens"),
		Environ:    environ,
	}
	if file := LocateRC(environ, cwd, home); file != "" {
		body, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		rc, err := ParseRC(body, file, environ)
		if err != nil {
			return nil, err
		}
		v.RC = *rc
		v.RCFile = file
		// A project's ./.vauthrc chooses the Vault; the user vouches for it in ~/.vauthrc.
		if file == filepath.Join(cwd, ".vauthrc") && file != filepath.Join(home, ".vauthrc") && rc.VaultAddr != "" {
			v.unknownVault = !KnownVault(rc.VaultAddr, home, environ)
		}
	}
	if v.RC.TokenCache != nil && !*v.RC.TokenCache {
		v.TokenCache = false
	}
	if v.Agent == "" {
		v.TokenCache = false
	}
	v.VaultAddr = v.RC.VaultAddr
	if v.VaultAddr == "" {
		v.VaultAddr = environ["VAULT_ADDR"]
	}
	v.VaultToken = environ["VAULT_TOKEN"]
	if v.VaultAddr == "" {
		fmt.Fprintln(v.stderr(), "Not bound to any vault")
	}
	return v, nil
}

func (v *Vauth) stderr() io.Writer {
	if v.Stderr != nil {
		return v.Stderr
	}
	return os.Stderr
}

func (v *Vauth) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Vauth) debug(format string, args ...any) {
	if strings.Contains(v.Environ["DEBUG"], "vauth-login") {
		fmt.Fprintf(v.stderr(), "vauth-login "+format+"\n", args...)
	}
}

// trustVault asks once before the first request to an unknown Vault.
func (v *Vauth) trustVault() error {
	if !v.unknownVault {
		return nil
	}
	addr := strings.Trim(v.VaultAddr, "/")
	confirm := v.Confirm
	if confirm == nil {
		confirm = v.promptVault
	}
	ok, err := confirm(addr, v.RCFile)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("Unknown vault %s: refused", addr)
	}
	v.unknownVault = false
	return nil
}

const knownVaultsHint = "Add it to known_vaults in ~/.vauthrc to stop being asked."

func (v *Vauth) promptVault(addr, file string) (bool, error) {
	where := fmt.Sprintf("Unknown vault %s, selected by %s", addr, file)
	if info, err := os.Stdin.Stat(); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return false, fmt.Errorf("%s. %s", where, knownVaultsHint)
	}
	fmt.Fprintf(v.stderr(), "%s.\n%s\nContinue? [y/N] ", where, knownVaultsHint)
	answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
}

func (v *Vauth) tokenStatus(operation string, token *token) {
	validity := "valid indefinitely"
	if token.TTL != 0 {
		validity = HumanDiff(token.TTL, 2)
	}
	fmt.Fprintf(v.stderr(), "Vauth token: %s · %s\n", operation, validity)
}

// Connect establishes VaultToken: an inherited token is returned as is;
// otherwise the cached one (renewed in the last third of its lease), then a
// new login. With renew, a new login is forced. Without an authentication
// method, no token is used.
func (v *Vauth) Connect(renew bool) (string, error) {
	if v.connected && !renew {
		return v.VaultToken, nil
	}
	// An inherited token is the caller's: never looked up, renewed or persisted.
	if v.VaultToken != "" && !renew {
		fmt.Fprintln(v.stderr(), "Vauth token: inherited")
		v.connected = true
		return v.VaultToken, nil
	}
	if v.RC.SSHAuth == nil && v.RC.JWTAuth == nil {
		v.VaultToken = ""
		return "", nil
	}
	v.connected = false

	cached := v.readTokenCache()
	hadToken := cached != nil
	operation := "reused"
	now := v.now().UnixMilli()
	if renew || (cached != nil && cached.ExpiresAt != nil && *cached.ExpiresAt <= now) {
		cached = nil
	}

	var established *token
	if cached != nil {
		established = &token{Value: cached.Token, LeaseDuration: cached.LeaseDuration, Renewable: cached.Renewable}
		if cached.ExpiresAt != nil {
			established.TTL = float64(*cached.ExpiresAt-now) / 1000
		}
		if established.TTL > 0 && established.TTL <= float64(established.LeaseDuration)/3 {
			if established.Renewable {
				if err := v.trustVault(); err != nil {
					return "", err
				}
				renewed, err := v.renewToken(cached.Token)
				if err := reauthenticable(err); err != nil {
					return "", err
				}
				if err != nil {
					established = nil
				} else {
					established = fromAuth(renewed)
					operation = "renewed"
				}
			} else {
				established = nil
			}
		}
	}

	if established == nil {
		if err := v.trustVault(); err != nil {
			return "", err
		}
		var granted *auth
		var err error
		if v.RC.SSHAuth != nil && v.Agent != "" {
			granted, err = v.loginVaultSSH(v.RC.SSHAuth)
		} else if v.RC.JWTAuth != nil && v.RC.JWTAuth.JWT != "" {
			path := v.RC.JWTAuth.Path
			if path == "" {
				path = "jwt"
			}
			granted, err = v.loginVault(path, map[string]string{"jwt": v.RC.JWTAuth.JWT, "role": v.RC.JWTAuth.Role})
		}
		if err != nil {
			return "", err
		}
		if granted == nil {
			if renew || hadToken {
				return "", errors.New("Could not login to vault: no authentication method available")
			}
		} else {
			established = fromAuth(granted)
		}
		operation = "generated"
	}

	v.VaultToken = ""
	if established != nil {
		if operation != "reused" {
			v.saveTokenCache(established)
		}
		v.tokenStatus(operation, established)
		v.VaultToken = established.Value
	}
	v.connected = true
	return v.VaultToken, nil
}

// reauthenticable returns err unless it is an invalid token (400/403), in
// which case a new login is appropriate.
func reauthenticable(err error) error {
	var failure *HTTPError
	if err == nil || (errors.As(err, &failure) && (failure.Status == 400 || failure.Status == 403)) {
		return nil
	}
	return err
}

func fromAuth(granted *auth) *token {
	return &token{Value: granted.ClientToken, TTL: float64(granted.LeaseDuration), LeaseDuration: granted.LeaseDuration, Renewable: granted.Renewable}
}
