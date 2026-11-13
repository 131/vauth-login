package vauthlogin

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func memoryHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home
}

func TestNewFromRCSnapshotsAndNativeDefaults(t *testing.T) {
	home := memoryHome(t)
	t.Setenv("VAULT_ADDR", "https://ambient.example.test")
	t.Setenv("VAULT_TOKEN", "ambient-token")
	// Neither VAUTHRC selection nor caller-provided HOME selects the inline RC's trust file.
	file := filepath.Join(t.TempDir(), ".vauthrc")
	if err := os.WriteFile(file, []byte("invalid: ["), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAUTHRC", file)
	environ := map[string]string{
		"VAUTHRC": file, "HOME": t.TempDir(), "USERPROFILE": t.TempDir(),
		"VAULT_ADDR": "https://inline.example.test", "VAULT_TOKEN": "caller-token",
		"ROLE": "MiXeD.User", "SSH_AUTH_SOCK": agentSocket,
	}
	body := []byte(`vault_addr: $${env.VAULT_ADDR}
ssh_auth: {role: '$${env.ROLE}', path: CustomSSH}
jwt_auth: {role: KeepJWTCase, jwt: fixture-jwt}
delegate: [profile-ro]
env: {map: {KEY: '$${profile.KEY}'}}
extra: [{nested: true}]
`)
	v, err := NewFromRC(body, environ)
	if err != nil {
		t.Fatal(err)
	}
	equal(t, v.HomeDir, home)
	equal(t, v.CacheDir, filepath.Join(home, ".vauth", "tokens"))
	equal(t, v.Agent, agentSocket)
	equal(t, v.TokenCache, true)
	equal(t, v.unknownVault, false)
	equal(t, v.VAULT_ADDR(), "https://inline.example.test")
	equal(t, v.VAULT_TOKEN(), "caller-token")
	equal(t, os.Getenv("VAULT_ADDR"), "https://ambient.example.test")
	equal(t, os.Getenv("VAULT_TOKEN"), "ambient-token")
	equal(t, v.rc.SSHAuth.Role, "mixed.user")
	equal(t, v.rc.SSHAuth.Path, "CustomSSH")
	equal(t, v.rc.JWTAuth.Role, "KeepJWTCase")
	equal(t, v.RC()["vault_addr"], "$${env.VAULT_ADDR}")
	equal(t, v.RC()["ssh_auth"].(map[string]any)["role"], "$${env.ROLE}")
	equal(t, v.RC()["env"].(map[string]any)["map"].(map[string]any)["KEY"], "$${profile.KEY}")
	if _, ok := v.RC()["extra"]; !ok {
		t.Fatal("inline RC lost uninterpreted sections")
	}
	// Caller data, raw RC snapshots and client environment are independent.
	environ["ROLE"] = "changed"
	v.Environ["VAULT_TOKEN"] = "client-change"
	body[0] = '!'
	view := v.RC()
	view["env"].(map[string]any)["map"].(map[string]any)["KEY"] = "changed"
	equal(t, v.Environ["ROLE"], "MiXeD.User")
	equal(t, environ["VAULT_TOKEN"], "caller-token")
	equal(t, v.RC()["vault_addr"], "$${env.VAULT_ADDR}")
	equal(t, v.RC()["env"].(map[string]any)["map"].(map[string]any)["KEY"], "$${profile.KEY}")
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	equal(t, len(entries), 0) // Construction writes neither RC nor token cache.
}

func TestNewFromRCEnvironmentAndCacheOptions(t *testing.T) {
	memoryHome(t)
	t.Setenv("VAUTHRC", filepath.Join(t.TempDir(), "missing.vauthrc"))
	t.Setenv("VAULT_ADDR", "https://ambient.example.test")
	t.Setenv("VAULT_TOKEN", "ambient-token")
	t.Setenv("SSH_AUTH_SOCK", agentSocket)
	v, err := NewFromRC(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	equal(t, v.VAULT_ADDR(), "https://ambient.example.test")
	equal(t, v.VAULT_TOKEN(), "ambient-token")
	equal(t, v.Agent, agentSocket)
	equal(t, v.TokenCache, true)
	equal(t, len(v.RC()), 0)

	v, err = NewFromRC(nil, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	equal(t, v.VAULT_ADDR(), "")
	equal(t, v.VAULT_TOKEN(), "")

	for _, tc := range []struct {
		name  string
		body  string
		agent string
		cache bool
	}{
		{"explicitly disabled cache", "token_cache: false", agentSocket, false},
		{"enabled cache", "token_cache: true", agentSocket, true},
		{"explicitly disabled agent", "token_cache: true", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := NewFromRC([]byte(tc.body), map[string]string{"SSH_AUTH_SOCK": tc.agent})
			if err != nil {
				t.Fatal(err)
			}
			equal(t, v.Agent, tc.agent)
			equal(t, v.TokenCache, tc.cache)
		})
	}
}

func TestNewFromRCParsing(t *testing.T) {
	memoryHome(t)
	for _, body := range []string{
		"vault_addr: [", "- not-a-mapping", "ssh_auth: wrong-type", "token_cache: wrong-type", "extra: [.inf]",
	} {
		if v, err := NewFromRC([]byte(body), map[string]string{}); err == nil || v != nil {
			t.Fatalf("invalid RC accepted: %q", body)
		}
	}
	v, err := NewFromRC([]byte(`{"ssh_auth":{"role":"MiXeD"},"env":{"map":{"KEY":"original"}}}`), map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	equal(t, v.rc.SSHAuth.Role, "mixed")
	equal(t, v.RC()["ssh_auth"].(map[string]any)["role"], "MiXeD")
	equal(t, v.RC()["env"].(map[string]any)["map"].(map[string]any)["KEY"], "original")
}

func TestNewFromRCHomeTrust(t *testing.T) {
	for _, tc := range []struct {
		name    string
		homeRC  string
		envAddr string
		trusted bool
	}{
		{"missing home", "", "", false},
		{"invalid home", "known_vaults: [", "", false},
		{"unrelated home", "vault_addr: https://other.example.test", "", false},
		{"home vault_addr", "vault_addr: $${env.TEST_VAULT}/", "", true},
		{"home known_vaults", "vault_addr: https://other.example.test\nknown_vaults: ['$${env.TEST_VAULT}/']", "", true},
		{"environment trust without home", "", "$TEST_VAULT/", true},
		{"unrelated environment", "", "https://other.example.test", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := memoryHome(t)
			f := newFixture(t, fixtureOptions{})
			if tc.homeRC != "" {
				if err := os.WriteFile(filepath.Join(home, ".vauthrc"), []byte(tc.homeRC), 0600); err != nil {
					t.Fatal(err)
				}
			}
			// Even a matching ambient address or caller's HOME cannot replace the explicit snapshot/native home.
			t.Setenv("VAULT_ADDR", f.server.URL)
			decoyHome := t.TempDir()
			if err := os.WriteFile(filepath.Join(decoyHome, ".vauthrc"), []byte("vault_addr: "+f.server.URL), 0600); err != nil {
				t.Fatal(err)
			}
			environ := map[string]string{
				"HOME": decoyHome, "USERPROFILE": decoyHome, "TEST_VAULT": f.server.URL,
				"VAULT_ADDR":    strings.ReplaceAll(tc.envAddr, "$TEST_VAULT", f.server.URL),
				"SSH_AUTH_SOCK": agentSocket,
			}
			// The inline known_vaults entry must not authorize its own address.
			body := "vault_addr: " + f.server.URL + "\nknown_vaults: ['" + f.server.URL + "']\njwt_auth: {jwt: fixture-jwt, role: test-role}\ntoken_cache: false\n"
			v, err := NewFromRC([]byte(body), environ)
			if err != nil {
				t.Fatal(err)
			}
			v.Stderr = io.Discard
			equal(t, v.HomeDir, home)
			equal(t, v.unknownVault, !tc.trusted)
			_, err = v.Connect(true)
			if tc.trusted {
				if err != nil {
					t.Fatal(err)
				}
				equal(t, v.VAULT_TOKEN(), "fresh-token")
				equalPaths(t, f.paths(), "/v1/auth/jwt/login")
			} else {
				if err == nil || !strings.Contains(err.Error(), "known_vaults") || !strings.Contains(err.Error(), "<memory>") {
					t.Fatalf("unknown inline Vault was not refused: %v", err)
				}
				_, _, err = v.Request("GET", "auth/token/lookup-self", "inherited-token", nil, 200)
				if err == nil {
					t.Fatal("Request bypassed inline Vault trust")
				}
				equal(t, len(f.requests), 0)
			}
		})
	}
}

func TestNewFromRCDoesNotMergeHomeConfiguration(t *testing.T) {
	home := memoryHome(t)
	if err := os.WriteFile(filepath.Join(home, ".vauthrc"), []byte(`vault_addr: https://home.example.test
jwt_auth: {jwt: home-jwt, role: home-role}
env: {map: {HOME_SECRET: secret}}
known_vaults: ['https://inline.example.test']
`), 0600); err != nil {
		t.Fatal(err)
	}
	v, err := NewFromRC([]byte("vault_addr: https://inline.example.test\nenv: {map: {INLINE: value}}"), map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	equal(t, v.unknownVault, false)
	equal(t, v.rc.JWTAuth == nil, true)
	if !reflect.DeepEqual(v.RC()["env"], map[string]any{"map": map[string]any{"INLINE": "value"}}) {
		t.Fatal("home environment was merged into the inline RC")
	}
	v.Stderr = io.Discard
	token, err := v.Connect(false)
	if err != nil {
		t.Fatal(err)
	}
	equal(t, token, "") // Home authentication is not an implicit fallback.
}

func TestNewFromRCInheritedTokenStillOffline(t *testing.T) {
	memoryHome(t)
	f := newFixture(t, fixtureOptions{})
	v, err := NewFromRC([]byte("vault_addr: "+f.server.URL), map[string]string{"VAULT_TOKEN": "caller-token"})
	if err != nil {
		t.Fatal(err)
	}
	v.Stderr = io.Discard
	equal(t, v.unknownVault, true)
	token, err := v.Connect(false)
	if err != nil {
		t.Fatal(err)
	}
	equal(t, token, "caller-token")
	if _, err := v.LookupSelf(token); err == nil {
		t.Fatal("inherited token authorized an unknown Vault")
	}
	equal(t, len(f.requests), 0)
}

func TestNewFromRCRequiresNativeHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", "")
	} else {
		t.Setenv("HOME", "")
	}
	v, err := NewFromRC(nil, map[string]string{"HOME": t.TempDir(), "USERPROFILE": t.TempDir()})
	if err == nil || v != nil || !strings.Contains(err.Error(), "home directory") {
		t.Fatalf("caller environment replaced the missing native home: %v", err)
	}
}

func TestNewFromRCMatchesFileConstructor(t *testing.T) {
	memoryHome(t)
	body := []byte(`vault_addr: https://vault.example.test
ssh_auth: {role: '$${env.ROLE}'}
jwt_auth: {jwt: fixture-jwt, role: KeepJWTCase}
token_cache: false
env: {map: {KEY: '$${profile.KEY}'}}
`)
	file := filepath.Join(t.TempDir(), ".vauthrc")
	if err := os.WriteFile(file, body, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAUTHRC", file)
	t.Setenv("VAULT_ADDR", "https://vault.example.test")
	t.Setenv("VAULT_TOKEN", "caller-token")
	t.Setenv("ROLE", "MiXeD.User")
	t.Setenv("SSH_AUTH_SOCK", agentSocket)
	fromFile, err := New()
	if err != nil {
		t.Fatal(err)
	}
	fromMemory, err := NewFromRC(body, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromFile.RC(), fromMemory.RC()) {
		t.Fatal("file and memory RC snapshots differ")
	}
	equal(t, fromMemory.rc.AuthKey(), fromFile.rc.AuthKey())
	equal(t, fromMemory.VAULT_ADDR(), fromFile.VAULT_ADDR())
	equal(t, fromMemory.VAULT_TOKEN(), fromFile.VAULT_TOKEN())
	equal(t, fromMemory.Agent, fromFile.Agent)
	equal(t, fromMemory.TokenCache, fromFile.TokenCache)
	equal(t, fromMemory.CacheDir, fromFile.CacheDir)
	equal(t, fromMemory.tokenCacheFile(), fromFile.tokenCacheFile())
}
