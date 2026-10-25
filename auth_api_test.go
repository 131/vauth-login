package vauthlogin

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestAuthenticationOnlyRC(t *testing.T) {
	body := []byte("vault_addr: https://vault.example.test\nssh_auth: {role: '$${env.ROLE}'}\nenv: {map: 'not a mapping', gitlab: true}\n")
	rc, err := ParseRC(body, ".vauthrc", map[string]string{"ROLE": "test-role"})
	if err != nil {
		t.Fatal(err)
	}
	equal(t, rc.SSHAuth.Role, "test-role")
	equal(t, rc.VaultAddr, "https://vault.example.test")
	equal(t, rc.AuthKey(), `ssh/test-role//`)
}

func TestConfigurationPrecedence(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	explicit := filepath.Join(t.TempDir(), "explicit.vauthrc")
	for _, name := range []string{explicit, filepath.Join(cwd, ".vauthrc"), filepath.Join(home, ".vauthrc")} {
		if err := os.WriteFile(name, []byte("token_cache: false\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	equal(t, LocateRC(map[string]string{"VAUTHRC": explicit}, cwd, home), explicit)
	equal(t, LocateRC(nil, cwd, home), filepath.Join(cwd, ".vauthrc"))
	equal(t, LocateRC(nil, t.TempDir(), home), filepath.Join(home, ".vauthrc"))
	equal(t, LocateRC(nil, t.TempDir(), t.TempDir()), "")
}

func TestPublicLookupAndTransport(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	v := f.client()
	token := connect(t, v, false)
	info, err := v.LookupSelf(token)
	if err != nil {
		t.Fatal(err)
	}
	equal(t, info.EntityID, "test-entity")
	equal(t, info.LeaseDuration, int64(24*hour))
	equal(t, v.vaultURL("/auth/token/lookup-self"), f.server.URL+"/v1/auth/token/lookup-self")
	status, _, err := v.Request("GET", "auth/token/lookup-self", token, nil, 200)
	if err != nil {
		t.Fatal(err)
	}
	equal(t, status, 200)
}

func TestTransportRejectsRedirect(t *testing.T) {
	target := newFixture(t, fixtureOptions{})
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.server.URL+"/v1/auth/token/lookup-self")
		w.WriteHeader(302)
		w.Write([]byte("secret-server-response"))
	}))
	defer redirect.Close()
	v := &Vauth{vaultAddr: redirect.URL}
	_, _, err := v.Request("GET", "redirect", "secret-token", nil, 200)
	var failure *HTTPError
	if !errors.As(err, &failure) {
		t.Fatalf("wrong error type: %T", err)
	}
	equal(t, failure.Status, 302)
	if bytes.Contains([]byte(err.Error()), []byte("secret")) {
		t.Fatal("error leaks server response")
	}
	equal(t, len(target.requests), 0)
	equal(t, defaultHTTPClient.Timeout, 60*time.Second)
}

func TestConnectReturnsToken(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	v := f.client()
	var status bytes.Buffer
	v.Stderr = &status
	token, err := v.Connect(true)
	if err != nil {
		t.Fatal(err)
	}
	equal(t, token, "fresh-token")
	equal(t, v.vaultToken, token)
	equal(t, status.String(), "Vauth token: generated · 1d\n")
}

func TestProjectVersionChecksOnlyLogin(t *testing.T) {
	file := filepath.Join(t.TempDir(), "package.json")
	os.WriteFile(file, []byte(`{"dependencies":{"vvauth":"^100.0.0","vauth-login":"^1.0.0"}}`), 0600)
	if err := CheckProjectVersion(file, "v1.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := CheckProjectVersion(file, "v2.0.0"); err == nil {
		t.Fatal("incompatible version accepted")
	}
}

func TestLoginLeaseMustBeExplicit(t *testing.T) {
	for _, body := range []string{`{}`, `{"auth":null}`, `{"auth":{"client_token":"token"}}`, `{"auth":{"client_token":"token","lease_duration":null}}`, `{"auth":{"client_token":"token","lease_duration":-1}}`} {
		if _, err := parseAuth([]byte(body), "Invalid Vault login response"); err == nil {
			t.Fatal("invalid lease accepted")
		}
	}
	for _, body := range []string{`{"auth":{"client_token":"token","lease_duration":0}}`, `{"auth":{"client_token":"token","lease_duration":3600}}`} {
		if _, err := parseAuth([]byte(body), "Invalid Vault login response"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLookupTTLRequired(t *testing.T) {
	for _, body := range []string{`{"data":{}}`, `{"data":{"ttl":null}}`, `{"data":{"ttl":-1}}`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		v := &Vauth{vaultAddr: server.URL}
		_, err := v.LookupSelf("token")
		server.Close()
		if err == nil {
			t.Fatal("invalid TTL accepted")
		}
	}
}

func TestUnrelatedEncryptionConfigIgnored(t *testing.T) {
	body := "vault_addr: https://vault.example.test\nssh_auth: {role: test-role}\n"
	baseline, err := ParseRC([]byte(body), ".vauthrc", nil)
	if err != nil {
		t.Fatal(err)
	}
	expected := (&Vauth{rc: *baseline, vaultAddr: baseline.VaultAddr}).tokenCacheKey()
	for _, value := range []string{"null", "not-a-mapping", "[ignored, '$${env.MISSING}']", "{path: missing-file, identity: ignored}"} {
		rc, err := ParseRC([]byte(body+"ssh-agent-crypt: "+value+"\n"), ".vauthrc", nil)
		if err != nil {
			t.Fatal(err)
		}
		equal(t, rc.AuthKey(), baseline.AuthKey())
		equal(t, (&Vauth{rc: *rc, vaultAddr: rc.VaultAddr}).tokenCacheKey(), expected)
	}
}

func TestNewRequiresUserHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", "")
	} else {
		t.Setenv("HOME", "")
	}
	if _, err := New(); err == nil || !strings.Contains(err.Error(), "Could not determine user home directory") {
		t.Fatalf("missing user home should fail initialization: %v", err)
	}
}

func TestPublicTransportRejectsUnknownVaultAfterInheritance(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	v := f.client()
	v.vaultToken = "inherited-token"
	v.unknownVault = true
	v.rcFile = "/project/.vauthrc"
	var stderr bytes.Buffer
	v.Stderr = &stderr
	token, err := v.Connect(false)
	if err != nil {
		t.Fatal(err)
	}
	equal(t, token, "inherited-token")
	equal(t, v.vaultURL("auth/token/lookup-self"), f.server.URL+"/v1/auth/token/lookup-self")
	check := func(err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "Unknown vault") {
			t.Fatalf("unknown Vault was not refused: %v", err)
		}
		if strings.Contains(err.Error(), "inherited-token") || strings.Contains(err.Error(), "secret-jwt") {
			t.Fatal("error leaked credentials")
		}
	}
	_, err = v.LookupSelf(token)
	check(err)
	for _, c := range []struct {
		method, path, token string
		payload             any
	}{
		{"GET", "auth/token/lookup-self", token, nil},
		{"POST", "auth/jwt/login", "", map[string]any{"jwt": "secret-jwt"}},
		{"GET", "identity/entity/id/test-entity", "", nil},
	} {
		status, body, err := v.Request(c.method, c.path, c.token, c.payload, 200)
		check(err)
		equal(t, status, 0)
		if body != nil {
			t.Fatal("refused request returned a response body")
		}
	}
	_, err = v.renewToken(token)
	check(err)
	_, err = v.loginVault("jwt", map[string]any{"jwt": "secret-jwt"})
	check(err)
	equal(t, len(f.requests), 0)
	equal(t, stderr.String(), "Vauth token: inherited\n")
}

func TestReadOnlyCompleteRCSnapshotAndEffectiveGetters(t *testing.T) {
	home := t.TempDir()
	file := filepath.Join(home, ".vauthrc")
	if err := os.WriteFile(file, []byte(`{"env":{"map":{"KEY":"original"}},"extra":[{"nested":true}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAUTHRC", file)
	t.Setenv("VAULT_ADDR", "https://vault.example.test")
	t.Setenv("VAULT_TOKEN", "inherited-token")
	v, err := New()
	if err != nil {
		t.Fatal(err)
	}
	equal(t, v.VAULT_ADDR(), "https://vault.example.test")
	equal(t, v.VAULT_TOKEN(), "inherited-token")
	if _, ok := v.RC()["vault_addr"]; ok {
		t.Fatal("environment fallback leaked into file configuration")
	}
	view := v.RC()
	view["env"].(map[string]any)["map"].(map[string]any)["KEY"] = "changed"
	equal(t, v.RC()["env"].(map[string]any)["map"].(map[string]any)["KEY"], "original")
}

func TestFileSnapshotKeepsAllSectionsAndLiveToken(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	home := t.TempDir()
	file := filepath.Join(home, ".vauthrc")
	body := `vault_addr: ` + f.server.URL + `
jwt_auth: {jwt: fixture-jwt, role: '$${env.ROLE}'}
env: {map: {WHO: '$${profile.WHO}'}}
extra: [one, two]
`
	if err := os.WriteFile(file, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAUTHRC", file)
	t.Setenv("ROLE", "actual-role")
	t.Setenv("VAULT_TOKEN", "")
	v, err := New()
	if err == nil {
		v.TokenCache = false
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	equal(t, v.RC()["jwt_auth"].(map[string]any)["role"], "$${env.ROLE}")
	equal(t, v.RC()["env"].(map[string]any)["map"].(map[string]any)["WHO"], "$${profile.WHO}")
	token, err := v.Connect(false)
	if err != nil {
		t.Fatal(err)
	}
	equal(t, token, "fresh-token")
	equal(t, v.VAULT_TOKEN(), token)
	var payload map[string]any
	json.Unmarshal([]byte(f.requests[0].Body), &payload)
	equal(t, payload["role"], "actual-role")
}

func TestRCSnapshotMatchesJSONCompatibleNodeValues(t *testing.T) {
	rc, err := ParseRC([]byte("extra: {date: 2026-01-01, timestamp: 2026-01-01T00:00:00Z, yes: yes}\n"), "fixture", nil)
	if err != nil {
		t.Fatal(err)
	}
	v := &Vauth{rc: *rc}
	extra := v.RC()["extra"].(map[string]any)
	equal(t, extra["date"].(string), "2026-01-01")
	equal(t, extra["timestamp"].(string), "2026-01-01T00:00:00Z")
	equal(t, extra["yes"].(string), "yes")
	for _, body := range []string{"extra: [.inf]\n", "extra: [.nan]\n"} {
		if _, err := ParseRC([]byte(body), "fixture", nil); err == nil || err.Error() != "Configuration is not JSON-compatible" {
			t.Fatalf("unsupported JSON values: %v", err)
		}
	}
}

func TestAuthKeyDoesNotDependOnYAMLOrder(t *testing.T) {
	first, err := ParseRC([]byte("ssh_auth: {role: alice, path: ssh}\njwt_auth: {jwt: fixture-jwt, role: bob, path: jwt}\n"), "first", nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ParseRC([]byte("jwt_auth: {path: jwt, role: bob, jwt: fixture-jwt}\nssh_auth: {path: ssh, role: alice}\n"), "second", nil)
	if err != nil {
		t.Fatal(err)
	}
	equal(t, first.AuthKey(), second.AuthKey())
	other := *second
	credential := *second.JWTAuth
	credential.JWT = "another-fixture-jwt"
	other.JWTAuth = &credential
	if first.AuthKey() == other.AuthKey() {
		t.Fatal("different JWTs share an auth key")
	}
	equal(t, first.SSHAuth.hash(), "ssh/alice/ssh")
	equal(t, first.JWTAuth.hash(), "jwt/bob/jwt/fixture-jwt")
}

func TestRCWalkPreservesKeysAndExpandsAliases(t *testing.T) {
	body := []byte("extra: &auth {role: '$${env.ROLE}'}\nssh_auth: *auth\njwt_auth: {'$${env.FIELD}': ignored, role: '$${env.ROLE}', jwt: fixture-jwt}\n")
	rc, err := ParseRC(body, "fixture", map[string]string{"ROLE": "actual-role", "FIELD": "path"})
	if err != nil {
		t.Fatal(err)
	}
	equal(t, rc.SSHAuth.Role, "actual-role")
	equal(t, rc.JWTAuth.Role, "actual-role")
	equal(t, rc.JWTAuth.Path, "")
	v := &Vauth{rc: *rc}
	equal(t, v.RC()["extra"].(map[string]any)["role"], "$${env.ROLE}")
}

func TestCacheCompositionMatchesNodeSDK(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node is not installed")
	}
	if exec.Command(node, "-e", "require.resolve('ssh2')").Run() != nil {
		t.Skip("npm dependencies are not installed")
	}
	cases := []string{
		`{"vault_addr":"https://vault.example.test/"}`,
		`{"vault_addr":"https://vault.example.test","ssh_auth":{"role":"alice"}}`,
		`{"vault_addr":"https://vault.example.test","ssh_auth":{"role":"alice","path":"ssh"}}`,
		`{"vault_addr":"https://vault.example.test","ssh_auth":{"path":"ssh","role":"alice"}}`,
		`{"vault_addr":"https://vault.example.test","jwt_auth":{"role":"r","path":"jwt","jwt":"fixture-jwt"}}`,
		`{"vault_addr":"https://vault.example.test","jwt_auth":{"jwt":"fixture-jwt","path":"jwt","role":"r"}}`,
		`{"vault_addr":"https://vault.example.test","jwt_auth":{"jwt":"other-fixture-jwt","path":"jwt","role":"r"}}`,
		`{"vault_addr":"https://vault.example.test","jwt_auth":{"role":"a/b","path":"c","jwt":"fixture-jwt"}}`,
		`{"vault_addr":"https://vault.example.test","jwt_auth":{"role":"a","path":"b/c","jwt":"fixture-jwt"}}`,
		`{"vault_addr":"https://vault.example.test","ssh_auth":{"role":"é😀\"\n","path":"ssh"},"jwt_auth":{"role":"r","jwt":"fixture-jwt"}}`,
		`{"vault_addr":"https://vault.example.test","ssh_auth":null,"jwt_auth":null}`,
		`{"vault_addr":"https://vault.example.test","jwt_auth":{"role":"r","jwt":"fixture-jwt","unrelated":"ignored"}}`,
	}
	body, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, "-e", `const fs = require('fs'); const path = require('path'); const VauthLogin = require('./index.js'); const cases = JSON.parse(fs.readFileSync(0, 'utf8')); const directory = process.argv[1]; process.chdir(directory); const hashes = cases.map((body, i) => { const file = path.join(directory, i + '.json'); fs.writeFileSync(file, body); process.env.VAUTHRC = file; return new VauthLogin()._token_cache_key(); }); process.stdout.write(JSON.stringify(hashes));`, t.TempDir())
	cmd.Env = append(os.Environ(), "VAULT_ADDR=", "VAULT_TOKEN=")
	cmd.Stdin = bytes.NewReader(body)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Node SDK: %v: %s", err, output)
	}
	var hashes []string
	if err := json.Unmarshal(output, &hashes); err != nil {
		t.Fatal(err)
	}
	if len(hashes) != len(cases) {
		t.Fatal("Node returned a different hash count")
	}
	for i, body := range cases {
		rc, err := ParseRC([]byte(body), "fixture", nil)
		if err != nil {
			t.Fatal(err)
		}
		v := &Vauth{rc: *rc, vaultAddr: rc.VaultAddr}
		equal(t, v.tokenCacheKey(), hashes[i])
	}
}
