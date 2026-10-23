package vauthlogin

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	equal(t, rc.AuthKey(), `"ssh_auth":{"role":"test-role"}`)
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
	equal(t, v.VaultURL("/auth/token/lookup-self"), f.server.URL+"/v1/auth/token/lookup-self")
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
	v := &Vauth{VaultAddr: redirect.URL}
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

func TestLoginOutput(t *testing.T) {
	for _, source := range []bool{false, true} {
		f := newFixture(t, fixtureOptions{})
		v := f.client()
		var stdout bytes.Buffer
		v.Stdout = &stdout
		if err := v.Login(source, true); err != nil {
			t.Fatal(err)
		}
		expected := "fresh-token"
		if source {
			expected = "export VAULT_TOKEN='fresh-token'\n"
		}
		equal(t, stdout.String(), expected)
	}
	v := &Vauth{}
	if err := v.Login(false, false); err == nil {
		t.Fatal("empty token accepted")
	}
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
		v := &Vauth{VaultAddr: server.URL}
		_, err := v.LookupSelf("token")
		server.Close()
		if err == nil {
			t.Fatal("invalid TTL accepted")
		}
	}
}
