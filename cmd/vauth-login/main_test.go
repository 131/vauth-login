package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Run the actual main entrypoint in an isolated process, including exit status.
func TestCLIProcess(t *testing.T) {
	if os.Getenv("LOGIN_CLI_TEST_PROCESS") != "1" {
		return
	}
	version = "v1.0.0"
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"vauth-login"}, os.Args[i+1:]...)
			main()
			os.Exit(0)
		}
	}
	os.Exit(2)
}

func TestCLI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/jwt/login":
			io.WriteString(w, `{"auth":{"client_token":"fixture-token","lease_duration":3600,"renewable":true}}`)
		case "/v1/auth/token/lookup-self":
			io.WriteString(w, `{"data":{"ttl":3600,"creation_ttl":3600,"renewable":true}}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	home := t.TempDir()
	rc := filepath.Join(home, ".vauthrc")
	body, _ := json.Marshal(map[string]any{"vault_addr": server.URL, "jwt_auth": map[string]string{"jwt": "test-jwt", "role": "test-role"}, "token_cache": false, "env": "ignored"})
	if err := os.WriteFile(rc, body, 0600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	inherited := ""
	dir, rcEnv := home, rc
	call := func(args ...string) (string, string, error) {
		cmd := exec.Command(exe, append([]string{"-test.run=TestCLIProcess", "--"}, args...)...)
		cmd.Dir = dir
		for _, entry := range os.Environ() {
			key := strings.SplitN(entry, "=", 2)[0]
			if key != "VAULT_TOKEN" && key != "VAUTHRC" && key != "SSH_AUTH_SOCK" && key != "HOME" && key != "USERPROFILE" && key != "LOGIN_CLI_TEST_PROCESS" {
				cmd.Env = append(cmd.Env, entry)
			}
		}
		cmd.Env = append(cmd.Env, "LOGIN_CLI_TEST_PROCESS=1", "HOME="+home, "VAUTHRC="+rcEnv, "SSH_AUTH_SOCK=", "VAULT_TOKEN="+inherited)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		cmd.Stdin = strings.NewReader("")
		out, err := cmd.Output()
		return string(out), stderr.String(), err
	}

	// A project ./.vauthrc selecting a Vault unknown to ~/.vauthrc is refused
	// without a terminal; --accept trusts it (CI).
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, ".vauthrc"), body, 0600); err != nil {
		t.Fatal(err)
	}
	home, dir, rcEnv = t.TempDir(), project, ""
	if stdout, stderr, err := call(); err == nil || stdout != "" || !strings.Contains(stderr, "Unknown vault "+server.URL+", selected by ") || !strings.Contains(stderr, "known_vaults") {
		t.Fatalf("unknown vault: stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	if stdout, stderr, err := call("--accept"); err != nil || stdout != "fixture-token" || strings.Contains(stderr, "Unknown vault") {
		t.Fatalf("--accept: stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	if stdout, _, err := call("login", "--renew", "--accept"); err != nil || stdout != "fixture-token" {
		t.Fatalf("--renew --accept: stdout=%q err=%v", stdout, err)
	}
	home, dir, rcEnv = filepath.Dir(rc), filepath.Dir(rc), rc
	for _, args := range [][]string{nil, {"login"}, {"connect"}, {"--renew"}, {"login", "--renew"}, {"connect", "--renew"}} {
		stdout, stderr, err := call(args...)
		if err != nil || stdout != "fixture-token" || stderr != "Vauth token: generated · 1h\n" {
			t.Fatalf("%v: stdout=%q stderr=%q err=%v", args, stdout, stderr, err)
		}
	}
	inherited = "inherited-token"
	stdout, stderr, err := call()
	if err != nil || stdout != "inherited-token" || stderr != "Vauth token: inherited\n" {
		t.Fatalf("inherited: stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	stdout, stderr, err = call("--renew")
	if err != nil || stdout != "fixture-token" || stderr != "Vauth token: generated · 1h\n" {
		t.Fatalf("inherited --renew: stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	inherited = ""
	for _, args := range [][]string{{"version"}, {"--version"}} {
		stdout, stderr, err := call(args...)
		if err != nil || stdout != "v1.0.0\n" || stderr != "" {
			t.Fatalf("version: %q %q %v", stdout, stderr, err)
		}
	}
	for _, args := range [][]string{{"env"}, {"run", "echo"}, {"--bogus"}, {"login", "unexpected"}, {"--source"}, {"--ir://json"}} {
		if _, _, err := call(args...); err == nil {
			t.Fatalf("invalid command accepted: %v", args)
		}
	}
}
