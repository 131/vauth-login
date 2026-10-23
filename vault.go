package vauthlogin

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	sshagentcrypt "github.com/131/ssh-agent-crypt"
	"golang.org/x/crypto/ssh/agent"
)

// HTTPError reports an unexpected Vault status code.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("Unexpected Vault status %d", e.Status)
}

// auth is the Vault auth block of a login or renewal response.
type auth struct {
	ClientToken   string `json:"client_token"`
	LeaseDuration int64  `json:"lease_duration"`
	Renewable     bool   `json:"renewable"`
}

// lookup is the relevant part of auth/token/lookup-self.
type lookup struct {
	TTL         float64 `json:"ttl"`
	Renewable   bool    `json:"renewable"`
	CreationTTL int64   `json:"creation_ttl"`
	EntityID    string  `json:"entity_id"`
}

func (v *Vauth) vaultURL(path string) string {
	return strings.TrimRight(v.VaultAddr, "/") + "/v1/" + strings.TrimLeft(path, "/")
}

// request performs a Vault API call. A JSON payload is sent when non-nil.
// With expect > 0, another status is returned as *HTTPError.
func (v *Vauth) request(method, path, token string, payload any, expect int) (int, []byte, error) {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, v.vaultURL(path), body)
	if err != nil {
		return 0, nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	res, err := v.httpClient().Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	response, err := io.ReadAll(res.Body)
	if err != nil {
		return res.StatusCode, nil, err
	}
	if expect > 0 && res.StatusCode != expect {
		return res.StatusCode, response, &HTTPError{res.StatusCode, string(response)}
	}
	return res.StatusCode, response, nil
}

var defaultHTTPClient = &http.Client{
	Timeout:       60 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
}

func (v *Vauth) httpClient() *http.Client {
	if v.HTTPClient != nil {
		return v.HTTPClient
	}
	return defaultHTTPClient
}

func parseAuth(response []byte, invalid string) (*auth, error) {
	var parsed struct {
		Auth *struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration *int64 `json:"lease_duration"`
			Renewable     bool   `json:"renewable"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(response, &parsed); err != nil || parsed.Auth == nil || parsed.Auth.ClientToken == "" || parsed.Auth.LeaseDuration == nil || *parsed.Auth.LeaseDuration < 0 {
		return nil, errors.New(invalid)
	}
	return &auth{parsed.Auth.ClientToken, *parsed.Auth.LeaseDuration, parsed.Auth.Renewable}, nil
}

func (v *Vauth) loginVault(path string, payload any) (*auth, error) {
	status, response, err := v.request("POST", "auth/"+path+"/login", "", payload, 0)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, &HTTPError{Status: status, Body: string(response)}
	}
	return parseAuth(response, "Invalid Vault login response")
}

func (v *Vauth) loginVaultSSH(config *SSHAuth) (*auth, error) {
	path := config.Path
	if path == "" {
		path = "ssh"
	}
	v.debug("Trying to auth as '%s'", config.Role)
	conn, err := sshagentcrypt.DialAgent(v.Agent)
	if err != nil {
		return nil, fmt.Errorf("Could not reach ssh-agent at %s: %w", v.Agent, err)
	}
	defer conn.Close()
	client := agent.NewClient(conn)
	keys, err := client.List()
	if err != nil {
		return nil, fmt.Errorf("Unable to list ssh-agent keys: %w", err)
	}
	for _, key := range keys {
		_, response, err := v.request("GET", "auth/"+path+"/nonce", "", nil, 200)
		if err != nil {
			return nil, err
		}
		var challenge struct {
			Data struct {
				Nonce string `json:"nonce"`
			} `json:"data"`
		}
		if err := json.Unmarshal(response, &challenge); err != nil {
			return nil, fmt.Errorf("Invalid nonce response: %w", err)
		}
		if challenge.Data.Nonce == "" {
			return nil, errors.New("Invalid Vault nonce response")
		}
		nonce := []byte(challenge.Data.Nonce)
		signature, err := client.Sign(key, nonce)
		if err != nil {
			v.debug("ssh : agent refused to sign with public key %s", key.Comment)
			continue
		}
		payload := map[string]string{
			"public_key": key.Type() + " " + base64.StdEncoding.EncodeToString(key.Marshal()),
			"role":       config.Role,
			"nonce":      base64.StdEncoding.EncodeToString(nonce),
			"signature":  base64.StdEncoding.EncodeToString(signature.Blob),
		}
		auth, err := v.loginVault(path, payload)
		if err != nil {
			v.debug("ssh : invalid challenge for public key %s", key.Comment)
			continue
		}
		return auth, nil
	}
	return nil, errors.New("Could not login to vault")
}

func (v *Vauth) lookupToken(token string) (*lookup, int64, error) {
	_, response, err := v.request("GET", "auth/token/lookup-self", token, nil, 200)
	if err != nil {
		return nil, 0, err
	}
	var parsed struct {
		Data *lookup `json:"data"`
	}
	var present struct {
		Data struct {
			TTL *float64 `json:"ttl"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response, &parsed); err != nil || parsed.Data == nil || parsed.Data.TTL < 0 {
		return nil, 0, errors.New("Invalid Vault token TTL")
	}
	if err := json.Unmarshal(response, &present); err != nil || present.Data.TTL == nil {
		return nil, 0, errors.New("Invalid Vault token TTL")
	}
	lease := parsed.Data.CreationTTL
	if cached := v.readTokenCache(); cached != nil && cached.Token == token {
		lease = cached.LeaseDuration
	}
	return parsed.Data, lease, nil
}

func (v *Vauth) renewToken(token string) (*auth, error) {
	_, response, err := v.request("POST", "auth/token/renew-self", token, map[string]any{}, 200)
	if err != nil {
		return nil, err
	}
	return parseAuth(response, "Invalid Vault token renewal response")
}

// VaultURL returns an API URL relative to this configured Vault.
func (v *Vauth) VaultURL(path string) string { return v.vaultURL(path) }

// Request performs a JSON Vault call. Set expect to zero to handle status yourself.
func (v *Vauth) Request(method, path, token string, payload any, expect int) (int, []byte, error) {
	return v.request(method, path, token, payload, expect)
}

// LookupToken is the token metadata returned by lookup-self.
type LookupToken struct {
	TTL           float64 `json:"ttl"`
	Renewable     bool    `json:"renewable"`
	CreationTTL   int64   `json:"creation_ttl"`
	EntityID      string  `json:"entity_id"`
	LeaseDuration int64   `json:"lease_duration"`
}

// LookupSelf validates a token online and returns metadata including entity ID.
func (v *Vauth) LookupSelf(token string) (*LookupToken, error) {
	info, lease, err := v.lookupToken(token)
	if err != nil {
		return nil, err
	}
	return &LookupToken{info.TTL, info.Renewable, info.CreationTTL, info.EntityID, lease}, nil
}
