# API and tests

## Shared public API

Node and Go use the same client method names and argument order:

| Method | Arguments | Result |
| --- | --- | --- |
| `Connect` | `renew` | Token |
| `LookupSelf` | `token` | Token metadata |
| `Request` | `method, path, token, payload, expect` | HTTP status and body |

Node returns promises for asynchronous operations; Go returns values and an
error. Node keeps optional argument defaults; Go supplies them explicitly.
Construction remains `new VauthLogin()` in Node and `New()` in Go. The version
is `VauthLogin.Version()` in Node and the package variable `Version` in Go.
HTTP/JSON field spelling and native error types remain language-specific.

## Read-only client data

| Data | Node property | Go reader | Meaning |
| --- | --- | --- | --- |
| Configuration | `client.RC` | `client.RC()` | Complete parsed JSON document, including sections vauth-login does not interpret |
| Address | `client.VAULT_ADDR` | `client.VAULT_ADDR()` | Effective address, with the environment fallback |
| Token | `client.VAULT_TOKEN` | `client.VAULT_TOKEN()` | Current token managed by `Connect` |

`RC` retains the file's original values/macros. Only vauth-login's private authentication
view expands `env` macros. `RC.vault_addr` can therefore differ from the effective
address. Node returns one recursively frozen snapshot; Go returns an independent
JSON snapshot rather than a shared mutable map. Copy the sections you need before
expanding macros in embedding code.

Node construction keeps the normal environment and file flow: `VAUTHRC`,
`./.vauthrc`, then `~/.vauthrc`. Home and cache paths use the native user home;
agent selection reads `SSH_AUTH_SOCK` at use time.

## Node

```js
const VauthLogin = require('vauth-login');
const client = new VauthLogin();       // .vauthrc and process environment
const token = await client.Connect(); // optional true forces a fresh login
const metadata = await client.LookupSelf(token);
// metadata: ttl, renewable, creation_ttl, entity_id, lease_duration
const {status, body} = await client.Request(
  'GET', 'auth/token/lookup-self', token, null, 200
);
```

`Connect(renew = false)` returns the token.
`VauthLogin.Version()` returns the package version.
`Request(method, path, token = '', payload = null, expect = 200)` sends object
payloads as JSON and returns `{status, body}` (a Buffer). Set `expect = 0` to
handle the status yourself. Each call makes a request to the configured Vault
origin. Status filtering returns `HTTPError` for a status different from
`expect`; with `expect = 0`, the status and body are returned directly.
`requestTimeout` sets the response deadline in milliseconds (default: 60000),
from completion of the send through headers and body reading.
Timeouts propagate with `code = 'ETIMEDOUT'`.

`VauthLogin.HTTPError` has `status`, `body`, and compatibility
`res.statusCode` fields. `body` is available to SDK callers as a non-enumerable
property; error logging displays the status.

The three read-only properties are `RC`, `VAULT_ADDR`, and `VAULT_TOKEN`.
`Connect(renew)` returns an inherited `VAULT_TOKEN` as is, then the
token for configured authentication, or undefined when authentication is
unavailable. `Request()` checks the destination before constructing or sending
an HTTP request, including login, renewal and `LookupSelf()`. It rejects a Vault selected
by `./.vauthrc` unless it matches environment `VAULT_ADDR`, or the user's
`~/.vauthrc` lists it as `vault_addr` or in `known_vaults`. There is no interactive
prompt or per-call acceptance override. Inherited tokens and valid cached
tokens are returned offline without this network-address check.

## Go

```go
import vauthlogin "github.com/131/vauth-login"

client, err := vauthlogin.New()
// Check err before proceeding.
token, err := client.Connect(false)
metadata, err := client.LookupSelf(token)
status, body, err := client.Request("GET", "auth/token/lookup-self", token, nil, 200)
```

`Agent`, `TokenCache`, `CacheDir`, `HomeDir`, `Environ`, `Stderr`, `HTTPClient`
and `Now` remain public Go settings, with their existing defaults.

`New()` discovers the agent and loads both the complete document and its private
authentication view. `RC()`, `VAULT_ADDR()` and `VAULT_TOKEN()` are native Go
reader methods with the same names as the Node properties. `Connect(renew)`
returns an inherited token as is unless `renew` is set. `Request()` checks the
selected destination before constructing or sending any HTTP request, including
login, renewal and `LookupSelf()`. Unknown project-selected addresses are refused.

`LookupSelf(token)` validates online and returns `*LookupToken` with `TTL`,
`Renewable`, `CreationTTL`, `EntityID`, and `LeaseDuration`.
`Request(method, path, token, payload, expect)` returns `(status, body, error)`;
`expect = 0` lets the caller handle statuses. `HTTPError` exposes `Status`/`Body`.
`LocateRC`, `ParseRC` and `Environ` support embedding.

`Connect(false)` returns an inherited token offline, even without authentication
configuration. Otherwise, without an auth method it returns an empty string in
Go or undefined in Node; both CLIs report that empty result as a failure.
One client announces status once per connection unless forced to log in again.

## CLI contract (Node and Go)

```text
vauth-login [--renew] [--version] [--help]
```

- No flags: return an inherited/cache token or authenticate.
- `--renew`: force fresh authentication instead of reusing credentials.
- `--version`: print the package/release version with a newline, without loading
  project configuration or credentials. The Go tag's `v` prefix is omitted.
- `--help`: print usage on stdout without loading configuration or credentials.
- Information flags take precedence: `--help`, then `--version`, then login.
- Token output is raw stdout, without a newline; status/errors go to stderr.
  After successfully writing a token, the CLI writes a newline to stderr for
  terminal display. SDK calls do not add this newline.
- Other arguments, aliases, and `--flag=value` forms are rejected before
  configuration loading or credential output. No token available: exit 1.

The Node executable is `bin/vauth-login.js`, separate from the `index.js` SDK;
the Go executable is `cmd/vauth-login`. SDK helpers are not CLI commands.
Neither implementation uses cnyks or interactive confirmation.

## Verification

```bash
npm install
npm run eslint
npm test
gofmt -l .
go vet ./...
go test ./...
go test -race ./...
GOOS=windows GOARCH=amd64 go build ./cmd/vauth-login
```

The authentication/cache suites create an isolated SSH agent
with a throwaway Ed25519 key and a loopback fake Vault; no real Vault or user
credentials are needed. Linux needs `ssh-agent`, `ssh-keygen`, and `ssh-add`.
Windows CI checks the native build. Installation validation exercises Pageant
login on Windows.
