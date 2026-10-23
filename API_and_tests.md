# API and tests

## Node

```js
const VauthLogin = require('vauth-login');
const client = new VauthLogin();       // .vauthrc and process environment
const token = await client.connect(); // optional true forces a fresh login
const metadata = await client.lookupSelf(token);
// metadata: ttl, renewable, creation_ttl, entity_id, lease_duration
const {status, body} = await client.request(
  'GET', 'auth/token/lookup-self', token, null, 200
);
```

`login(source = false, renew = false)` returns the token or a bash export string.
`version()` returns the package version.
`vaultURL(path)` constructs an API URL under the configured Vault `/v1/`.
`request(method, path, token = '', payload = null, expect = 200)` sends object
payloads as JSON and returns `{status, body}` (a Buffer). Set `expect = 0` to
handle the status yourself. Each call makes a request to the configured Vault
origin. Status filtering returns `HTTPError` for a status different from
`expect`; with `expect = 0`, the status and body are returned directly.
`requestTimeout` sets nyks's response deadline in milliseconds (default: 60000),
from completion of the send through headers and body reading. The method uses
`nyks/http/request` for the HTTP call and `nyks/stream/drain` for the response.
Timeouts propagate with `code = 'ETIMEDOUT'`.

`VauthLogin.HTTPError` has `status`, `body`, and compatibility
`res.statusCode` fields. `body` is available to SDK callers as a non-enumerable
property; error logging displays the status.

The client exposes `rc`, `VAULT_ADDR`, and `VAULT_TOKEN`. `connect()` returns
undefined when authentication is unavailable; CLI/login output rejects an empty
token.

## Go

```go
import vauthlogin "github.com/131/vauth-login"

client, err := vauthlogin.New()
// Check err before proceeding.
token, err := client.Connect(false)
metadata, err := client.LookupSelf(token)
status, body, err := client.Request("GET", "auth/token/lookup-self", token, nil, 200)
```

`Vauth` exposes `RC`, `VaultAddr`, `VaultToken`, `Agent`, `TokenCache`, `CacheDir`,
`Environ`, `Stdout`, `Stderr`, `HTTPClient`, and `Now`. `New()` discovers the agent,
loads configuration and applies the process environment. For tests/embedded use,
fields may be supplied directly. `Login(source, renew)` writes the token/export
to `Stdout` and rejects missing authentication.

`LookupSelf(token)` validates online and returns `*LookupToken` with `TTL`,
`Renewable`, `CreationTTL`, `EntityID`, and `LeaseDuration`.
`Request(method, path, token, payload, expect)` returns `(status, body, error)`;
`expect = 0` lets the caller handle statuses. `HTTPError` exposes `Status`/`Body`.
`VaultURL(path)`, `TokenCacheKey()`, `TokenCacheFile()`, `LocateRC`, `ParseRC`,
`Environ`, `ShellEscape`, and `HumanDiff` support embedding.

`Connect(false)` ignores a token when no auth method is configured and returns an
empty string without error; `Login` and the CLI instead reject that empty result.
One client announces status once per connection unless forced to log in again.

## CLI contract (both implementations)

- Default, `login`, `connect`: authenticate and emit the token without a newline.
- `--renew`: force login instead of reusing inherited/cache credentials.
- `--source`: emit a single shell-escaped `export VAULT_TOKEN=…` line.
- `--ir://json`: emit a JSON string; `--source` takes precedence.
- `version`, `--version`: emit the version without loading credentials.
- `--help`, `help`: command help. Go prints usage on stdout; Node prints the
  cnyks-generated command list on stderr.
- Errors: nonzero exit, diagnostics on stderr.

Go release versions use the `v` tag prefix; Node uses the package semver.

The Node CLI delegates method lookup, parameters, aliases and result rendering
to cnyks. `connect` is a cnyks alias for `login`; `--ir://run=version` and
`runner:list_commands` use its native runner interface.

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

Coverage includes cache isolation and format compatibility, encrypted-only disk
storage, cache disabled/missing/corrupt/expired/unwritable, unlimited lifetime,
lease thresholds and renewal baseline, forced login, inherited credentials,
400/403 reauthentication, server failures, key selection, status/output secrecy,
configuration precedence and authentication configuration, public lookup/HTTP
APIs, redirect rejection and Node request deadlines. CLI subprocess tests check default and aliases,
source/JSON output, renewal, caching, reflected commands and runner help.

Live installation validation must clear the inherited token, force a new login,
validate it with Vault `lookup-self`, then invoke the installed binary again with
no inherited token and confirm the encrypted cache is reused. Compare Node/Go
against the same cache without logging any token. On Windows,
clear `SSH_AUTH_SOCK` too to exercise Pageant autodiscovery. Verify the installed
EXE's Authenticode signature and compare both installed binaries to the release's
`SHA256SUMS`; do not install a locally cross-built unsigned EXE.
