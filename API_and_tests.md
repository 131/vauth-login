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

`login(source = false, renew = false)` returns the token or a bash export string;
it does not exit the process. `version()` returns the package version.
`vaultURL(path)` constructs an API URL under the configured Vault `/v1/`.
`request(method, path, token = '', payload = null, expect = 200)` sends JSON when
payload is non-null and returns `{status, body}` (a Buffer). Set `expect = 0` to
handle the status yourself. No automatic retry or redirect is performed.
`requestTimeout` can override the 60-second deadline in milliseconds.

`VauthLogin.HTTPError` has `status`, `body`, and compatibility
`res.statusCode` fields. Its message contains only the status, not the body.

The client exposes `rc`, `VAULT_ADDR`, and `VAULT_TOKEN`. `connect()` can return undefined when authentication
is unavailable; CLI/login output instead rejects an empty token.

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
- `--help`, `help`: usage; no authentication.
- Errors: nonzero exit, no token on stdout. No environment/profile commands.

Go release versions include the `v` tag prefix; Node's package version does not.

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
The Windows CI job cross-checks the native build; actual Pageant login is an
installation-level check, not a fake Windows unit-test claim.

Coverage includes cache isolation and format compatibility, encrypted-only disk
storage, cache disabled/missing/corrupt/expired/unwritable, unlimited lifetime,
lease thresholds and renewal baseline, forced login, inherited credentials,
400/403 reauthentication, server failures, key selection, status/output secrecy,
configuration precedence and ignored env.*, public lookup/HTTP APIs, redirect
rejection and Node body deadlines. CLI subprocess tests check default and aliases,
source/JSON output, renewal, caching and argument errors.

Live installation validation must clear the inherited token, force a new login,
validate it with Vault `lookup-self`, then invoke the installed binary again with
no inherited token and confirm the encrypted cache is reused. Compare Node/Go
against the same cache without logging any token. On Windows,
clear `SSH_AUTH_SOCK` too to exercise Pageant autodiscovery. Verify the installed
EXE's Authenticode signature and compare both installed binaries to the release's
`SHA256SUMS`; do not install a locally cross-built unsigned EXE.
