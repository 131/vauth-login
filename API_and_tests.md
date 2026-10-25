# API and tests

## Client

| Operation | Arguments | Result |
| --- | --- | --- |
| `Connect` | `renew` | Vault token |
| `LookupSelf` | `token` | Token metadata |
| `Request` | `method, path, token, payload, expect` | HTTP status and body |

Node calls are promises; Go returns values and an error.

| Read-only data | Node | Go |
| --- | --- | --- |
| Raw configuration | `client.RC` | `client.RC()` |
| Effective address | `client.VAULT_ADDR` | `client.VAULT_ADDR()` |
| Current token | `client.VAULT_TOKEN` | `client.VAULT_TOKEN()` |

RC retains original values/macros. The authentication view expands `env`.
Node returns a frozen snapshot; Go returns an independent JSON snapshot.

## Node

```js
const VauthLogin = require('vauth-login');
const client = new VauthLogin();
const token = await client.Connect();
const metadata = await client.LookupSelf(token);
const {status, body} = await client.Request(
  'GET', 'auth/token/lookup-self', token, null, 200
);
```

`Connect(renew = false)` returns the token, or undefined without authentication.
`VauthLogin.Version()` returns the package version.

`Request(method, path, token = '', payload = null, expect = 200)` sends object
payloads as JSON and returns `{status, body}` with a Buffer body. `expect = 0`
returns any HTTP status. Other unexpected statuses reject with `HTTPError`,
whose data fields are `status`, `body` and `res.statusCode`.

`requestTimeout` is the response deadline in milliseconds (default 60000).
Timeout errors carry `code = 'ETIMEDOUT'`.

## Go

```go
import vauthlogin "github.com/131/vauth-login"

client, err := vauthlogin.New()
// Check err before using client.
token, err := client.Connect(false)
metadata, err := client.LookupSelf(token)
status, body, err := client.Request("GET", "auth/token/lookup-self", token, nil, 200)
```

`Connect(renew)` returns the token, or an empty string without authentication.
`LookupSelf` returns `*LookupToken`: `TTL`, `Renewable`, `CreationTTL`, `EntityID`,
`LeaseDuration`. `Request` returns `(status, body, error)`; `expect = 0` accepts
any HTTP status. `HTTPError` exposes `Status` and `Body`.

Go settings: `Agent`, `TokenCache`, `CacheDir`, `HomeDir`, `Environ`, `Stderr`,
`HTTPClient`, `Now`. `LocateRC`, `ParseRC` and `Environ` support embedding.

## Authentication and trust

Inherited tokens and valid cached tokens can be returned offline. `renew`
forces authentication. Requests check the selected Vault destination before
sending; unknown project-selected addresses are refused without prompting.
See [configuration](README.md#configuration) for selection and trust settings.

## CLI

```text
vauth-login [--renew] [--version] [--help]
```

The token is raw stdout without a newline; diagnostics are stderr. Missing
token or invalid arguments: exit 1. Help/version do not load configuration;
other arguments and `--flag=value` forms are rejected.

## Tests

```bash
npm install
npm run eslint
npm test
go vet ./...
go test -race ./...
```

Fixtures use disposable SSH keys/agents and loopback Vault responses, not real
credentials. Tests cover authentication, cache lifecycle, trust refusal,
transport, CLI output and Node/Go interoperability.
