# vauth-login

Standalone Vault authentication using an SSH agent or JWT, with encrypted token
caching. Native Go binaries for Windows and Linux, plus a Node module and CLI.
Authentication only: no identity-profile or secret/environment expansion,
shell installation, or child process execution.

## Install

Download `vauth-login-windows-amd64.exe` or `vauth-login-linux-amd64` from the
GitHub release, check `SHA256SUMS`, and put it on your PATH as `vauth-login.exe`
or `vauth-login`. Windows release binaries are Authenticode signed; an unavailable
signing server fails the release rather than publishing an unsigned executable.

Or install the Go CLI:

```bash
go install github.com/131/vauth-login/cmd/vauth-login@latest
```

The Node CLI exposes the same commands. The first npm-registry publication is
pending; install the tagged source in the meantime:

```bash
npm install -g 'git+ssh://git@github.com/131/vauth-login.git#v1.0.0'
```

## Use

```bash
vauth-login                 # stdout: token; stderr: status and remaining validity
vauth-login --renew         # force a fresh login (not merely a lease renewal)
vauth-login --source        # stdout: export VAULT_TOKEN='…'
vauth-login version         # release/build version, without authenticating
```

`login` and `connect` are optional aliases for the default operation.
`--ir://json` JSON-encodes the token; otherwise it is written without a trailing
newline. `--source` produces a bash export with a trailing newline. Status goes
only to stderr, for example `Vauth token: reused · 11h`. No token or Vault address
is included in that status.

In bash, verify the producer succeeds before sourcing its output:

```bash
if token_export=$(vauth-login --source); then
  eval "$token_export"
  unset token_export
fi
```

## Configuration

The first existing file wins: `VAUTHRC`, `./.vauthrc`, then `~/.vauthrc`.
`VAULT_ADDR` is the fallback when `vault_addr` is absent. `env.*` is ignored,
including malformed or hostile environment-map keys. Authentication fields support `$${env.NAME}`
substitution from the process environment, not profile or secret expansion.

```yaml
vault_addr: https://vault.example.test
ssh_auth:
  path: ssh
  role: developer
# Or jwt_auth: {path: jwt, role: developer, jwt: "$${env.LOGIN_JWT}"}
token_cache: true
```

Recognized keys: `vault_addr`, `ssh_auth`, `jwt_auth`, `token_cache`, and
`ssh-agent-crypt`. The last key is retained for configuration compatibility;
local encrypted secret files and their environment expansion are outside this
package’s scope.

SSH authentication uses `SSH_AUTH_SOCK`. Without it, the native Windows binary
autodiscovers the Pageant (0.75+) named pipe, then the OpenSSH agent pipe. It does
not use WM_COPYDATA or an external signing helper. Without an agent, disk caching
is disabled; JWT authentication can still work. The Node implementation uses
ssh2's Pageant transport when no Windows socket is configured.

## Token lifecycle and cache

The inherited `VAULT_TOKEN` takes priority over the disk cache. When authentication
is configured, an uncached inherited token is validated with `lookup-self`.
The cache is `~/.vauth/tokens/<session-sha256>.creds`, encrypted/authenticated by
ssh-agent-crypt v3. The session hash and JSON payload are identical between
Node and Go: either implementation can read the other's cache. The native
Windows cache is under the Windows user's home; the WSL cache is under the Linux
user's home.

A usable cached token is reused locally without contacting Vault. In the last
third of its lease it is renewed if renewable, otherwise replaced by a fresh
login. An expired cache or a 400/403 from token lookup/renewal triggers login;
network and server failures are not treated as invalid tokens. `--renew` ignores
both inherited and cached tokens. Without authentication configuration, the
library ignores inherited/cache tokens and the CLI fails rather than reporting
an empty token as success.

Cache encryption chooses `VAUTH_USER_IDENTITY`, then `VAUTH_USER_MAIL`, then the
ssh-agent-crypt default selector. Decryption uses the fingerprint embedded in the
armor. Writes use distinct temporary files and atomic replacement; normal reuse
does not rewrite the cache. Cache failures do not expose tokens or prevent a
successful login. `token_cache: false` disables cache access entirely.

## API and tests

See [API_and_tests.md](API_and_tests.md) for Node/Go APIs, transport and test details.
Both APIs expose connection, token lookup and Vault HTTP transport so consumers
can share the authentication boundary without reimplementing it.

## Security boundary

A configuration file chooses the Vault origin and authentication role. This
package uses the configuration precedence described above; it does not make a
cloned repository's `.vauthrc` trustworthy. Review it before permitting SSH-agent signing.
Whoever controls the agent socket can decrypt its caches. Tokens are bearer
credentials: don't log stdout, enable shell tracing around exports, or store tokens
in plaintext files.

The default HTTP transports do not follow redirects and have a 60-second deadline
including the response body. HTTP errors expose status/body to programmatic
callers, but their printable messages omit bodies to avoid echoing credentials.
Go callers overriding `HTTPClient` own its redirect/timeout policy. Cache reuse
intentionally does not check revocation online; use `LookupSelf`/`lookupSelf` when
that validation is needed. It is a Vault client, not a replacement for Vault's
server-side authorization.

## Credits

- François Leurent / [131](https://github.com/131)
- Go/Node implementation and validation with OpenAI Codex
- ssh-agent-crypt and its contributors
- Code signing courtesy of Essilor International

ISC license.
