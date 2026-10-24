# vauth-login

## A Vault token, ready to use

Authenticate to Vault with your SSH agent or JWT and get the token on stdout.
The encrypted cache keeps it ready for the next call. Available as a Node module
and CLI, a Go module and CLI, and binaries for Windows and Linux.

## Quick login

```bash
export VAULT_TOKEN=$(vauth-login)
```

## Install

Pick whichever fits the machine in front of you:

```bash
# node
npm install -g vauth-login

# go
go install github.com/131/vauth-login/cmd/vauth-login@latest

# binary, linux
wget -O vauth-login https://github.com/131/vauth-login/releases/latest/download/vauth-login-linux-amd64
chmod +x vauth-login

# binary, windows (cmd or PowerShell)
curl.exe -fsSL -o vauth-login.exe https://github.com/131/vauth-login/releases/latest/download/vauth-login-windows-amd64.exe
```

The [npm](https://www.npmjs.com/package/vauth-login) package carries the Node CLI
and module. Windows binaries are Authenticode signed, with `SHA256SUMS` on every
[release](https://github.com/131/vauth-login/releases). Check the checksum and put
the binary on your PATH. The release workflow requires the signing server.

## Usage

Get a token using your configured authentication and available cache:

```bash
export VAULT_TOKEN=$(vauth-login)
```

The token is written raw to stdout, without a trailing newline. Status goes to
stderr, for example `Vauth token: reused · 11h`.

Force a fresh login:

```bash
vauth-login --renew
```

In CI, trust the Vault selected by the project's `./.vauthrc` without the
confirmation described under Configuration:

```bash
export VAULT_TOKEN=$(vauth-login --accept)
```

Check the version or show help:

```bash
vauth-login version
vauth-login --help
```

`login` and `connect` are optional aliases for the default operation. The Node
library returns the token; cnyks writes that result with `--ir://raw`. Its help
prints the generated command list on stderr, and `--ir://run=version` selects
the version method directly.

## Configuration

The first existing file wins: `VAUTHRC`, `./.vauthrc`, then `~/.vauthrc`.
`VAULT_ADDR` supplies the default Vault address. Authentication fields support
`$${env.NAME}` substitution from the process environment.

```yaml
vault_addr: https://vault.example.test
ssh_auth:
  path: ssh
  role: developer
# Or jwt_auth: {path: jwt, role: developer, jwt: "$${env.LOGIN_JWT}"}
token_cache: true
```

Configuration keys: `vault_addr`, `ssh_auth`, `jwt_auth`, `token_cache`, and
`known_vaults`.

A `./.vauthrc` belongs to the project; `~/.vauthrc` belongs to the user. Before
the first request to a Vault selected by a project file, the user must vouch
for that address: either it is the `vault_addr` of `~/.vauthrc`, or it is
listed in its `known_vaults`. Otherwise `vauth-login` asks `Continue? [y/N]`
once on the terminal, and refuses without one. `VAUTHRC` and `~/.vauthrc`
never ask; `--accept` never asks either (CI). Reusing a valid cached token
makes no request and asks nothing.

```yaml
# ~/.vauthrc
known_vaults:
  - https://vault.example.test
  - https://vault.partner.example
```

SSH authentication uses `SSH_AUTH_SOCK`. Without it, the native Windows binary
autodiscovers the Pageant (0.75+) named pipe, then the OpenSSH agent pipe.
Disk caching requires an SSH agent; JWT authentication can still work. The Node
implementation uses ssh2's Pageant transport when no Windows socket is configured.

## What It Does

An inherited `VAULT_TOKEN` is the caller's: it is returned as is, announced as
`Vauth token: inherited`, and never looked up, renewed or written to the cache.
Without it, a usable cached token is reused locally. In the last third of its lease it is
renewed if renewable, otherwise replaced by a fresh login. An expired cache or a
400/403 from token lookup/renewal triggers login; other lookup/renewal failures
propagate to the caller. `--renew` forces a fresh login.

The cache is `~/.vauth/tokens/<session-sha256>.creds`, encrypted and authenticated
by ssh-agent-crypt v3. The session hash and JSON payload are identical between
Node and Go: either implementation can read the other's cache. Native Windows
uses the Windows user's home; WSL uses the Linux user's home.

Cache encryption chooses `VAUTH_USER_IDENTITY`, then `VAUTH_USER_MAIL`, then the
ssh-agent-crypt default selector. Decryption uses the fingerprint embedded in
the armor. Writes use distinct temporary files and atomic replacement; normal
reuse leaves the cache unchanged. Cache failures keep the token available for
the current call. `token_cache: false` disables cache access.

## Security

The selected configuration file determines the Vault origin and authentication
role. Review it before permitting SSH-agent signing. Whoever controls the agent
socket can decrypt its caches. Tokens are bearer credentials: keep them out of
logs, shell traces and plaintext files.

## API & SDK

Node module, Go module, token lifecycle, Vault HTTP transport and the test matrix:
[API_and_tests.md](API_and_tests.md).

## Security audit

Two independent reviews of the design and of the two implementations, each
scoring Coolness, Robustness and Safety out of 20:
[SECURITY_AUDIT_fable-5.1.md](SECURITY_AUDIT_fable-5.1.md) and
[SECURITY_AUDIT_gpt-6.1-sol.md](SECURITY_AUDIT_gpt-6.1-sol.md).

| Criterion | Codex (Claude Fable 5.1) | Codex (GPT 6.1) |
| --- | ---: | ---: |
| ✨ **Coolness** | 17/20 | 17/20 |
| Robustness | 15/20 | 12/20 |
| Safety | 14/20 | 12/20 |

Both reviews converge on the same items: the Node CLI exiting 0 with an
empty token when no authentication method is available, the Node CLI
exposing `lookupSelf`/`request` outside the `known_vaults` consent gate and
accepting any flag (`--accept=false` counts as accept), `--accept` delegating
more than the prompt explains, cached tokens trusted until expiry without a
revocation check, and a lockfile-free release pipeline. Scores are opinions,
not a certification. Both reviews describe the current tree (v1.1.1).

## Credits

- [François Leurent/131](https://github.com/131)
- [OpenAI](https://openai.com) Codex (GPT 6.1-sol), in collaboration
- [Anthropic](https://www.anthropic.com) Claude (Fable 5.1), in collaboration
- [ssh-agent-crypt](https://github.com/131/ssh-agent-crypt) and its contributors
- Code signing, courtesy of Essilor International

ISC license.
