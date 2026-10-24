# vauth-login

## A Vault token, ready to use

Authenticate to [Vault](https://developer.hashicorp.com/vault/docs) with your
[SSH agent](https://github.com/42wim/vault-plugin-auth-ssh#using-ssh-agent) or JWT
and get the token on stdout.
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

In CI, supply the trusted Vault address through the environment. Only a
matching project address passes the trust check described under Configuration:

```bash
export VAULT_ADDR=https://vault.example.test
export VAULT_TOKEN=$(vauth-login)
```

The Node executable is `bin/vauth-login.js`; Node and Go share this CLI:

```text
vauth-login [--renew] [--version] [--help]
```

`--version` prints the package/release version and `--help` prints usage, both
without loading project configuration or credentials. All other arguments,
aliases, and `--flag=value` forms are rejected. SDK helpers are not CLI commands.
An unavailable token is an error (exit 1).

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

A project-selected Vault must match `VAULT_ADDR`, the `vault_addr` in
`~/.vauthrc`, or one of its `known_vaults`. Explicit `VAUTHRC` and home
configuration are trusted operator inputs.

```yaml
# ~/.vauthrc
known_vaults:
  - https://vault.example.test
  - https://vault.partner.example
```

SSH authentication uses `SSH_AUTH_SOCK`. Without it, the native Windows binary
autodiscovers the Pageant (0.75+) named pipe, then the OpenSSH agent pipe.
Disk caching requires an SSH agent; JWT authentication can still work. The Node
implementation uses [ssh2](https://github.com/mscdex/ssh2)'s Pageant transport
when no Windows socket is configured.

## Tokens and caching

`VAULT_TOKEN` takes precedence: it is returned unchanged, without contacting
Vault or writing it to the cache. Otherwise, vauth-login reuses a cached token
or authenticates with the configured SSH/JWT method. `--renew` skips reuse and
forces fresh authentication.

In the last third of a cached token's lease, vauth-login renews it if renewable
or logs in again if not. Expired tokens and renewals rejected with 400/403 also
trigger login. Network and server errors remain errors, not a
reason to silently reauthenticate.

The cache lives at `~/.vauth/tokens/<session-sha256>.creds`, encrypted and
authenticated by [ssh-agent-crypt](https://github.com/131/ssh-agent-crypt).
Node and Go share its format; each runtime uses its own home directory.
Set `token_cache: false` to disable it. A cache-write failure does not prevent
returning the token.

Encryption selects `VAUTH_USER_IDENTITY`, then `VAUTH_USER_MAIL`, then the
[ssh-agent-crypt](https://github.com/131/ssh-agent-crypt) default selector.
Decryption uses the key fingerprint stored in the cache.

## Security

The selected configuration file determines the Vault origin and authentication
role. Review it before permitting SSH-agent signing. Whoever controls the agent
socket can decrypt its caches. Tokens are bearer credentials: keep them out of
logs, shell traces and plaintext files.

## API & SDK

Node module, Go module, token lifecycle, Vault HTTP transport and the test matrix:
[API_and_tests.md](API_and_tests.md).

The prototype client API is `Connect`, `LookupSelf`, `Request` in Node and Go.
Read-only `RC`, `VAULT_ADDR` and `VAULT_TOKEN` readers expose the complete parsed
configuration, effective address and current token. The file path and authentication
state remain internal; embedding code can read the document without reopening
its file.
Old Node method spellings and exported cache/URL helpers are removed, without
compatibility aliases; update SDK callers accordingly. The standalone CLI
contract remains unchanged.

## Security audit

Two fresh independent source assessments accompany the 1.1.3 release:
[SECURITY_AUDIT_fable-5.1.md](SECURITY_AUDIT_fable-5.1.md) and
[SECURITY_AUDIT_gpt-6.1-sol.md](SECURITY_AUDIT_gpt-6.1-sol.md).

| Criterion | Claude Fable 5.1 | GPT 6.1 Sol |
| --- | ---: | ---: |
| ✨ **Coolness** | 15/20 | 17/20 |
| Robustness | 13/20 | 13/20 |
| Safety | 14/20 | 13/20 |

Both were generated on October 24, 2026 from clean functional commit `41f56c1`,
before documentation-only consolidation and metadata-only ppackage patch
versioning. The host confirmed models `claude-fable-5-1` and
`gpt-6.1-sol_codeassist`, exact inputs, source immutability and read exclusions.
Prior reports, scores and task handoffs were not source-review inputs. An
invalid Claude attempt was discarded; the successful fresh invocation excluded
README entirely. Sol read isolated non-assessment documentation ranges.
Each published report preserves the raw reviewer response after a separate
host provenance block; check-scope caveats are explicit.

The three-method client API and shared HTTP trust guard were assessed as
implemented. Remaining findings include plaintext HTTP acceptance, mutable
address/trust state, resource limits, cache validation/isolation and release
supply-chain controls. Severity and hypotheses remain each reviewer's own
judgments. Reports and scores were not rewritten for agreement; neither is
certification or a live vulnerability-database clearance.

Reviewer checks differ: Sol ran syntax/format/ESLint and bounded offline probes;
Claude ran syntax/format/ESLint, offline Go vet and Linux/Windows builds using
scratch compiler files. Neither completed full integration suites under the
review sandbox. The host provenance distinguishes temporary filesystem writes
and blocked socket probes from actual suite execution.

Separate release validation passes all 81 Node tests on Node 24, ESLint, Go
vet/race tests, Windows compilation and Node/Go CLI output comparisons. These
are host validation results, not tests silently attributed to the assessments.
Published package/binary identity is verified separately during publication.

## Credits

- [François Leurent/131](https://github.com/131)
- [OpenAI](https://openai.com) Codex (GPT 6.1-sol), in collaboration
- [Anthropic](https://www.anthropic.com) Claude (Fable 5.1), in collaboration
- [ssh-agent-crypt](https://github.com/131/ssh-agent-crypt) and its contributors
- Code signing, courtesy of Essilor International

ISC license.
