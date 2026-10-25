# vauth-login

Authenticate to [Vault](https://developer.hashicorp.com/vault/docs) with SSH or
JWT and get a token on stdout. Node and Go modules/CLIs, Linux and Windows binaries.

## Install

```bash
npm install -g vauth-login
go install github.com/131/vauth-login/cmd/vauth-login@latest

# Linux binary
wget -O vauth-login https://github.com/131/vauth-login/releases/latest/download/vauth-login-linux-amd64
chmod +x vauth-login

# Windows binary
curl.exe -fsSL -o vauth-login.exe https://github.com/131/vauth-login/releases/latest/download/vauth-login-windows-amd64.exe
```

[Releases](https://github.com/131/vauth-login/releases) include `SHA256SUMS`;
Windows binaries are Authenticode signed. Verify before putting them on PATH.

## Login

```bash
export VAULT_TOKEN=$(vauth-login)
vauth-login --renew
```

An inherited `VAULT_TOKEN` is reused offline; otherwise login uses the encrypted
cache or SSH/JWT authentication. `--renew` forces fresh authentication.
Tokens go raw to stdout, status/errors to stderr. No token: exit 1.

```text
vauth-login [--renew] [--version] [--help]
```

Help/version do not load credentials or configuration.

## Configuration

The first existing file wins: `VAUTHRC`, `./.vauthrc`, then `~/.vauthrc`.
`VAULT_ADDR` supplies the address fallback; `$${env.NAME}` reads the environment.

```yaml
vault_addr: https://vault.example.test
ssh_auth:
  path: ssh
  role: developer
# Or jwt_auth: {path: jwt, role: developer, jwt: "$${env.LOGIN_JWT}"}
token_cache: true
```

A project-selected Vault must match environment `VAULT_ADDR`, the home
`vault_addr`, or its `known_vaults`. Explicit `VAUTHRC` and home configuration
are trusted operator inputs.

```yaml
# ~/.vauthrc
known_vaults:
  - https://vault.partner.example
```

SSH uses `SSH_AUTH_SOCK`; native Windows discovers Pageant/OpenSSH pipes.
The encrypted cache lives under `~/.vauth/tokens`; `token_cache: false` disables
it. Cache-write failure does not prevent returning the token.

Review configuration before permitting agent signing. Tokens are bearer
credentials: keep them out of logs, shell traces and plaintext files.

## SDK and assessments

- [API and tests](API_and_tests.md)
- Source assessments: [Claude](SECURITY_AUDIT_fable-5.1.md), [Sol](SECURITY_AUDIT_gpt-6.1-sol.md).
  Each report identifies its assessed commit and limitations.

## Credits

François Leurent/131, OpenAI Codex, Anthropic Claude and ssh-agent-crypt contributors.
Code signing courtesy of Essilor International. ISC license.
