# Security audit — Codex (Anthropic Claude Fable 5.1)

**Review provenance:** October 24, 2026; an isolated source snapshot matching
functional commit `b7fba0c`. Temporary `.review-go-modcache` paths and snapshot
Git metadata in this report are review artifacts, not upstream/package files.

**Project context (as announced):** upstream `https://github.com/131/vauth-login`, public, ISC license; distributed as npm `vauth-login`, Go module `github.com/131/vauth-login`, and Linux/Windows binaries on GitHub Releases; a public patch release is planned.

## 1. Input selection and exclusion statement

Inventory was done by filename first (`git ls-files`, `find`). No `SECURITY_AUDIT*`, advisory, or handoff documents exist in the tree; no excluded content entered this run. Inputs explicitly selected:

- Source: `vauth.go`, `rc.go`, `vault.go`, `cache.go`, `humandiff.go`, `cmd/vauth-login/main.go`, `index.js`, `bin/vauth-login.js`
- Tests: `vauth_test.go`, `auth_api_test.go`, `cmd/vauth-login/main_test.go`, `test/token-cache.js`
- Build/release: `go.mod`, `go.sum`, `package.json`, `.goreleaser.yaml`, `.github/workflows/{release,publish-npm,test}.yml`, `.eslintrc`, `.gitignore`
- Docs: `README.md` (all sections are user documentation; the `## Security` section is a threat-model note, not an audit) and `API_and_tests.md`
- Dependencies: `.review-go-modcache/github.com/131/ssh-agent-crypt@v1.4.1/*.go`, `golang.org/x/crypto@v0.31.0/ssh/agent/client.go`, `node_modules/{ssh-agent-crypt,nyks/http/request.js}` and installed package versions
- Excluded: Git history, `REVIEW_SCOPE.json` beyond confirming scope, all Markdown inside dependency caches

Working tree: clean (no uncommitted tracked changes). Note: `.review-go-modcache/` (1,146 files) is tracked in this snapshot but is a review artifact not listed in the upstream scope; it must not be published (it would also fail upstream CI's `gofmt -l .`).

## 2. Scope and method

- Manual review of all first-party Go and Node code, CLI entry points, config loading, Vault transport, cache encryption path, and release pipelines.
- Review of the cryptographic dependency `ssh-agent-crypt` v1.4.1 (Go) and v1.4.1 (Node) as used by the cache.
- Local checks run offline (sandbox: no network, no listening sockets): `gofmt -l` on first-party sources (clean), `go vet ./...` (OK), `GOOS=windows go build` (OK), socket-free Go tests `TestCLIProcess`/`TestCLIInformationalFlagsIgnoreConfiguration` (PASS), `eslint .` (clean), `go version -m` on the built binary (deps match `go.sum`).
- Not run: `go test ./...` / `npm test` integration suites (they spawn `ssh-agent` and a loopback HTTP fixture; `listen` is `EPERM` in this sandbox), `go test -race`, `govulncheck`, `npm audit`, any real Vault or credential access.

## 3. Findings (prioritized)

Severity reflects impact in the announced public/integrator context. **Verified** = behavior confirmed in code/config; **Hypothesis** = plausible impact that depends on an external component or deployment.

### F1 — SSH agent signs an unconstrained, server-chosen challenge, for every key in the agent (Medium–High)
**Verified:** `vault.go:137-157` fetches `auth/<path>/nonce`, takes `data.nonce` as an arbitrary string, and calls `client.Sign(key, nonce)` for each agent key, moving to the next key on any login failure (`:165-167`). `index.js:257-269` does the same. No length, charset, or structure check is applied, and no domain separation is added before signing.
**Impact (hypothesis on exploitation):** any Vault origin the client will talk to (a trusted-but-compromised Vault, an attacker-controlled `VAULT_ADDR` in CI, or a MitM on an `http://` address — see F3) becomes a chosen-message signing oracle over all identities loaded in the agent, not just the Vault key. Two concrete consequences: (a) classic SSH impersonation — the attacker returns as "nonce" an SSH userauth request blob for a live session it opened against a third-party server trusting one of the victim's keys; (b) decryption of a stolen `~/.vauth/tokens/*.creds` file — the attacker returns the exact SSHSIG blob `ssh-agent-crypt` derives keys from (`sshagentcrypt.go:257-259`, namespace `ssh-agent-crypt`, sha512(salt)), obtaining the key material without agent access. The loop also discloses every public key in the agent to the server.
**Fix:** reject nonces that are not a bounded, fixed-alphabet token (e.g., ≤ 128 bytes of base64/hex); never sign raw server bytes — sign a domain-separated hash (e.g., SSHSIG envelope with a `vault-ssh-login` namespace, which would require the auth plugin to verify the same envelope); let `ssh_auth` pin a key (`key: <fingerprint|comment>`) and use only that key by default instead of iterating all agent keys.

### F2 — Release and publish pipelines depend on mutable refs, unpinned installs and an EOL toolchain (Medium)
**Verified:**
- `.github/workflows/release.yml:22-26` checks out `131/gh-actions@v1` (mutable branch/tag) and `.goreleaser.yaml:19` executes `.gh-actions/sign-binaries/sign` from it with `SIGNING_SERVER`; `actions/*` and `goreleaser-action` are major-tag pinned, not SHA pinned.
- `publish-npm.yml:23`, `test.yml:18` use `npm install` and `package-lock.json` is gitignored (`.gitignore:1`), so every CI run resolves fresh transitive versions.
- `go.mod:5` declares `go 1.22` with no `toolchain` line; `setup-go` with `go-version-file` therefore builds release binaries with Go 1.22.x, unsupported since Feb 2025 — stdlib (`net/http`, `crypto/tls`) fixes after that date are absent from shipped binaries. `golang.org/x/crypto v0.31.0` is also well behind (`ssh` package fixes since; the known post-0.31 ssh CVE is server-side, so low direct impact here).
**Impact:** an actor with write access to `131/gh-actions` can alter the signing step for all Windows releases; a compromised transitive npm release enters CI and the publish job immediately; binaries ship with an unpatched runtime.
**Fix:** pin third-party actions and the `gh-actions` checkout by commit SHA; commit `package-lock.json` and use `npm ci`; bump `go`/`toolchain` to a supported line (1.24+/1.25) and update `x/crypto`; consider `actions/attest-build-provenance` or cosign for Linux binaries and `SHA256SUMS` (currently only Windows is signed).

### F3 — Plaintext `http://` Vault addresses are accepted silently (Medium)
**Verified:** no scheme validation in `vauth.go:150-153`, `vault.go:43-45`, `index.js:79,300-313`. The client sends `X-Vault-Token`, JWTs and SSH signatures over whatever scheme `vault_addr`/`VAULT_ADDR` specifies.
**Impact:** on `http://`, a network attacker reads bearer tokens/JWTs and can act as the oracle in F1.
**Fix:** require `https://` except for loopback hosts, or demand an explicit `allow_insecure: true` in `~/.vauthrc`.

### F4 — `publish-npm.yml` trigger filter is ineffective and the job lacks environment protection (Medium)
**Verified:** `publish-npm.yml:3-5` uses `on: create` with a `tags:` filter; GitHub only supports branch/tag filters on `push`/`pull_request*`, so the workflow runs on every branch *and* tag creation, with `id-token: write`, no `environment:` (unlike `release.yml:13`), and no check that the tag equals `package.json` version.
**Impact (hypothesis):** a branch created after a version bump publishes to npm before review/tag; version skew between npm (`package.json`) and binaries (`{{ .Tag }}`) is possible.
**Fix:** `on: push: tags: ['v*']`, add `environment: production`, and assert `v$(node -p require('./package.json').version) == $GITHUB_REF_NAME` before `npm publish`.

### F5 — Environment-based trust (`VAUTHRC`, `VAULT_ADDR`) can be set by the project being authenticated (Medium, design)
**Verified:** `rc.go:247-258` takes `VAUTHRC` as first candidate and skips the known-vault gate for it (`vauth.go:140`); `rc.go:265` and `index.js:87` accept `VAULT_ADDR` as proof of trust. The README (`:97-98`) declares the environment operator-controlled, yet the tool is designed to be a project dependency (`CheckProjectVersion`, `vauth.go:63-93`).
**Impact (hypothesis):** when invoked from project-controlled scripts (`package.json` scripts, direnv, Makefiles), a malicious repository sets `VAUTHRC=…` or `VAULT_ADDR=https://attacker` plus a matching `.vauthrc`, bypassing the allowlist; combined with `$${env.X}` macro expansion (`rc.go:130-155`), arbitrary environment variables (e.g., `jwt: $${env.GITHUB_TOKEN}`) are posted to the attacker, and F1 applies.
**Fix:** document this limitation prominently; optionally treat `VAULT_ADDR`-only trust as insufficient when `./.vauthrc` was selected and `~/.vauthrc` exists (require `known_vaults`), and restrict macro expansion for project files to an allowlist of variable names.

### F6 — RSA signatures requested with default flags (SHA-1 `ssh-rsa`) (Low)
**Verified:** `vault.go:153` uses `client.Sign` → `SignWithFlags(..., 0)` (`x/crypto ssh/agent/client.go:439-441`); `index.js:262` passes `{}` flags. `ssh-agent-crypt` itself requests `rsa-sha2-512` (`sshagentcrypt.go:121-127`).
**Fix:** request `SignatureFlagRsaSha512` for RSA keys (plugin must accept `rsa-sha2-512`).

### F7 — Unvalidated `path` in `ssh_auth`/`jwt_auth` reaches the request URL (Low)
**Verified:** `vault.go:110,137` and `index.js:257,293` interpolate `path` unescaped (`auth/<path>/login`); Go sends `..` segments verbatim, Node normalizes them. A project file can thus target any unauthenticated path on the trusted Vault with the login payload.
**Fix:** validate `path` against `^[A-Za-z0-9_./-]+$` and reject `..`/empty segments.

### F8 — `go test ./...` in `publish-npm.yml` runs after `npm install` and traverses `node_modules` (Low)
**Verified locally:** `go list ./...` enumerates `github.com/131/vauth-login/node_modules/flatted/golang/pkg/flatted`. Any npm dependency shipping Go test files would be compiled/executed by the publish job, and unrelated Go breakage in `node_modules` can block publishing.
**Fix:** run Go steps before `npm install`, or `go test $(go list ./... | grep -v /node_modules/)`.

### F9 — Dead, outdated dev dependencies (Low)
**Verified:** `package.json:28-29` lists `mocha ^3.1.2` (installed 3.5.3, 2017) and `nyc`, `expect.js`, while tests use `node --test`; `mocha@3` drags `growl@1.9.2` (known command-injection advisory), `diff@3.2.0`, `json3`, legacy `lodash.*` into every CI install (with lifecycle scripts enabled). `eslint@8` is EOL.
**Fix:** remove `mocha`, `nyc`, `expect.js`; move to ESLint 9 or pin and plan.

### F10 — No vulnerability disclosure policy or dependency-update automation (Low)
**Verified:** no `SECURITY.md`, `.github/dependabot.yml`, or CODEOWNERS in the tree. For a public release with integrators this leaves no reporting path.
**Fix:** add `SECURITY.md` (contact, supported versions, PGP/private advisory via GitHub) and Dependabot for `gomod`, `npm`, `github-actions`.

### Informational
- Response bodies are read without a size cap (`vault.go:73`, `index.js:315`): memory pressure from a hostile server only.
- Cache filename is `sha256(JSON including the raw JWT)` (`cache.go:26-31`, `index.js:110-112`): a credential-derived identifier on disk; not reversible in practice, but surprising.
- `MkdirAll(…, 0o700)` does not tighten pre-existing `~/.vauth` permissions; file mode is not enforced on Windows (ACL inheritance).
- `ssh-agent-crypt` still decrypts legacy v1/v2 armor without authenticated prefix (`sshagentcrypt.go:341-344`); vauth-login writes only v3.
- `go.mod:3` comment `// version: 1.0.0` is stale relative to `package.json` 1.1.1.

## 4. Strengths

- Clear, documented trust model: inherited tokens never touched, project-selected Vaults gated by `~/.vauthrc`/`known_vaults`, no interactive prompt (`vauth.go:139-142`, `index.js:82-89`).
- Cache is encrypted and authenticated (v3, HMAC-SHA256 over header+payload, constant-time compare), written `0600` via temp file + atomic rename, directory `0700`; plaintext caches are rejected (tests `TestPlaintextCacheNotAccepted`, `TestCacheIsArmorOnly`).
- Redirects disabled in both transports (`vault.go:85`; nyks `followRedirect` unset), 60 s timeouts, `HTTPError` hides bodies from logs while keeping them for SDK callers.
- Strict CLI surface; `--help/--version` never load config or credentials; token is the only stdout output.
- Byte-identical cache key/format between Node and Go with cross-implementation tests; fixtures use throwaway agents and loopback fake Vaults (no real credentials).
- Release: `-trimpath -s -w`, `SHA256SUMS`, Authenticode for Windows, `environment: production`, `contents: read` on test workflow, npm trusted publishing (OIDC) instead of a long-lived token; `files` allowlist keeps tests/workflows out of the npm tarball.

## 5. Limitations of this review

- Integration test suites could not be executed in this sandbox (no sockets); results in `API_and_tests.md` were not independently reproduced.
- No network: `govulncheck`, `npm audit`, GitHub repository settings (tag protection, environment reviewers, branch protection) and the `131/gh-actions` signing script were not inspected.
- The Vault SSH auth plugin's nonce format and signature verification rules are unknown; F1/F6 exploitation depends on it.
- Windows Pageant/named-pipe behavior reviewed from source only.

## 6. Scores

| Dimension | Score | Justification |
|---|---|---|
| **Coolness** | 15/20 | Elegant idea (agent-sealed, implementation-interoperable token cache; prompt-free allowlisting), tight CLI contract, dual Node/Go parity with shared tests. Loses points for the all-keys signing loop and version/tooling drift. |
| **Robustness** | 12/20 | Thorough behavioral tests and defensive parsing, but CI is non-reproducible (no lockfile, `npm install`), the publish trigger is misconfigured, Go toolchain is EOL, `node_modules` leaks into `go test`, and dead dev deps bloat installs. |
| **Safety** | 13/20 | Strong storage and transport hygiene and a sensible trust model, offset by the unconstrained signing oracle (F1), silent plaintext HTTP (F3), environment-trust bypass in the dependency use case (F5), and supply-chain exposure in the signing path (F2). |

*No repository files were modified, nothing was published or deployed, and no real credentials or Vault services were accessed during this analysis.*


## Release verification (coordinator, separate from the assessment)

The reviewed functional source matches commit `b7fba0c`. Independent review
sandboxes restricted network/listening sockets. The coordinator separately
passed all 80 Node tests on Node 24, ESLint, `go vet ./...`, `go test -race ./...`,
and a Windows cross-build. Node/Go CLI outputs matched byte-for-byte for nine
normal, informational, and invalid-argument cases. These checks do not change
the assessment's findings or scores. Release version markers are subsequently
aligned by `ppackage version patch`; the assessments precede that metadata-only
versioning step.
