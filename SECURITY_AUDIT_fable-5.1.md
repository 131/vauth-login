<!-- Host-verified provenance; the standalone reviewer output below is preserved verbatim. -->

## Host-verified execution provenance

- Fresh independent invocation on October 24, 2026, source commit `dccf1a61c6679c3a79fd0fdef154d3d89399de38`, clean working tree.
- Actual model/provider from the execution header: `claude-fable-5-1` / `claude`, profile `claude`, Codex CLI `0.164.0`. The reviewer's model-visibility disclaimer below does not override this host-verified identity.
- Session: `01a16ebb-03a6-71d2-9bca-fb2dc1f3f564`; exit status `0`.
- Exact expanded stdin SHA256: `3cd00dd716d64b3e07abe8f82811017b5418bb0efb9cc18131229e78429a1baa`.
- Raw standalone report SHA256: `29bcf879c0dd981910ad44d3ed832b85a95149eaa6f571e23916199e10c1c8b9`.
- Invocation: `codex -p claude exec --ephemeral --sandbox read-only -c 'web_search="disabled"' --output-last-message <raw-report> -`, with the exact expanded prompt supplied through stdin.
- Exact successful input and command are maintained in `$AGENT_WORKSPACE/users/fleurent/sa/claude-sa-prompt.md`. Scratch input, log and raw output: `/tmp/tasks/FLEURENT-09/sa-vauth-login-20261024T162506Z/` (not durable).
- Host inspected the logged read commands: prior audit contents and README audit ranges were excluded. All tracked repository files, the other assessment and checked client configuration/catalog files remained byte-identical during review.
- Host validation covered completeness, provenance, input exclusions and primary source evidence, not certification of every conclusion. Recollection-based CVE and workflow hypotheses remain explicitly unverified.

---

# Security Advisory — vauth-login (independent analysis)

| Field | Value |
|---|---|
| Target | `/var/monolith/3rd/github.com/131/vauth-login` (upstream `git@github.com:131/vauth-login.git`) |
| Branch / commit | `main` @ `dccf1a61c6679c3a79fd0fdef154d3d89399de38`, clean working tree (`git status --porcelain` empty; no uncommitted tracked changes to include) |
| Version under review | npm `vauth-login@1.1.2`, Go module `github.com/131/vauth-login` (`go.mod` `// version: 1.1.2`), GitHub Release v1.1.2 (already published) |
| Date | 2026-10-24 (Europe/Paris) |
| Reviewer | Claude (Anthropic) running in the Codex agent harness; the exact model version string is not exposed to this session |
| License | ISC (confirmed in `LICENSE`) |
| Mode | Independent analysis phase only — no comparison/consolidation, no edits, no publication, no real Vault/credential access |

---

## 1. Scope and input selection

### 1.1 Inventory (tracked + untracked, excluding `.git/`, `node_modules/`)

```
.eslintignore  .eslintrc  .gitignore  LICENSE  README.md  API_and_tests.md
.github/workflows/{publish-npm.yml, release.yml, test.yml}  .goreleaser.yaml
index.js  bin/vauth-login.js  test/token-cache.js  package.json  package-lock.json (untracked, gitignored)
vauth.go  vault.go  cache.go  rc.go  humandiff.go  vauth_test.go  auth_api_test.go
cmd/vauth-login/main.go  cmd/vauth-login/main_test.go  go.mod  go.sum
SECURITY_AUDIT_fable-5.1.md   ← EXCLUDED
SECURITY_AUDIT_gpt-6.1-sol.md ← EXCLUDED
```

### 1.2 Explicitly selected inputs
- Node: `index.js`, `bin/vauth-login.js`, `test/token-cache.js`, `package.json`, local `package-lock.json`, `.eslintrc`, `.eslintignore`, `.gitignore`
- Go: `vauth.go`, `vault.go`, `cache.go`, `rc.go`, `humandiff.go`, `cmd/vauth-login/main.go`, test files (names/coverage only), `go.mod`, `go.sum`
- Release: `.github/workflows/*.yml`, `.goreleaser.yaml`
- Docs: `API_and_tests.md` (whole; no audit section), `README.md` **lines 1–144 and 178–186 only** (the `## Security audit` section, lines 145–177, was identified from the heading list and never read), `LICENSE`
- Explicitly selected dependency sources (no recursion into dependency docs): `node_modules/ssh-agent-crypt/index.js`, `node_modules/nyks/http/request.js`, `node_modules/nyks/string/replaceEnv.js`, `node_modules/nyks/object/{walk,jqdive}.js`, `node_modules/ssh2/lib/agent.js` (sign flags only), `$GOMODCACHE/github.com/131/ssh-agent-crypt@v1.4.1/{sshagentcrypt.go,agent_windows.go}` (function signatures / crypto core via grep + two short excerpts)

### 1.3 Excluded-input statement
- `SECURITY_AUDIT_fable-5.1.md`, `SECURITY_AUDIT_gpt-6.1-sol.md` (repo root) and the two same-named files inside the `ssh-agent-crypt` Go module cache were **never opened, grepped, or diffed**. Grep commands over tracked files filtered them by name.
- README `## Security audit` section excluded by line range before output.
- No personal workspace tasks/indexes/`sa/` files, no prior advisories, no Git history beyond `git rev-parse HEAD` / `git branch` / `git remote -v` / `git status` / `git ls-files`.
- No audit content entered the input; the run is valid.

### 1.4 Method
Manual code review of both implementations side by side (Node ↔ Go parity), threat modelling against the documented trust model (inherited token → cache → login; project `./.vauthrc` vs user `~/.vauthrc`), review of release/publish workflows and dependency pins, verification of the cryptographic cache format in the dependency source, and the safe local checks listed in §5. No web access, no live vulnerability database — CVE references below are from reviewer memory and marked as such.

---

## 2. Threat model (as derived from code and docs)

- **Assets**: Vault bearer tokens (inherited `VAULT_TOKEN`, cached token, freshly issued token), the user's SSH agent signing capability, JWTs supplied via env, the release signing server secret, npm trusted-publishing identity.
- **Trust boundaries**: (a) a *project* `./.vauthrc` from a cloned repository is semi-trusted — it may choose auth path/role/JWT macros but may only target a Vault vouched for by `~/.vauthrc`/`VAULT_ADDR`; (b) the SSH agent socket owner can decrypt caches (documented); (c) the GitHub Actions pipeline is trusted to produce binaries/packages consumed by external integrators (vvauth pending).
- **Exposure**: public source and packages; CLI used in developer shells and CI; SDK embedded by third parties.

---

## 3. Findings (prioritized)

Severity legend: **High / Medium / Low / Info**. "Verified" = confirmed by code reading or local check; "Hypothesis" = plausible, not confirmed in this environment.

### F1 — SDK transport bypasses the known-Vault guard; inherited token can be sent to a project-selected unknown Vault — **Medium→High for SDK integrators** (Verified in code; impact contextual)

**Evidence**
- `index.js:103-106` `_check_vault()` is called only from `connect()` (`index.js:191`, `index.js:209`).
- `index.js:288-290` `lookupSelf(token = this.VAULT_TOKEN)` and `index.js:304-319` `request()` build the URL from `this.VAULT_ADDR` (`index.js:300-302`), which is the project `./.vauthrc` `vault_addr` (`index.js:79`), with **no** `_safe_vault` check.
- Go mirror: `vault.go:174-198` `lookupToken`, `vault.go:209-214` `VaultURL`/`Request`, `vault.go:226-232` `LookupSelf` — `checkVault()` is only invoked in `vauth.go:230,250`.
- `index.js:80` / `vauth.go:154`: `VAULT_TOKEN` from the environment is loaded into the client unconditionally.
- Test coverage gap: `test/token-cache.js:1011-1030` ("SDK commands cannot send inherited credentials to an unknown project Vault") only asserts that the **CLI rejects** `lookupSelf`/`request` as arguments; no test exercises the SDK methods themselves with `_safe_vault === false`.

**Impact**
An SDK consumer (the documented pattern in `API_and_tests.md` lines 5–13: `connect()` then `lookupSelf()`/`request()`) running in a directory containing an attacker-supplied `./.vauthrc` (`vault_addr: https://attacker.example`) will: receive the inherited token from `connect()` (correct, offline), then **POST/GET it as `X-Vault-Token` to the attacker's host** via `lookupSelf()`/`request()`. The CLI is not affected. The upcoming vvauth integration is precisely such a consumer, so this is the most relevant finding for the announced scope.

**Fix**
- Enforce `_check_vault()` / `checkVault()` inside `request()` (Node) and `request()` (Go) whenever the client is in the unknown-Vault state — at minimum whenever a token header is attached. Offer an explicit, named opt-out for embedders that supply `VaultAddr` programmatically.
- Add SDK-level tests: `new VauthLogin()` in a project with unknown `vault_addr`, `VAULT_TOKEN` set → `lookupSelf()`/`request()` must reject before any socket is opened.
- Document in `API_and_tests.md` that transport calls are guarded.

### F2 — Release pipeline executes a mutable third-party ref and unpinned actions with the signing secret — **Medium** (Verified)

**Evidence**
- `.github/workflows/release.yml:22-26` checks out `131/gh-actions` at `ref: v1` (mutable tag/branch) into `.gh-actions`.
- `.goreleaser.yaml:18-19` post-build hook executes `.gh-actions/sign-binaries/sign {{ .Path }}` with `SIGNING_SERVER: ${{ secrets.SIGNING_SERVER }}` (`release.yml:33`) and `contents: write` (`release.yml:8`).
- All actions pinned by major tag only: `actions/checkout@v4`, `actions/setup-go@v5`, `actions/setup-node@v4`, `goreleaser/goreleaser-action@v6` (`release.yml`, `publish-npm.yml`, `test.yml`).

**Impact**
A compromise or force-push of `131/gh-actions@v1` (or of any upstream action tag) yields arbitrary code execution inside the `production` environment job: exfiltration of `SIGNING_SERVER`, substitution of binaries *before* Authenticode signing and checksum generation, i.e. signed malicious Windows releases. External users are told to trust the signature and `SHA256SUMS` (README lines 33–36).

**Fix**
- Pin `131/gh-actions` and all actions to full commit SHAs (with a comment giving the tag); enable Dependabot `github-actions` updates.
- Have the signing script verify the artifact it receives (e.g., compare to the checksum computed by the goreleaser build step) and make the signing server reject unexpected callers.
- Optionally compute `SHA256SUMS` *before* the signing hook and publish both pre- and post-sign hashes.

### F3 — Go release/test toolchain is end-of-life and dependencies are stale — **Medium** (Config verified; exact toolchain is a hypothesis)

**Evidence**
- `go.mod:5` `go 1.22`, no `toolchain` directive. `release.yml:18-20`, `test.yml:31-33`, `publish-npm.yml:20-22` use `go-version-file: go.mod`, which resolves to the newest **1.22.x** patch. Go 1.22 left support when Go 1.24 shipped (Feb 2025); the v1.1.2 binaries (Oct 2026) were therefore most likely compiled with a standard library (`net/http`, `crypto/tls`, `encoding/json`, `os`) ~20 months behind security fixes.
- `go.mod:8-10` `golang.org/x/crypto v0.31.0`, `golang.org/x/sys v0.28.0` (Dec 2024 era). From memory: the `x/crypto/ssh` package received further fixes after v0.31.0 (e.g., CVE-2025-22869, fixed ≈ v0.35.0). vauth-login only uses the `ssh/agent` client and `ssh` key parsing, so practical exposure is probably low — **hypothesis, no live DB scan**.
- No `govulncheck` step in any workflow.

**Fix**
- Bump `go` directive to a supported minor (and add `toolchain goX.Y.Z`), `go get -u ./... && go mod tidy`, rebuild/retag.
- Add `golang/govulncheck-action` (SHA-pinned) to `test.yml` and `release.yml`; add Dependabot for `gomod`.

### F4 — npm publish job installs unpinned dependencies with lifecycle scripts under an OIDC-capable job — **Medium** (Verified)

**Evidence**
- `.gitignore:2` ignores `package-lock.json`; `git ls-files --error-unmatch package-lock.json` → not tracked. Both `test.yml:18` and `publish-npm.yml:23` run `npm install` (not `npm ci`), so every CI/publish run resolves fresh versions for `^` ranges (`package.json:14-22`).
- `publish-npm.yml:7-9` grants `id-token: write` to the **same job** that runs `npm install`, `npm test`, `go test`; the `ACTIONS_ID_TOKEN_REQUEST_*` variables are available to every dependency install script and test process in that job.
- Unused, very old devDependencies are installed: `mocha@^3.1.2` (resolved 3.5.3, 2017), `expect.js`, `nyc` — `grep -c "mocha|expect.js|nyc" test/token-cache.js` → 0 (tests use `node:test`). The lockfile shows transitive `growl@1.9.2` and `diff@3.2.0` (from memory: CVE-2017-16042 command injection; ReDoS fixed in diff 3.5.0) — only reachable through mocha, not shipped, but present in the publish environment.

**Impact**
A malicious or compromised minor release of any of ~7 runtime or ~5 dev dependency trees can run code in the publish job, mint the OIDC token, and publish a trojaned `vauth-login` to npm via trusted publishing — reaching all external integrators. Builds are also non-reproducible.

**Fix**
- Commit `package-lock.json` (or a `npm-shrinkwrap`-style lock for CI only) and switch to `npm ci --ignore-scripts`.
- Remove unused dev dependencies (`mocha`, `expect.js`, `nyc`).
- Split `publish-npm.yml` into a test job (no `id-token`) and a publish job with `id-token: write` only, `npm ci --ignore-scripts --omit=dev`, and `npm publish --provenance`.
- Add Dependabot/Renovate for npm.

### F5 — `publish-npm.yml` trigger uses `create` with a `tags` filter that the `create` event does not support — **Medium** (Hypothesis)

**Evidence**: `.github/workflows/publish-npm.yml:2-5`:
```yaml
on:
  create:
    tags:
      - 'v*'
```
GitHub documents `branches`/`tags` filters for `push`/`pull_request*`, not for `create`. If the filter is ignored, the workflow runs on **every branch creation**; `actions/checkout` then checks out that branch and runs `npm publish`. If a contributor bumps `package.json` `version` on a feature branch and pushes it, an **untagged, unreviewed commit is published** (trusted publishing needs no token). Also, nothing verifies that the Git tag matches `package.json` version or `go.mod`'s `// version:` comment.

**Fix**: use `on: push: tags: ['v*']`, add `if: startsWith(github.ref, 'refs/tags/v')`, and a step asserting `"v$(node -p 'require("./package.json").version')" == "$GITHUB_REF_NAME"`.

### F6 — Linux binary and `SHA256SUMS` carry no signature or provenance attestation — **Low–Medium** (Verified)

**Evidence**: `.goreleaser.yaml:25-26` produces `SHA256SUMS` only; no `signs:` block, no cosign, no `actions/attest-build-provenance`. Only Windows gets Authenticode via the external server (`.goreleaser.yaml:18-19`). README (lines 26–36) tells users to "check the checksum", but the checksum file comes from the same release page, so it only detects transfer corruption, not a compromised release.

**Fix**: add SLSA/GitHub artifact attestations or cosign keyless signing for all artifacts and `SHA256SUMS`; document verification commands.

### F7 — Project `.vauthrc` can exfiltrate arbitrary environment variables to any endpoint of a trusted Vault — **Low** (Verified)

**Evidence**
- `index.js:40-43` / `rc.go:306-308`: `$${env.NAME}` macros are expanded for **all** rc keys, including project files; nothing restricts which variables a project may read.
- `index.js:213-215` / `vauth.go:257-262`: `jwt_auth.jwt`, `role`, and `path` are project-controlled and POSTed to `auth/<path>/login`. `path` is concatenated unvalidated (`index.js:293`, `vault.go:110`); `..`, `?`, `#` are accepted, so the request can target other endpoints under `/v1/` of the trusted Vault.
- The known-Vault guard (F1 context) correctly limits the **destination** to a vouched Vault; this finding is about **payload** control.

**Impact**: a malicious repository can cause `vauth-login` to send e.g. `$${env.AWS_SECRET_ACCESS_KEY}` as the `jwt` field to the organisation's Vault, where it lands in audit logs (HMAC'd by default, raw if audit devices are configured with raw logging) and in any plugin mounted at the chosen path. Requires the user to run the CLI inside the repo; no network redirection.

**Fix**: validate `path` against `^[A-Za-z0-9_./-]+$` without `..`; restrict macros in a *project* rc to an allowlist (e.g., only `VAULT_*`/`LOGIN_JWT`-style names) or require `jwt_auth` with macros to come from `~/.vauthrc`/`VAUTHRC`; document.

### F8 — SSH nonce is signed raw with default agent flags (SHA-1 for RSA) and no domain separation — **Low** (Verified; exploitation hypothesis)

**Evidence**: `index.js:262` `agent.sign(pubKey, Buffer.from(nonce), {}, …)` → ssh2 sends `flags = 0` (`node_modules/ssh2/lib/agent.js:778-818`), i.e. `ssh-rsa`/SHA-1 for RSA keys; `vault.go:153` `client.Sign(key, nonce)` likewise (contrast `ssh-agent-crypt` which uses `SignatureFlagRsaSha512`, `sshagentcrypt.go:121-126`). The signed bytes are exactly the server-chosen string.

**Impact**: a compromised *known* Vault obtains a signature oracle over attacker-chosen (UTF-8-valid) bytes with the user's SSH key. Real SSH userauth transcripts contain random binary session IDs that rarely form valid UTF-8, so practical misuse is limited; SHA-1 RSA signatures are deprecated but not practically forgeable here.

**Fix**: request `rsa-sha2-256/512` flags; coordinate with the Vault SSH plugin to sign a domain-separated digest (e.g., `SSHSIG`-style envelope with a `vauth-login` namespace, as `ssh-agent-crypt` already does).

### F9 — Token cache hygiene: JWT value inside the cache key, no eviction, directory permissions only on creation — **Low** (Verified)

**Evidence**
- `index.js:108-113` and `rc.go:42` + `cache.go:25-32`: the expanded `jwt` **value** is hashed into the file name. Each new JWT (OIDC tokens rotate per job/session) produces a new `~/.vauth/tokens/<sha256>.creds` file holding a still-valid, encrypted Vault token; nothing ever deletes old entries (only the temp file is unlinked, `index.js:149`, `cache.go:79`).
- `index.js:140` / `cache.go:72`: `mode 0700` applies only if the directory is created; pre-existing `~/.vauth` keeps its mode.

**Impact**: accumulation of long-lived encrypted bearer tokens on disk; decryptable by anyone controlling the agent (documented). A SHA-256 of structured JSON containing the JWT is not reversible for a signed JWT, so disclosure risk is negligible.

**Fix**: key on `(vault_addr, path, role)` plus a hash of the JWT *subject/issuer* rather than the raw token, or omit the JWT; prune files whose plaintext `expires_at` has passed (or older than N days by mtime); `chmod 0700` the directory on each write.

### F10 — Windows Go client keeps the cache enabled when no agent pipe exists → noisy failure every run — **Low** (Verified)

**Evidence**: `agent_windows.go:29-37` `DefaultAgentAddress()` returns `\\.\pipe\openssh-ssh-agent` unconditionally when neither `SSH_AUTH_SOCK` nor Pageant is present; `vauth.go:122,147-149` only disables `TokenCache` when `Agent == ""`. Result: `readTokenCache` fails silently, `saveTokenCache` prints "Could not encrypt/write token cache; token not persisted" (`cache.go:87`) on every JWT login. Node disables the cache without `SSH_AUTH_SOCK` only on non-Windows (`index.js:76-77`).

**Fix**: probe the pipe (`pipeExists`) before enabling the cache, or treat `DialAgent` failure as "cache disabled" silently.

### F11 — Miscellaneous hardening gaps — **Low / Info** (Verified)

| # | Item | Evidence | Fix |
|---|---|---|---|
| a | Plaintext `http://` Vault addresses accepted without warning | `index.js:300-313`, `vault.go:43-45` | Warn/refuse non-loopback `http://` |
| b | Node request timeout starts only after the request is fully sent; connect/TLS stalls fall back to OS TCP timeout | `node_modules/nyks/http/request.js:111-120`; `index.js:312` | Set `timeout` on the socket / use `AbortSignal.timeout` |
| c | Node imports ssh2 internal module `ssh2/lib/agent` (not public API) | `index.js:22` | Pin ssh2 minor or vendor a thin agent client |
| d | Node `replaceEnv` recursion is unbounded (Go caps at 16, `rc.go:135`) — self-referencing env value → stack overflow | `node_modules/nyks/string/replaceEnv.js:23-24` | Depth-limit in `loadRC` |
| e | No `SECURITY.md`/disclosure policy, no Dependabot/Renovate config, no `engines` field (code needs Node ≥16.9 for `Object.hasOwn`, `randomUUID`) | repo root, `package.json` | Add them |
| f | `package.json` `repository.url` is SSH form (`git@github.com:…`) — provenance tooling prefers `https://github.com/131/vauth-login.git` | `package.json:30-33` | Normalize |
| g | Version pin check reads `./package.json` in cwd and fails closed on non-semver ranges (`"latest"`, git URLs) | `index.js:61-67`, `vauth.go:66-93` | Accept/ignore non-semver specifiers |
| h | Documented quick-start `export VAULT_TOKEN=$(vauth-login)` masks the non-zero exit status (sets an empty variable on failure) | README lines 9–13 | Document `VAULT_TOKEN=$(vauth-login) || exit 1` or `set -o pipefail`-style patterns |
| i | Unbounded `io.ReadAll` / `drain` of Vault responses | `vault.go:73`, `index.js:315` | Cap body size (e.g., 1 MiB) |

---

## 4. Strengths (verified)

- **Fail-closed, non-interactive Vault allowlist** for project-selected addresses (`index.js:82-89`, `rc.go:263-282`), with exact string matching (no fuzzy normalization that could be spoofed) and good test coverage (`test/token-cache.js:642-713`, Go `TestUnknownVaultRejected`).
- **Inherited `VAULT_TOKEN` never leaves the process in the CLI path** (`index.js:165-169`, `vauth.go:203-207`); tests assert no network and no stderr leakage.
- **Encrypted + authenticated cache** (`ssh-agent-crypt` v3: AES-256-CBC + HMAC-SHA256 over prefix+payload, keys derived from a namespaced `SSHSIG` signature, constant-time MAC compare, PKCS#7 checks) — verified in dependency source; plaintext caches are rejected (`TestPlaintextCacheNotAccepted`).
- **Atomic, private cache writes**: `wx` + `0600` + random temp name + `rename` (`index.js:140-149`, `cache.go:72-111`); cache failures never block login nor print secrets.
- **Transport hygiene**: redirects not followed in either implementation (`vault.go:85`, nyks default), TLS verification at platform defaults, 60 s deadlines, strict response-shape validation (`index.js:236,259,281,295`, `vault.go:95-107,187-192`), `HTTPError` hides bodies from logs (`index.js:50`, `vault.go:24-26`).
- **Strict CLI contract** (`bin/vauth-login.js:7-9`, `main.go:38-49`): unknown flags rejected before any config/credential access; `--help/--version` load nothing; raw token on stdout, status on stderr.
- **No secrets in debug output** (all `logger`/`v.debug` sites reviewed, §5).
- **Node/Go parity tests** including byte-identical cache keys (`TestTokenCacheKeyMatchesNode`), a loopback fake Vault and throwaway ssh-agent (no real credentials needed).
- **Supply-chain positives**: npm trusted publishing (OIDC, no long-lived `NPM_TOKEN`), `environment: production` gate on release, least-privilege `permissions:` blocks, `-trimpath -s -w`, `go.sum` present, npm `files` allowlist excludes tests and audit documents, Authenticode signing of Windows binaries.

---

## 5. Local checks

| Check | Result |
|---|---|
| Inventory / exclusion filtering | Done (§1) |
| `git rev-parse HEAD`, `git status --porcelain` | `dccf1a61…`, clean |
| `npm run eslint` (eslint 8.57.1, plugin ivs) | **Pass**, no findings |
| `node --check index.js bin/vauth-login.js` | **Pass** |
| `gofmt -l .` | **Clean** (no files listed) |
| `npm ls --depth=0` vs `package.json` | All declared deps resolvable; `ssh2@1.17.0`, `ssh-agent-crypt@1.4.1`, `nyks@6.15.2`, `yaml@2.9.1`, `semver@7.8.5`, `debug@4.4.3`, `mout@1.2.4`; devDeps `mocha@3.5.3` (unused), `expect.js`, `nyc` |
| Secret scan over tracked source (Vault/AWS/private-key patterns, audit docs excluded) | **Nothing found** |
| Debug/log-site review for token leakage | **None** |
| Dependency crypto review (`ssh-agent-crypt` Node + Go) | Consistent with README claims |
| `go vet ./...`, `go test ./...`, `go test -race ./...`, `GOOS=windows go build` | **Not run** — sandbox filesystem is fully read-only (`GOCACHE` and `/tmp` unwritable: "read-only file system") |
| `npm test` (`node --test test/token-cache.js`) | **Not run to completion** — `before` hook fails with `EROFS: mkdtemp '/tmp/vvauth-agent-XXXXXX'` (sandbox limitation, not a code defect) |
| `npm audit`, `govulncheck`, live CVE lookup, release-binary inspection (`go version -m`) | **Not run** — no network access; CVE mentions are from memory and flagged as hypotheses |

---

## 6. Limitations

- Static review only for Go; dynamic tests blocked by the read-only sandbox.
- No live vulnerability database; dependency CVE statements are recollection-based hypotheses.
- Release workflow behavior (F2, F5) and the exact Go toolchain used for v1.1.2 (F3) could not be observed; they are inferred from configuration.
- The Vault "ssh" auth plugin consuming the nonce/signature is out of scope and was not reviewed; F8's server-side assumptions are hypotheses.
- Windows behavior (Pageant/OpenSSH pipe) reviewed from source only.

---

## 7. Scores

| Dimension | Score | Justification |
|---|---|---|
| **Coolness** | **15 / 20** | Elegant idea: agent-sealed, byte-compatible token caches shared by a Node and a Go implementation, zero key management, a crisp CLI contract and a well-thought project-vs-user trust split. Loses points for a stale toolchain/dependency posture and the absence of provenance for a tool whose whole purpose is trust. |
| **Robustness** | **14 / 20** | Strong, behavior-rich test suites in both languages (lease thirds, renewal, corrupt/unwritable caches, parity), strict response validation and atomic writes. Deductions: no lockfile and `npm install` in CI (non-reproducible), EOL Go 1.22 toolchain, unused legacy devDeps, Windows cache noise (F10), internal ssh2 import, unbounded Node macro recursion. |
| **Safety** | **13 / 20** | The local credential model is sound (inherited token never sent by the CLI, authenticated cache, fail-closed allowlist, no secret logging). The score is held back by F1 — the SDK transport can forward an inherited token to a project-chosen unknown Vault, directly relevant to the pending vvauth integration — and by release-pipeline supply-chain exposure (mutable signing-script ref, unpinned actions, OIDC-capable job running unpinned install scripts, probable mis-triggered publish workflow). |

---

## 8. Recommended order of remediation

1. **F1** — guard `request()`/`Request()` with the known-Vault check; add SDK tests (before vvauth integrates).
2. **F2 + F5** — SHA-pin actions and `131/gh-actions`; fix `publish-npm.yml` trigger and add tag↔version assertion.
3. **F4** — commit a lockfile, `npm ci --ignore-scripts`, drop unused devDeps, split publish job with minimal permissions, `--provenance`.
4. **F3** — upgrade Go directive/toolchain and `x/*` modules; add `govulncheck` and Dependabot (npm, gomod, github-actions).
5. **F6** — attest/sign all release artifacts including `SHA256SUMS`.
6. **F7–F11** — path/macro validation, rsa-sha2 flags and nonce domain separation, cache eviction and key composition, Windows agent probing, `SECURITY.md`, `engines`, doc tweaks.

*End of advisory — independent analysis phase; no comparison with or consolidation of other assessments was performed.*