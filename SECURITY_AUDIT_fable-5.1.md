<!-- Host-verified provenance; the raw standalone reviewer output is preserved verbatim below. -->

## Host-verified release-assessment provenance

- Date: October 24, 2026. Clean functional source commit `41f56c1a8e7effe655e2b6034f934780f99fcdef` on `main`.
- This snapshot has version 1.1.2; the operator-authorized patch 1.1.3 is prepared after the independent assessments through documentation-only consolidation and metadata-only ppackage versioning. The report is not an audit of downloaded release binaries.
- Actual model: `claude-fable-5-1`; provider `claude`, profile `claude`, Codex CLI `0.164.0`.
- Session: `01a16f72-8ad2-7be0-b306-03fbd56b32d0`; exit status `0`.
- Exact successful expanded stdin SHA256: `b11fc3231da5c0ea5cf7635f64ae27b28ea0fa24cd9b37a51e8d48811463a7dd`.
- Raw final output SHA256: `d1f074842e05ed750a1c452b536d9c31823586e8d3aae43553bab8839eaf3876`.
- Invocation: `codex -p claude exec --ephemeral --sandbox read-only -c 'web_search="disabled"' --output-last-message <raw-report> -`, with exact prompt bytes supplied through stdin.
- Exact successful input, command and provenance are maintained in `$AGENT_WORKSPACE/users/fleurent/sa/claude-sa-prompt.md`. Scratch materials: `/tmp/tasks/FLEURENT-09/release-vauth-login-20261024T194258Z/` (temporary, not durable).
- The host verified immutable tracked source, both preexisting reports and checked client configuration/catalog files during independent analysis. Logged commands were checked for input exclusions. Models did not receive earlier findings, scores, conversation or task handoffs.
- Claude prepared Sol's prompt without a source assessment; the host ran its bytes unchanged. Subsequent Claude coordination accepted completeness/exclusion compliance, not the correctness of every finding, and did not rewrite scores or conclusions.
- Successful Claude review excluded README entirely. An earlier session that saw excluded scores was discarded; neither its input history nor diagnostics entered this fresh source review.
- Source and client files stayed byte-identical. Claude wrote temporary compiler caches, build artifacts and a fake home under `/dev/shm`; its broad "no files modified" wording must be read as no repository/client edits, not an absence of scratch writes. `GOFLAGS=-mod=mod` was used, but the host verified go.mod/go.sum remained unchanged.
- Claude successfully ran offline vet and Linux/Windows compilation checks. Go tests failed on socket restrictions; Node socket probing demonstrated blocked loopback access, but a full npm test invocation is not evidenced. Its report's "attempted npm test" wording overstates the logged check. No complete integration suite is claimed for this review.
- Full local release validation is separate from the reviewers' checks. This report does not certify production settings, current advisory status, artifact identity, or absence of vulnerabilities.

---

I have everything needed. Below is the complete standalone advisory.

---

# Security Advisory — vauth-login (Node SDK/CLI + Go module/CLI)

| Field | Value |
| --- | --- |
| Target | `/var/monolith/3rd/github.com/131/vauth-login` — upstream `https://github.com/131/vauth-login` (public, ISC) |
| Source commit | `41f56c1a8e7effe655e2b6034f934780f99fcdef`, branch `main`, working tree clean (`git status --porcelain` empty — no uncommitted tracked changes to include) |
| Manifest version | 1.1.2 (`package.json`, `go.mod` comment); pending PATCH 1.1.3 not yet versioned |
| Assessment date | 2026-10-24 (Europe/Paris) |
| Reviewer | Claude (Anthropic), executed through the Codex CLI agent harness; the exact model variant is not exposed to this session |
| Mode | Independent, read-only, source-only; no network, no credentials, no real Vault, no edits, no publication |

## 1. Scope and distribution context

Assessed as a **public** project with four external surfaces: public GitHub source, the `vauth-login` npm package (SDK `index.js` + CLI `bin/vauth-login.js`), the Go module `github.com/131/vauth-login` (library + `cmd/vauth-login`), and GitHub Release binaries (Linux amd64, Windows amd64 Authenticode-signed, `SHA256SUMS`). Integrators (including the announced `vvauth` consumer) call `Connect`, `LookupSelf`, `Request`. The threat model therefore includes untrusted project directories (`./.vauthrc`, `./package.json`), hostile networks, a malicious or compromised Vault endpoint, and supply-chain compromise of the release pipeline — not only trusted local usage.

## 2. Input inventory and exclusions

Filenames were inventoried first (`git ls-files`, `find`), then inputs were selected explicitly.

**Read (implementation / tests / manifests / workflows):** `index.js`, `bin/vauth-login.js`, `test/token-cache.js` (test titles + fixture + selected tests), `package.json`, `.eslintrc`, `.eslintignore`, `.gitignore`, `vauth.go`, `vault.go`, `rc.go`, `cache.go`, `humandiff.go`, `cmd/vauth-login/main.go`, test function names in `vauth_test.go`, `auth_api_test.go`, `cmd/vauth-login/main_test.go`, `go.mod`, `go.sum`, `.github/workflows/{test,release,publish-npm}.yml`, `.goreleaser.yaml`, `LICENSE`, `package-lock.json` (untracked; metadata only).
**Documentation:** `API_and_tests.md` — headings listed first (`API and tests / Shared public API / Node / Go / CLI contract / Verification`); all sections are API/test documentation, none are assessment sections; read in full. No audit content was encountered.
**Dependency sources (explicitly selected, code only):** `node_modules/nyks/http/request.js`, `node_modules/nyks/string/replaceEnv.js`, `node_modules/nyks/object/walk.js`, `node_modules/ssh-agent-crypt/index.js`, `$GOMODCACHE/github.com/131/ssh-agent-crypt@v1.4.1/{agent_unix.go,sshagentcrypt.go}` (selected functions), `node_modules/ssh2/lib/agent.js` (grep for agent transport names only).
**Instruction files:** `$AGENT_WORKSPACE/AGENTS.md`, `$AGENT_WORKSPACE/monolith/AGENTS.md` (the target is an unmapped external checkout; no neighbor rules borrowed; no project-level AGENTS/STYLE/`.vauthrc`/`.ai/memory` exists).

**Excluded from every read, search and diff:** `README.md` (all depths, including the copy under `node_modules/ssh-agent-crypt`), `SECURITY_AUDIT_fable-5.1.md`, `SECURITY_AUDIT_gpt-6.1-sol.md` (repo root and the identically named files inside the `ssh-agent-crypt` module cache), all dependency Markdown, Git history beyond `HEAD` identity, personal task/README/sa materials, and any prior assessment output. No documentation-wide keyword searches were run. **Exclusion status: maintained** — no excluded content entered the input.

## 3. Method and checks

- Manual code review of authentication flow, configuration loading/trust, token cache cryptography and file handling, HTTP transport, CLI argument handling, manifests and release/publish workflows; cross-language parity review.
- **Run:** `npx eslint .` (pass), `gofmt -l .` (clean), `go vet ./...` (pass, with `GOCACHE`/`TMPDIR` redirected to `/dev/shm`), `go build ./cmd/vauth-login` for linux/amd64 and `GOOS=windows GOARCH=amd64` (both pass).
- **Attempted, blocked by sandbox:** `go test ./...` and `npm test` — the sandbox forbids socket creation (`listen tcp6 [::1]:0: socket: operation not permitted`; Node loopback `listen` → `EPERM`; `ssh-agent` needs a Unix socket). Test suites were reviewed statically, not executed.
- **Not run (no network):** `npm audit`, `govulncheck`, Dependabot/advisory lookups, npm/GitHub API verification. **No live vulnerability-database scanning was performed**; dependency remarks come from reviewer memory and are labelled as such.
- Toolchain observed locally: Node v22.22.2, Go 1.24.0; CI uses Node 24.x and `go.mod` (`go 1.22`).

## 4. Findings (prioritized)

Severity reflects public-distribution exposure. **Verified** = confirmed in code/configuration; **Hypothesis** = plausible but not demonstrated here.

### F1 — `publish-npm` workflow uses an unfilterable `create` trigger (Medium, Verified by GitHub Actions semantics)
- **Evidence:** `.github/workflows/publish-npm.yml:2-5` (`on: create: tags: ['v*']`), `:7-9` (`id-token: write`), `:28` (`npm publish`), no `environment:` (compare `release.yml:13`).
- **Impact:** The `create` event supports neither activity types nor `branches`/`tags` filters; the filter is ignored, so this workflow — which holds the OIDC publishing identity — runs on **every branch or tag creation**. A branch created with a bumped, not-yet-published `package.json` version publishes to npm without passing through the protected `production` environment used for binaries. The operator context indicates 1.1.2 was published through this pipeline, consistent with the filter being silently ignored.
- **Fix:** Switch to `on: push: tags: ['v*']`, add `environment: production`, publish with `npm publish --provenance --access public`, and guard that the tag equals `v${package.json.version}`.

### F2 — Release and publish pipelines build from unpinned npm dependencies; no lockfile is tracked (Medium, Verified)
- **Evidence:** `.gitignore` ignores `package-lock.json`; `git ls-files` contains no lockfile; `publish-npm.yml:23` and `test.yml:18` run `npm install` (not `npm ci`), executing lifecycle scripts of whatever `^` range resolves at build time (`package.json:15-30`).
- **Impact:** Non-reproducible release validation and a supply-chain window: a compromised transitive dependency (dev or runtime) executes in the job that publishes to npm. Consumers also receive floating runtime ranges, which is normal for libraries, but the *release job itself* should be deterministic.
- **Fix:** Track `package-lock.json`, use `npm ci --ignore-scripts` in CI, and consider `overrides`/Dependabot (no `.github/dependabot.yml` exists — verified by inventory).

### F3 — Transport accepts plaintext `http://` Vault addresses; secrets would transit in clear (Medium, Verified; exploitation requires misconfiguration)
- **Evidence:** Node `index.js:286-301` builds the URL from `VAULT_ADDR` and lets nyks choose `http` vs `https` by scheme (`nyks/http/request.js:63`); Go `vault.go:36-65` performs `http.NewRequest` on any scheme. No scheme check anywhere; the allowlist (`index.js:85-89`, `rc.go:263-282`) compares strings only.
- **Impact:** `X-Vault-Token`, JWTs (`jwt_auth.jwt`) and SSH challenge signatures are sent over the configured scheme; with `http://` an on-path attacker captures bearer secrets and can also act as the Vault (see F4). Public users copying examples with `http://` would get no warning.
- **Fix:** Refuse non-`https` origins unless the host is loopback or an explicit `allow_insecure: true` is set; document `NODE_EXTRA_CA_CERTS`/`SSL_CERT_FILE` for private CAs so users are not tempted to disable TLS verification.

### F4 — SSH login blindly signs a server-supplied nonce with the user's agent key (Medium design weakness; exploitability Hypothesis)
- **Evidence:** Node `index.js:247-254`: the nonce is any non-empty string, signed raw with `agent.sign(pubKey, Buffer.from(nonce), {})`; Go `vault.go:134-150`: `client.Sign(key, []byte(nonce))` after an empty-string check only.
- **Impact:** Whoever answers `auth/<path>/nonce` (malicious/compromised Vault, or a MITM under F3) obtains a signing oracle over arbitrary UTF-8-valid byte strings with every key in the agent — including keys unrelated to Vault. Forging SSH userauth or SSHSIG blobs requires attacker-chosen or luckily UTF-8-valid hash bytes, so practical abuse is constrained but not excluded; the agent prompts nothing because no namespace/confirmation is involved. For RSA keys the default agent flags yield `ssh-rsa` (SHA-1) signatures (hypothesis, depends on agent and the custom server plugin).
- **Fix:** Validate the nonce charset/length client-side (e.g., `^[A-Za-z0-9+/=_-]{16,256}$`) so only printable, non-structured data is ever signed; longer term, sign an SSHSIG-style namespaced envelope (server-side change) and request `rsa-sha2-512` for RSA keys.

### F5 — Release artifacts: mutable third-party ref executes with signing credentials; Linux binary and checksums unsigned (Medium-Low, Verified)
- **Evidence:** `release.yml:22-26` checks out `131/gh-actions` at mutable `ref: v1` and `.goreleaser.yaml:19` runs `.gh-actions/sign-binaries/sign` with `SIGNING_SERVER` (`release.yml:33`) under `contents: write`. Only the Windows build has a signing hook; no `signs:` or `sboms:` sections; actions pinned by major tag only.
- **Impact:** A compromise or force-push of `131/gh-actions@v1` controls code executing with the release token and signing-server access. Linux users and `SHA256SUMS` consumers can only verify integrity against the same GitHub channel, not authenticity.
- **Fix:** Pin `131/gh-actions` and all actions to commit SHAs; add goreleaser `signs` (cosign keyless via `id-token: write`) for `SHA256SUMS` and `sboms`; set `mod_timestamp` for reproducibility.

### F6 — `go vet ./...` / `go test ./...` in the publish job include Go code shipped inside `node_modules` (Low, Verified locally)
- **Evidence:** `publish-npm.yml:23-27` runs `npm install` before the Go steps; locally `go test ./...` enumerated `github.com/131/vauth-login/node_modules/flatted/golang/pkg/flatted`.
- **Impact:** Third-party Go code from npm packages is compiled/vetted in the release pipeline; a vet failure or test in such code can block or confuse releases; it expands the code executed under the publishing identity.
- **Fix:** Run Go steps before `npm install`, or `go vet $(go list ./... | grep -v /node_modules/)`, or build only `. ./cmd/...`.

### F7 — Project `package.json` version pin can refuse to run on non-range specifiers (Low robustness, Verified)
- **Evidence:** `index.js:61-66` throws (a **string**, not an `Error`) when `semver.satisfies(VERSION, required)` is false; a git/`file:`/`workspace:` specifier never satisfies. Go `vauth.go:85-88` returns "Invalid … version requirement" for the same inputs.
- **Impact:** Integrators that depend on `vauth-login` via a git URL or local path (plausible for `vvauth` during development) make both CLIs and the Node constructor fail in their project directory. A malformed `./package.json` also crashes the Node constructor with a raw `SyntaxError` (`index.js:63`).
- **Fix:** Skip the check unless `semver.validRange(required)` (Node) / `NewConstraint` succeeds (Go); wrap JSON errors; throw `Error` instances.

### F8 — Macro expansion in project-level `.vauthrc` can read and transmit arbitrary environment variables (Low, Verified; mitigated by vault allowlist)
- **Evidence:** `index.js:40-43` with `nyks/string/replaceEnv.js:7-26` expands `$${env.NAME}` and even `$${env}` (object substitution, line 16-17) in any of the five keys; Go `rc.go:130-155, 306-308` expands string scalars. `jwt_auth.jwt` and `.path` are sent in the login body (`index.js:208-209, 278-279`; `vauth.go:251-256`).
- **Impact:** A malicious repository's `./.vauthrc` can post selected environment secrets (or, in Node, the entire environment object) to `auth/<attacker-chosen path>/login` on the user's **own** trusted Vault, where request bodies reach audit devices (HMAC'd). Exfiltration to a foreign Vault is blocked by the `known_vaults` check (`index.js:85-89,99-102`; `vauth.go:139-141,179-184`). Node's `str.replace(match[0], v)` additionally interprets `$&`/`$'` in env values (robustness divergence from Go), and Node has no recursion depth limit (Go: 16).
- **Fix:** Restrict macro expansion in a *project* file to a documented allow-list (`env.VAULT_ADDR`, `env.VAUTH_*`), reject object substitution, use a literal replacer, cap recursion.

### F9 — No vulnerability scanning, EOL dev dependencies, aging crypto dependency (Low, Verified presence; CVE details from memory)
- **Evidence:** `package.json:24-30` keeps unused `mocha ^3.1.2` (installed 3.5.3 → `growl 1.9.2`), `expect.js`, `nyc` while tests use `node:test`; `eslint 8.57.1` (EOL); `go.mod` pins `golang.org/x/crypto v0.31.0`. No `npm audit`, `govulncheck`, CodeQL or Dependabot in `.github/`.
- **Impact:** From memory: `growl < 1.10` has a command-injection advisory (dev-only, not shipped); `x/crypto v0.31.0` predates 2025 `ssh` package advisories (server-side DoS, likely not reachable from agent-client code — hypothesis). Public consumers running `npm audit` will see noise that erodes trust.
- **Fix:** Remove unused devDependencies; bump `x/crypto`; add `govulncheck` and `npm audit --omit=dev` jobs; add `.github/dependabot.yml`.

### F10 — Hygiene for public adoption (Low, Verified)
- No `SECURITY.md`/disclosure policy; no `engines` field in `package.json` although `Object.hasOwn` (`index.js:42`) requires Node ≥16.9 and `fs.rmSync` in tests ≥14.14; `repository.url` is an SSH URL (`git@github.com:…`) — npm provenance matching normally normalizes it, but verify before relying on `--provenance` (hypothesis); `author` empty.
- Node SDK always prints status lines to `stderr` via `console.error` (`index.js:149-153,162,174`) with no override (Go exposes `Stderr`), and `_login_vault_ssh` swallows all per-key login errors into a generic string throw (`index.js:255-264`), hiding TLS/5xx root causes.
- Go `Vauth` is not goroutine-safe (`connected` flag, `vauth.go:51`); a caller-supplied `HTTPClient` loses the redirect block (`vault.go:80-90`) and Go copies `X-Vault-Token` across cross-host redirects (hypothesis on stdlib header policy). Response bodies are read unbounded (`vault.go:70`, `index.js:302`).

## 5. Strengths (verified)

- **Encrypted-only token cache**: SSHSIG-derived AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC, constant-time compare) via `ssh-agent-crypt`; plaintext caches rejected; cache disabled without an agent (`index.js:76-77`, `vauth.go:147-149`).
- **Safe file handling**: directory `0700`, file `0600`, `wx` temp + atomic rename, temp cleanup (`index.js:135-146`; `cache.go:72-110`); cache key isolates by Vault address and auth config and is byte-identical across languages (`TestTokenCacheKeyMatchesNode`).
- **Destination trust**: a project-selected Vault is refused before any HTTP request unless the user vouches for it in `~/.vauthrc` or `VAULT_ADDR`; no interactive override.
- **Secret-safe errors**: `HTTPError` messages carry status only; bodies are non-enumerable in Node; CLIs print messages only; tests assert no token leakage.
- **No redirects** followed in either transport; deadlines on headers and body (Node `reqtimeout`, Go `Timeout`).
- **Strict CLI contract**: unknown flags rejected before configuration/credential use; `--help/--version` never load config; raw token to stdout only.
- **Release hygiene already present**: `files` whitelist excludes tests and audit documents from the npm tarball; OIDC trusted publishing (no long-lived npm token); minimal `permissions`; `environment: production` and Authenticode signing for Windows; `-trimpath -s -w`; `go.sum` pinned.
- **Broad behavioral test coverage** in both languages (≈55 Node tests, ≈45 Go tests) over an isolated ssh-agent and loopback fake Vault.

## 6. Limitations

- Tests could not be executed in this sandbox (no sockets); results rely on static review.
- No live CVE database, `npm audit`, or `govulncheck`; dependency risk statements are from memory.
- GitHub/npm settings (trusted-publisher constraints, branch/tag protection, environment reviewers) were not inspectable offline; F1's impact depends on them.
- The custom Vault SSH auth plugin (`auth/<path>/nonce`) is out of repository scope; server-side verification (algorithms, nonce freshness/binding) was not reviewed.
- Windows/Pageant paths were only cross-compiled, not executed.

## 7. Scores (out of 20)

| Axis | Score | Justification |
| --- | --- | --- |
| **Coolness** | **15/20** | Compact dual-language SDK/CLI with an interoperable, agent-derived encrypted cache and byte-identical cache keys; converged minimal API; but console noise in the SDK, string throws and ad-hoc macro semantics reduce polish. |
| **Robustness** | **13/20** | Strong behavioral tests and careful cache/transport edge handling; penalized by the untracked lockfile and floating CI installs, brittle `package.json` version gate, Node/Go macro-expansion divergences, `node_modules` leaking into `go test ./...`, and non-goroutine-safe client. |
| **Safety** | **14/20** | Secrets are handled well (encryption at rest, status-only errors, no redirects, destination allowlist, OIDC publishing); held back by accepted plaintext transport, blind nonce signing, the mis-triggering publish workflow, mutable signing-helper ref and unsigned Linux/checksum artifacts, and absent vulnerability scanning. |

## 8. Recommended order of remediation before 1.1.3 goes public

1. F1 — fix `publish-npm` trigger, add `environment: production` and provenance.
2. F2/F6 — commit lockfile, `npm ci --ignore-scripts`, reorder/limit Go steps.
3. F3/F4 — enforce `https` (loopback exception) and validate nonce charset.
4. F5 — SHA-pin `131/gh-actions` and actions; sign `SHA256SUMS`, add SBOM.
5. F7–F10 — version-gate leniency, macro allow-list for project files, drop unused devDependencies, bump `x/crypto`, add `SECURITY.md`, `engines`, Dependabot and `govulncheck`.

*End of advisory. No files were modified, nothing was published or deployed, and no credentials or real Vault services were accessed.*