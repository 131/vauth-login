# Host provenance — Claude Fable 5.1, post-publication assessment

- Assessed release: **vauth-login 1.1.4**, tag `v1.1.4`, clean commit `b80d3113509f8fb065b3b78f12636b2a1cefeef5`.
- Date: **October 25, 2026**. Publication completed and was verified **before** this independent assessment; this report is a later documentation-only publication on main, not part of the immutable release tag/npm tarball.
- Actual execution model: **`claude-fable-5-1`**, provider `claude`, Codex CLI `0.164.0`, session `01a17243-7689-7230-b23b-6fa7508e8e7b`, exit `0`. The host launched one fresh Claude-profile review; it launched no further reviewers.
- Input SHA256: `bb93ba6095b2701d6ab5b07eec2fa9a63ca3fa7ade64d533caf209f0d43e965d`.
- Raw report SHA256: `01236cc5b056a798deb9e442ef0a09d2781b2b7fb049d73815ff4c79c94007ab`. The raw response is preserved byte-for-byte after the separator below.
- Both reviewers inventoried current inputs and excluded previous assessment contents, README at every depth, personal tasks/sa materials and coordinator history. Current API documentation was isolated through headings/ranges. Host inspection of executed command inventories found no prohibited report reads. Tracked source and checked client configuration hashes were unchanged before/after reviews.
- Supporting dependency inputs included local installed sources and an ignored local npm lockfile; that lockfile is not a committed release manifest.
- Check scope: Fable ran ESLint, gofmt, offline Go vet and synthetic macro probes. Compiler/probe artifacts were written in ephemeral `/dev/shm`; `GOFLAGS=-mod=mod` was used with `GOPROXY=off`. Node/Go suite attempts were blocked by sandbox socket binding and did not pass. The raw model-build disclaimer is retained below; the CLI header supplies the exact model identity above.
- Host release checks, separate from reviewer checks: 85 Node24 tests, ESLint, Go vet/race, Linux/Windows builds; successful test/publish/release CI; npm latest tarball integrity and exact source; Go proxy manifest/source; GitHub asset checksums; Linux version/help; Windows Authenticode verification.
- Limitations and hypotheses remain the reviewer's judgments. No live vulnerability scan was performed. The trigger behavior discussed as F4 was an offline reviewer hypothesis; host evidence separately confirms the actual v1.1.4 npm publication workflow succeeded. Neither scores nor findings were rewritten to agree with the other report.

- Coordination acceptance: both complete reports were checked in a separate Claude validation phase after independent outputs finished, without score/severity calibration.
- Temporary-write caveat: the command inventory includes earlier cache/write-probe attempts under `/tmp`, `/var/tmp`, `$HOME` and the repository directory before using `/dev/shm`. Tracked source, non-ignored status and checked configuration hashes remained unchanged; the raw report does not inventory the fate of all non-repository temporary artifacts. One macro probe supplied `process.env` only to inspect its constructor; no credential value was present in the observed output. F7/F8 vulnerability notes are expressly memory-based, not verified against live databases.

### Exact host command

```bash
command codex -p claude exec --ephemeral --sandbox read-only -c 'web_search="disabled"' --output-last-message /tmp/tasks/FLEURENT-09/release-vauth-login-20261025T085000Z/claude-report.md - < /tmp/tasks/FLEURENT-09/release-vauth-login-20261025T085000Z/claude-input.txt > /tmp/tasks/FLEURENT-09/release-vauth-login-20261025T085000Z/claude-run.log 2>&1
```

## Raw reviewer response

---

# Security Advisory — `vauth-login` v1.1.4 (independent analysis)

| Field | Value |
| --- | --- |
| Target | `/var/monolith/3rd/github.com/131/vauth-login` (canonical remote `git@github.com:131/vauth-login.git`, public upstream `https://github.com/131/vauth-login`, ISC) |
| Source commit | `b80d3113509f8fb065b3b78f12636b2a1cefeef5` on `main`, tag `v1.1.4`; `git status --porcelain` empty (no uncommitted tracked changes), no untracked non-ignored files |
| Manifests | `package.json` 1.1.4, `go.mod` `// version: 1.1.4`, Go 1.22 |
| Assessment date | 2026-10-25 (Europe/Paris) |
| Reviewer | Claude (Anthropic), running inside the Codex CLI agent harness; the exact model build identifier is not surfaced to this session and is therefore not asserted |
| Mode | Read-only, source-only, offline; one independent review session; no further reviewers launched |

## 1. Scope and context

The package is distributed through three public channels serving external users and integrators (including the separate `vvauth` consumer): the npm package `vauth-login` (SDK `index.js` + CLI `bin/vauth-login.js`), the Go module `github.com/131/vauth-login` (library + `cmd/vauth-login`), and GitHub Release binaries (Linux amd64, Windows amd64 Authenticode-signed, `SHA256SUMS`). Version 1.1.4 is already published; this advisory assesses the exact released source and does not authorize any release or deployment.

In scope: `index.js`, `bin/vauth-login.js`, `test/token-cache.js`, `vauth.go`, `vault.go`, `rc.go`, `cache.go`, `humandiff.go`, `cmd/vauth-login/main.go`, `cmd/vauth-login/main_test.go`, `vauth_test.go`, `auth_api_test.go`, `package.json`, `package-lock.json` (local, untracked/ignored), `go.mod`, `go.sum`, `.eslintrc`, `.eslintignore`, `.gitignore`, `.github/workflows/{release,publish-npm,test}.yml`, `.goreleaser.yaml`, `LICENSE`, and explicitly selected dependency sources: `node_modules/nyks/{http/request.js,object/freeze.js,object/walk.js,object/jqdive.js,string/replaceEnv.js}`, `node_modules/ssh-agent-crypt/index.js`, `node_modules/ssh2/lib/agent.js` (grep only), and `$GOMODCACHE/github.com/131/ssh-agent-crypt@v1.4.1/{sshagentcrypt.go (grep),agent_unix.go,agent_windows.go (head)}`.

## 2. Inventory and input-exclusion statement

Tracked files were inventoried with `git ls-files` before any content read. The following were **excluded from every read, search and diff**: `README.md` (at every depth, including heading/keyword probes), `SECURITY_AUDIT_fable-5.1.md`, `SECURITY_AUDIT_gpt-6.1-sol.md`, the `README.md`/`API_and_tests.md`/`SECURITY_AUDIT*.md` files present inside the `ssh-agent-crypt` module cache, dependency Markdown, Git history (only `git rev-parse HEAD`, branch, status and remotes were queried), personal README/task indexes, `sa/` materials, the coordinating conversation, and any prior assessment or diagnostic output. No documentation-wide keyword search for audit/advisory/score terms was run; all greps were restricted to explicitly named implementation/test/manifest/workflow/dependency-source files.

`API_and_tests.md` was handled as instructed: its heading lines were listed first (`API and tests`, `Shared public API`, `Read-only client data`, `Node`, `Go`, `CLI contract`, `Verification`); all are API/contract/test-procedure sections with no assessment content, so the document was read in full. The workspace `$AGENT_WORKSPACE/AGENTS.md` entry instruction was read; its request to read the workspace README and personal context was not followed because the operator's exclusions for this invocation take precedence, and the operator already stated the checkout is unmapped in monolith (no neighbouring rules borrowed). No excluded audit content entered the input, so the run proceeds to a report.

## 3. Method

1. Full read of all Node and Go implementation files and the CLI entry points; targeted read of test suites (test names, fixtures, isolation of HOME/agent/Vault).
2. Review of dependency manifests, local lockfile resolution, and the selected dependency source files that sit on the security path (HTTP transport, macro expansion, freezing, cache encryption, agent dialling).
3. Review of the three GitHub workflows and `.goreleaser.yaml` for supply-chain and release-integrity properties.
4. Safe local checks (see §7) plus pure in-process probes of the macro expanders in both languages (no agent, no network, no credentials, nothing written in the repository).
5. Threat model used: (a) an untrusted project directory containing `./.vauthrc` and `package.json` in which a user runs the CLI/SDK; (b) an on-path network attacker; (c) a compromised or malicious upstream dependency/action; (d) a local attacker with access to the user's files but not the agent; (e) a hostile or compromised Vault.

## 4. Findings (prioritized)

Severity scale: High / Medium / Low / Informational. Each finding is marked **Verified** (confirmed by reading the exact code path and, where noted, by a local probe) or **Hypothesis** (plausible, could not be confirmed offline).

### F1 — Medium — No transport-security floor; SSH-agent signing oracle exposed to any on-path attacker when `vault_addr` is `http://` — Verified

Evidence:
- `index.js:293-295` `_vault_url()` and `index.js:303-309` `Request()` build the URL from `VAULT_ADDR` as-is and hand `protocol` to `nyks/http/request`, which selects `http` vs `https` purely from the scheme (`node_modules/nyks/http/request.js:63`).
- `vault.go:36-38` `vaultURL()` and `vault.go:55-65` `Request()` likewise accept any scheme.
- `rc.go:264-283` `KnownVault()` and `index.js:96-100` compare addresses as trimmed strings; an `http://` address can be allow-listed exactly like an `https://` one.
- SSH login signs **server-chosen** nonces with every key in the user's agent: `index.js:250-259` (`agent.sign(pubKey, Buffer.from(nonce), {}, …)` for each identity) and `vault.go:133-150` (`client.Sign(key, nonce)` for each key).

Impact: with a plaintext or MITM-able endpoint, the bearer token travels in `X-Vault-Token` in clear, and an on-path attacker who answers `GET auth/<path>/nonce` obtains signatures over attacker-chosen bytes from **all** agent identities (the loop tries each key until one succeeds). A chosen-message SSH signature is sufficient to impersonate the user against SSH servers whose session identifier the attacker controls, i.e. the classic agent-oracle attack. The user's allow-list mitigates the *destination* but not the *channel*. The signature request also uses the agent's default flags (SHA-1 `ssh-rsa` for RSA keys in both ssh2 and x/crypto with flags 0) rather than `rsa-sha2-*`.

Fix: refuse non-`https:` schemes unless the host is a loopback literal (keep tests working), or require an explicit `insecure_http: true` in **`~/.vauthrc` only**; pass `rsa-sha2-512` signature flags where the Vault plugin supports them; consider limiting SSH login to a key selected by fingerprint/comment (as `ssh-agent-crypt` already does for the cache) instead of iterating every identity.

### F2 — Medium — Project-controlled `.vauthrc` can select arbitrary local environment variables — including the whole environment — and an unvalidated auth path/role for transmission to Vault — Verified (probe)

Evidence:
- Macro expansion of the private authentication view uses the entire process environment as the lookup dictionary: `index.js:85` (`replaceEnv(value, {env: process.env})`), `rc.go:315-317` (`ReplaceEnv(value, Lookup{"env": environ})`).
- Nothing restricts which variable a **project** file may reference. Local probes: Node `replaceEnv("$${env}", {env})` returns the env **object**, Go `ReplaceEnv("$${env}", …)` returns the env as a **JSON string** (`rc.go:124-128` `stringify` falls back to `json.Marshal`). A project `.vauthrc` with `jwt_auth: {jwt: $${env}}` therefore POSTs the complete environment (cloud keys, CI tokens, …) to `auth/jwt/login` (`index.js:214-216`, `vauth.go:258-263`).
- `ssh_auth.path` / `jwt_auth.path` are concatenated unvalidated into the request path: `index.js:254,286`, `vault.go:107,134`. Probe: `ParseRC` accepted `path: '../../sys/x?y='`; Node's `new URL()` normalizes `..` so the request lands on an attacker-chosen path under `/v1/`, Go sends the raw path.
- When `./.vauthrc` exists, `~/.vauthrc` is **not** merged (`index.js:73`, `rc.go:248-259`): the project fully controls `ssh_auth`/`jwt_auth`.

Impact: the destination is still constrained to a Vault the user vouched for (F1 aside), so this is a confused-deputy/data-exfiltration-to-trusted-party issue rather than a direct compromise: a hostile repository can make the user's tool ship arbitrary local secrets to the trusted Vault's unauthenticated login endpoint (where they land in server/audit logs and are visible to Vault operators), and can drive unauthenticated POST/GET requests to arbitrary `/v1/...` paths with the user's agent signatures attached.

Fix: for files not owned by the user (`./.vauthrc`), restrict macros to an allow-list such as `^(VAULT|VAUTH)_[A-Z0-9_]+$`; reject non-string expansions (`$${env}`); validate `path` against `^[A-Za-z0-9_./-]+$` with no `..`/`?`/`#`; document that `~/.vauthrc` overrides are not merged.

### F3 — Medium — Release/publish supply chain relies on mutable references and unpinned dependency resolution — Verified (configuration)

Evidence:
- All actions are pinned by mutable major tag: `.github/workflows/release.yml:15,18,22,27`, `publish-npm.yml:15,16,20`, `test.yml:14,15,30,31`.
- `release.yml:22-26` checks out `131/gh-actions` at mutable `ref: v1` and `.goreleaser.yaml:18-19` executes `.gh-actions/sign-binaries/sign {{ .Path }}` with `SIGNING_SERVER` in the `production` environment — the code-signing step itself comes from a mutable branch of another repository.
- `package-lock.json` is git-ignored (`.gitignore:2`); `publish-npm.yml:23` runs `npm install` immediately before `npm publish`, so the published package is validated against whatever dependency versions resolve on that day (the lockfile also would not be shipped, which is normal for a library, but it should still gate CI).
- `SHA256SUMS` is not signed; the Linux binary carries no signature or provenance (`.goreleaser.yaml:21-26`).

Impact: a compromised tag in any upstream action, or a push to `131/gh-actions@v1`, executes with `contents: write` (`release.yml:8`) and the signing secret, allowing substitution of released binaries and checksums in one step. `npm install` at publish time widens the window for a poisoned transitive dependency to influence the gate.

Fix: pin actions and `131/gh-actions` to commit SHAs (Dependabot/Renovate can bump them); commit `package-lock.json` and use `npm ci`; sign `SHA256SUMS` (cosign keyless or GPG) and emit provenance (`goreleaser` `sboms`/`signs`, npm `--provenance`).

### F4 — Low — `publish-npm` trigger: `on: create` with a `tags` filter — Hypothesis

Evidence: `publish-npm.yml:3-6` uses `on: create: tags: ['v*']`. GitHub documents `branches`/`tags` filters for `push`, `pull_request`, `pull_request_target` and `workflow_run`; `create` has no documented filter support. If the filter is ignored, every branch creation also runs `npm publish` from that branch (succeeding whenever `package.json` carries a not-yet-published version). I could not verify GitHub's actual behaviour offline.

Fix: use `on: push: tags: ['v*']` (as `release.yml` does) and add a guard that `package.json` version equals the tag without `v`.

### F5 — Low — `go vet ./...` / `go test ./...` in `publish-npm` compile third-party Go code from `node_modules` — Verified (locally reproduced)

Evidence: `publish-npm.yml:23-27` runs `npm install` before `go vet ./...` and `go test ./...`. Locally, `go test ./...` listed `github.com/131/vauth-login/node_modules/flatted/golang/pkg/flatted` (a dev dependency ships Go sources). Go does not skip `node_modules`.

Impact: the Go gate in the publish job compiles (and would run tests of) Go code supplied by npm packages, muddying the release gate and adding an unnecessary execution path for a hostile npm package (lifecycle scripts already give such a package code execution, so the increment is modest).

Fix: run the Go steps before `npm install`, or restrict to `go test . ./cmd/...`.

### F6 — Low — Macro expander robustness and Node/Go divergence — Verified (probe)

Evidence (`node_modules/nyks/string/replaceEnv.js:16-17`, `rc.go:135-156`):
- Node: `$${constructor}` → `RangeError: Maximum call stack size exceeded` (a hostile project `.vauthrc` crashes `new VauthLogin()` and the CLI with a stack trace rather than a clean message).
- Node returns **objects** for object-valued macros (`$${env}`) while Go returns a JSON string; an object in `vault_addr` is stringified to `[object Object]` in `normalizeAddr` (`index.js:38`) and in the cache key (`index.js:111-116`), producing silently different cache keys and error messages between languages.
- Node `throw` of plain strings at `index.js:70` and `index.js:271`; `JSON.parse` of the project's `package.json` at `index.js:67` is unguarded (Go's `CheckProjectVersion` at `vauth.go:81-108` tolerates malformed manifests), so a malformed project manifest aborts the Node CLI/SDK but not the Go one.

Fix: in both implementations, only accept string results and cap recursion; wrap manifest parsing; throw `Error` instances.

### F7 — Low — Unused, outdated development dependencies installed in CI — Verified (lockfile), vulnerability status from memory only

Evidence: `package.json:24-30` declares `mocha ^3.1.2`, `expect.js`, `nyc`; `test/token-cache.js` uses `node --test` and `node:assert` and never references them. The local lockfile resolves `mocha 3.5.3` with `growl 1.9.2`, `debug 2.6.8`, `minimatch 3.1.5`, `diff 3.2.0`. From memory (no live database consulted), `growl < 1.10.0` has a published command-injection advisory. These are dev-only and not shipped, but they are installed on every CI runner (`test.yml:18`, `publish-npm.yml:23`).

Fix: remove the unused dev dependencies.

### F8 — Low — Dependency surface notes — Verified (versions), risk assessment partly from memory

- `go.mod:10` pins `golang.org/x/crypto v0.31.0`; only the `ssh/agent` client is used (`vault.go:15,128`). From memory, later `x/crypto/ssh` releases fixed additional issues (server-side/transport); exposure here is low but the module should be bumped and `govulncheck` run in CI.
- `index.js:23` deep-imports `ssh2/lib/agent` (unexported internal path) — breakage risk on `ssh2` updates.
- On Windows, the Node path uses ssh2's `'pageant'` agent (`index.js:208`), which spawns the **binary blob** `node_modules/ssh2/util/pagent.exe` (`ssh2/lib/agent.js:168,218`); the Go path instead speaks to the Pageant named pipe natively (`agent_windows.go`). Integrators who require reproducible/signed executables should prefer the Go binary on Windows.

### F9 — Informational — Token cache design observations — Verified

- The cache filename is `sha256(JSON{vault_addr, ssh_auth, jwt_auth})` (`index.js:111-120`, `cache.go:25-37`), and `jwt_auth` contains the **expanded JWT**: the filename is an unsalted hash fingerprint of a secret. It is not reversible, but it leaks equality between configurations and ties a public filename to secret material. Consider hashing a secret-free projection.
- Expired cache files are never deleted; they remain encrypted on disk (`index.js:131-156`, `cache.go:62-111`).
- Cached tokens are reused offline without a revocation check (by design; test "cached tokens are reused without checking revocation").
- Encryption (`ssh-agent-crypt`): AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC with authenticated prefix, constant-time compare) with keys derived from a deterministic SSHSIG signature over a random salt (`node_modules/ssh-agent-crypt/index.js:48-129`). Consequence: anyone who can talk to the user's agent (same user, or a forwarded agent) can decrypt; the cache's confidentiality equals the agent's — appropriate for this tool, but worth documenting for integrators who forward agents.

### F10 — Informational — Unbounded response reads and partial deadline coverage — Verified

- Response bodies are read without a size cap: `index.js:310` (`drain`), `vault.go:70` (`io.ReadAll`).
- Node's deadline starts only at request `finish` (`nyks/http/request.js:111-120`): a stalled TCP connect relies on OS timeouts, unlike Go's `http.Client.Timeout` (`vault.go:80-83`).

### F11 — Informational — Repository hygiene — Verified

No `SECURITY.md`/disclosure policy, no Dependabot/Renovate configuration, no `CODEOWNERS`; `.gitignore` excludes the lockfile. The Go module zip necessarily includes every tracked file, including non-code Markdown.

## 5. Strengths

- Destination trust gate executed **before** any URL construction or HTTP request (`index.js:298-299`, `vault.go:44-46`), including for login, renewal and `LookupSelf`; only `./.vauthrc` can be refused, user-owned sources are trusted by design.
- Redirects are never followed (nyks `followRedirect` unset; Go `CheckRedirect` returns `ErrUseLastResponse`), TLS verification is left at platform defaults, timeouts exist on both sides.
- Tokens are never written to stderr or embedded in error strings; `HTTPError` hides the body from default logging (`index.js:46-54`, `vault.go:24-26`).
- Cache writes are atomic (`randomUUID()`/`CreateTemp` + rename), `0600`/`0700`, `wx`, encrypted-only; cache is disabled when no agent is reachable; failures never block login or leak the token.
- Inherited `VAULT_TOKEN` is returned as-is, never looked up, renewed or persisted; `--help`/`--version` run before any configuration or credential access; strict argument parsing.
- Byte-identical cache key between Node and Go with cross-tests; extensive isolated test suites (throwaway agent, temp HOME, loopback fake Vault).
- Workflows use least-privilege `permissions`, OIDC `id-token: write` for npm, a protected `production` environment for releases, `-trimpath -s -w`, Authenticode-signed Windows binary and published checksums.

## 6. Limitations

- Offline, read-only review: **no live vulnerability-database scanning** (`npm audit`, `govulncheck`, OSV) was possible; the dependency observations in F7/F8 rely on reviewer memory and are flagged as such.
- The sandbox denies socket binding, so neither test suite could execute (see §7); test coverage was assessed by reading the test sources.
- GitHub's runtime behaviour for F4 and the real contents of `131/gh-actions@v1` could not be inspected.
- The Vault-side SSH auth plugin was not reviewed; conclusions about nonce handling concern the client only.
- Dependency review was limited to explicitly selected files on the security path; transitive packages were not audited.

## 7. Checks run / not run

| Check | Result |
| --- | --- |
| `git rev-parse HEAD`, `git status --porcelain`, `git ls-files`, remotes | `b80d3113…`, clean, inventory in §1 |
| `npx eslint .` (eslint 8, `plugin:ivs/node`) | passed, exit 0 |
| `gofmt -l .` | no output, exit 0 |
| `go vet ./...` (GOPROXY=off, local module cache) | passed, exit 0 |
| `go test ./...` | **could not run**: `ssh-agent` cannot bind a Unix socket and `httptest` cannot listen on loopback in this sandbox (`operation not permitted`); environmental, not a repository defect |
| `node --test test/token-cache.js` | **could not run**: same sandbox restriction (ssh-agent bind refused) |
| In-process probes of `nyks/string/replaceEnv` and Go `ReplaceEnv`/`ParseRC`/`KnownVault` via a throwaway module in `/dev/shm` with a `replace` directive | results reported in F2/F6 |
| Lockfile inspection (`package-lock.json`, local only): 268 packages, 15 production | versions reported in F7/F8 |
| Not run | `npm audit`, `govulncheck`, `npm pack` tarball comparison, Windows build, `go test -race`, any network access, any access to real agents/Vault/credentials |

No repository file was modified; probe artefacts were confined to the ephemeral `/dev/shm` tmpfs.

## 8. Scores

| Dimension | Score | Justification |
| --- | --- | --- |
| **Coolness** | **15 / 20** | Genuinely useful: one `.vauthrc`, ssh-agent or JWT login, byte-compatible encrypted token cache shared by a Node SDK and a static Go binary, Pageant support, project-pinned versions, a tight converged API. Loses points for the exotic macro syntax inherited from `nyks`, a bundled `pagent.exe` on the Node/Windows path, and no SBOM/provenance story for integrators. |
| **Robustness** | **13 / 20** | Strong, isolated test suites and careful cache/transport error handling. Deductions for: Node crash paths from hostile config (`$${constructor}` stack overflow, unguarded project `package.json` parse, string throws), Node/Go divergence on object-valued macros, no committed lockfile, deep import of `ssh2` internals, and the `go test ./...` / `node_modules` interaction. |
| **Safety** | **13 / 20** | Sound defaults (trust gate before any request, no redirects, TLS verification, token never logged, encrypted atomic cache). Deductions for: no HTTPS floor combined with an all-keys agent signing oracle (F1), project files able to route arbitrary environment variables and unvalidated paths to Vault (F2), and a release chain built on mutable action refs, an externally sourced mutable signing script, and publish-time `npm install` (F3), plus the unverified `on: create` trigger (F4). |

## 9. Recommended remediation order

1. F1 — enforce `https:` (loopback exception) and request `rsa-sha2-*` signatures; consider key selection instead of iterating all identities.
2. F2 — restrict macro namespace for project-level files, reject non-string expansions, validate `path`.
3. F3/F4/F5 — SHA-pin actions and `131/gh-actions`, commit the lockfile and use `npm ci`, switch `publish-npm` to `push: tags` with a version==tag guard, run Go gates before `npm install`, sign checksums.
4. F6/F7/F8 — harden the expanders, wrap manifest parsing, drop unused dev dependencies, bump `x/crypto`, add `govulncheck`/`npm audit` to CI.
5. F9–F11 — secret-free cache key projection, cache expiry cleanup, `SECURITY.md`, dependency-update automation.

*End of advisory. This document is a single independent assessment of commit `b80d3113509f8fb065b3b78f12636b2a1cefeef5` produced on 2026-10-25; no comparison with or consolidation of other assessments was performed.*