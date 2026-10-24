<!-- Host-verified execution provenance. The raw standalone reviewer output is preserved verbatim below. -->

## Host-verified execution provenance

- Fresh independent assessment on October 24, 2026, of clean `main` commit `fd0bf4d2837a3d9955cc87bd47df3d828d4d5b56`.
- Actual model: `gpt-6.1-sol_codeassist`; provider `azure`, default profile, reasoning effort `medium`, Codex CLI `0.164.0`.
- Session: `01a16f29-b647-7681-a024-3fdc9865cc7b`; exit status `0`.
- Exact expanded stdin SHA256: `1784cc231c61edb068b594a27ef969275ab07b3dadaea70511ed76f9f612b3a4`.
- Raw final report SHA256: `8ac3f4ac9ef43cfa6de5aec47a8c4d5c23cc4f7dff246d00eabebf067de5523b`.
- Claude prepared the input without performing another source assessment. The host executed the exact prompt bytes unchanged in a fresh ephemeral read-only session.
- Invocation: `codex exec --ephemeral --sandbox read-only -m gpt-6.1-sol_codeassist -c 'web_search="disabled"' --output-last-message <raw-report> -`, with input supplied through stdin.
- Successful expanded prompt, command and provenance are maintained in `$AGENT_WORKSPACE/users/fleurent/sa/codex-sa-prompt.md`. Scratch materials: `/tmp/tasks/FLEURENT-09/sa-sol-vauth-login-20261024T182509Z/` (temporary, not durable).
- Host inspected the logged read commands and verified byte hashes: tracked source, the Claude report, and checked client configuration/catalog files remained unchanged. Previous assessment content, personal/task/sa material and documentation audit sections were excluded from the source review.
- Claude subsequently accepted completeness and exclusion compliance from the new-run materials and documentation-heading metadata, without another source review or comparison/calibration against earlier reports. This acceptance is not certification of every finding or cited line.
- Publication identity/version/license metadata were verified by the host through Git, GitHub and npm metadata; the reviewer accurately distinguishes supplied context from its own offline source evidence.

---

# Security Assessment — vauth-login

- **Assessed commit:** `fd0bf4d2837a3d9955cc87bd47df3d828d4d5b56`
- **Branch:** `main`
- **Assessment date:** October 24, 2026
- **Actual reviewing model:** `gpt-6.1-sol_codeassist`
- **Method:** Independent, read-only, source-only review of the current working tree.

## Provenance

This assessment was derived from this reviewer's reading of implementation code, tests, dependency manifests, and publication/release configuration. Selected non-assessment documentation was read only for interface context.

Neither `SECURITY_AUDIT_fable-5.1.md` nor any other `SECURITY_AUDIT*.md` content was read, searched, compared, or reused. Excluded inputs also included documentation assessment sections, previous reports and scores, Git history and assessment-related commit messages, personal README files, task indexes and handoffs, coordination conversations, files under `sa/`, and dependency Markdown advisories or audits.

No web search, network verification, real Vault access, or deliberate use of real credentials or SSH-agent identities was performed. No repository files were changed. Git metadata checks confirmed the assessed commit and an unchanged tracked working tree.

The public repository identity and existing npm, Go-module, and GitHub-release distribution described in the task are supplied project context, not independently verified publication facts. This report evaluates their source-defined security implications. It does not authorize changes, publication, or another release.

## 1. Scope and Method

### Scope

The review covered:

- Node.js SDK and standalone CLI.
- Go SDK and standalone CLI.
- Configuration discovery, environment expansion, and Vault-address trust.
- SSH-agent and JWT authentication.
- Token inheritance, renewal, offline reuse, and encrypted persistence.
- Node/Go cache compatibility.
- Dependency selection and local lockfile state.
- GitHub testing, npm publication, binary release, and signing configuration.
- Risks to external consumers, including the pending `vvauth` integration.

### Explicit input inventory

**Implementation and tests**

- `index.js`
- `bin/vauth-login.js`
- `test/token-cache.js`
- `vauth.go`
- `vault.go`
- `cache.go`
- `rc.go`
- `humandiff.go`
- `vauth_test.go`
- `auth_api_test.go`
- `cmd/vauth-login/main.go`
- `cmd/vauth-login/main_test.go`

**Manifests and distribution configuration**

- `package.json`
- `package-lock.json`
- `go.mod`
- `go.sum`
- `.github/workflows/test.yml`
- `.github/workflows/publish-npm.yml`
- `.github/workflows/release.yml`
- `.goreleaser.yaml`
- `.gitignore`
- `.eslintignore`
- `.eslintrc`
- `LICENSE`

**Safely isolated documentation**

Heading line numbers were listed before selecting these ranges:

- `README.md`: lines **1–132**, ending before the Security section.
- `API_and_tests.md`: lines **1–95**, covering public interfaces and the CLI contract.

The remaining documentation ranges were not needed and were not read.

**Supporting dependency source**

The following installed JavaScript sources were inspected to understand behavior delegated by the implementation:

- `node_modules/ssh-agent-crypt/index.js`
- `node_modules/nyks/http/request.js`
- `node_modules/nyks/stream/drain.js`
- `node_modules/nyks/string/replaceEnv.js`
- `node_modules/nyks/object/walk.js`

Selected cryptographic and agent-transport portions of these locally cached Go dependency sources were also inspected:

- `/root/go/pkg/mod/github.com/131/ssh-agent-crypt@v1.4.1/sshagentcrypt.go`
- `/root/go/pkg/mod/github.com/131/ssh-agent-crypt@v1.4.1/agent_unix.go`

These dependency files describe the locally available implementations; their correspondence to downloaded registry artifacts was not independently verified.

**Instruction context**

`$AGENT_WORKSPACE/AGENTS.md` was available and read for instructions only. The checkout was treated as an unmapped external repository; neighboring project rules and excluded workspace personal/task material were not used.

### Safe local checks performed

| Check | Result |
|---|---|
| Filename inventory, excluding Git internals and dependency-tree contents | Completed; assessment filenames were metadata only. |
| Git commit and tracked status, with optional locking disabled | Commit matched the assessment target; tracked status remained clean. |
| `git ls-files --error-unmatch package-lock.json` | Confirmed that the local lockfile is not tracked. |
| `node --check index.js` | Passed. |
| `node --check bin/vauth-login.js` | Passed. |
| `node --check test/token-cache.js` | Passed. |
| `gofmt -l` on the nine selected Go files | No formatting differences reported. |
| JSON parsing and structural inventory of `package-lock.json` | Completed: 267 dependency entries, 15 non-development entries, all dependency entries carrying integrity fields. |
| In-memory transport probes using a substituted HTTP helper | Confirmed that Node lookup bypasses the trust flag and that request construction accepts HTTP. No traffic was sent. |
| In-memory parser probes using synthetic markers | Confirmed source-context disclosure in YAML errors and malformed-login JSON errors. Only Boolean/result messages were printed. |
| In-memory malformed-cache and YAML-alias probes | Confirmed acceptance of a cache missing expiry metadata and a `RangeError` from cyclic configuration traversal. |

The local tools were Node.js **22.22.2** and Go **1.24.0**. Go version discovery used `GOTOOLCHAIN=local`, `GOPROXY=off`, and `GOSUMDB=off`.

An exploratory Node macro-cycle assertion did **not** confirm its hypothesis. No macro-cycle finding is claimed.

### Checks not performed

- **`node --test`, `npm test`, and `go test ./...`:** The inspected suites create temporary files, start SSH agents, generate keys, and bind loopback HTTP servers. They are unsuitable for this invocation's strict read-only and no-network constraints.
- **`go vet`, Go builds, and race testing:** These generally require writable build caches or temporary build artifacts. No writable scratch environment was authorized.
- **Dependency installation, npm audit, vulnerability-database queries, or module downloads:** These would require writes and/or network access.
- **Actual cache encryption/decryption:** No real agent or credential material was used. Cryptographic behavior was assessed from dependency source and test definitions.
- **Publication, signing, release execution, and artifact downloads:** Not authorized and incompatible with the source-only scope.
- **Windows runtime tests or actual Node-to-Go cache exchange:** Not executed.

Tests mentioned below are evidence of intended coverage, not a claim that those tests passed during this review.

## 2. Prioritized Findings

Severity reflects impact and prerequisites. A **verified observation** is supported by inspected code or a safe local probe; it does not necessarily mean an attack was executed. A **hypothesis** identifies an outcome requiring additional confirmation.

### F1 — High: Public SDK helpers bypass the project-Vault trust boundary

**Classification:** Verified observation; credential exfiltration is conditional on consumer usage.

**Evidence**

- Node computes project-address trust in `index.js:82–89` and checks it before login or renewal at `index.js:191` and `209`.
- `lookupSelf()` calls `_lookup_token()` without that check: `index.js:278–289`.
- `request()` constructs the destination and attaches `X-Vault-Token` without checking trust: `index.js:300–318`.
- Go applies the project trust decision in `vauth.go:139–142`, but its transport attaches the token without checking that decision: `vault.go:49–68`.
- Public Go helpers expose that transport directly: `vault.go:211–213` and `225–231`.

An in-memory Node probe confirmed that `lookupSelf()` reaches the substituted transport with a credential header while `_safe_vault` is false.

**Impact**

An external integration can instantiate a client in an untrusted checkout, inherit a token, and then call `lookupSelf()` or `Request()` against the checkout-selected address. `Connect(false)` returning the inherited token does not validate that destination.

An attacker controlling project configuration could therefore obtain a consumer-supplied Vault token if the consumer subsequently uses these helpers. The restricted standalone CLIs do not expose this SDK route.

**Suggested fix**

Enforce destination trust at the common transport boundary for all credential-bearing requests. Bind authorization to the current destination, rather than only to a Boolean computed during construction. Preserve offline token inheritance, but require destination validation before sending that token anywhere.

Add Node and Go regression tests for the complete consumer sequence: construct from unknown project configuration, inherit a token, connect, then attempt lookup and a generic request.

### F2 — Medium: Privileged release inputs are mutable rather than immutable

**Classification:** Verified observation; upstream compromise or unauthorized tag movement is a hypothesis.

**Evidence**

- Release actions use major-version references: `.github/workflows/release.yml:15–19` and `27`.
- The signing helper checkout uses `131/gh-actions` at mutable `ref: v1`: `.github/workflows/release.yml:22–26`.
- GoReleaser itself is selected by a version range: `.github/workflows/release.yml:29`.
- The release job has `contents: write`, receives `GITHUB_TOKEN` and `SIGNING_SERVER`, and invokes the external signing helper through a build hook: `.github/workflows/release.yml:7–8,31–33`; `.goreleaser.yaml:18–19`.

**Impact**

A release can execute upstream code different from what was reviewed, while holding release authority and signing-server access. Compromise of those upstream references could affect binaries distributed to external users.

The `production` environment is a useful control, but its approval and protection rules are not visible in this checkout.

**Suggested fix**

Pin actions and the signing-helper repository to reviewed commit SHAs and select an exact GoReleaser version. Narrow credential exposure to the steps that need it, explicitly minimize checkout credential persistence, and maintain a reviewed update process.

Provide verifiable artifact provenance and an authenticated checksum manifest; checksums alone do not establish publisher identity.

### F3 — Medium: Node parser failures can disclose credential-bearing content on stderr

**Classification:** Verified observation.

**Evidence**

- Configuration parsing is not wrapped in a redacted error: `index.js:40–42`.
- Vault response JSON is parsed directly at `index.js:235`, `258`, `280`, and `294`.
- The CLI prints arbitrary error messages: `bin/vauth-login.js:25–27`.
- Safe probes confirmed that malformed YAML errors include adjacent synthetic credential content and malformed login JSON errors include response content.

**Impact**

A malformed configuration containing a JWT can expose that value in CLI logs. A malformed Vault response can also leak content through a JSON parser diagnostic, despite the otherwise careful `HTTPError` handling.

This is particularly relevant to CI and integrations that capture stderr centrally.

**Suggested fix**

Convert parser failures into fixed, redacted messages. Configuration errors should identify the file and safe location metadata without source excerpts. Vault response parsing should report the operation and response-validation failure without printing response text.

Add malformed YAML and malformed JSON tests asserting that credential markers never appear in stderr.

### F4 — Medium: Authentication and token-bearing requests accept plaintext HTTP

**Classification:** Verified observation; interception requires an exposed HTTP deployment or misconfiguration.

**Evidence**

- Node uses the configured URL protocol without requiring HTTPS: `index.js:300–314`.
- The installed HTTP helper selects HTTP for non-HTTPS transport: `node_modules/nyks/http/request.js:63`.
- Go passes the configured URL directly to `http.NewRequest`: `vault.go:43–68`.
- An in-memory Node probe confirmed HTTP request construction.

**Impact**

A trusted but HTTP-configured endpoint receives JWTs, Vault tokens, or SSH challenge exchanges without transport confidentiality. Address allowlisting does not protect traffic from an on-path observer or modifier.

Normal HTTPS certificate verification has not been explicitly disabled in the inspected default transport.

**Suggested fix**

Require HTTPS by default. Support local development HTTP only through an explicit insecure option, preferably limited to loopback addresses. Apply the policy consistently to login, renewal, lookup, and generic SDK calls.

### F5 — Medium: npm publication lacks a supported, explicit tag-only guard

**Classification:** Hypothesis about hosted execution; the workflow configuration and absent guard are verified observations.

**Evidence**

- `.github/workflows/publish-npm.yml:2–5` uses `create` with a nested `tags: ['v*']` filter.
- The job has no explicit condition checking the created ref type or tag name.
- `npm publish` executes at `.github/workflows/publish-npm.yml:28`.

**Impact**

The `create` event does not provide the tag-filter semantics of `push.tags`. The nested filter should not be relied upon to prevent branch creation or unrelated tag creation from reaching publication. Hosted validation or execution behavior was not tested here.

Unexpected invocation could produce failed publication attempts or, when package version and registry authorization permit it, unintended publication.

**Suggested fix**

Use a supported tag-filtered trigger and add an explicit guard for a release tag. Validate agreement between the tag and `package.json` version before publication. Restrict publication through appropriate repository/environment protections.

OIDC permission is present, but registry-side trusted-publisher configuration cannot be verified from source.

### F6 — Medium: npm CI and publication do not use a committed dependency lock

**Classification:** Verified observation.

**Evidence**

- `.gitignore:2` ignores `package-lock.json`; Git metadata confirmed it is untracked.
- The local lockfile identifies version `1.1.1` at `package-lock.json:3,9`, whereas `package.json:3` identifies `1.1.2`.
- Dependency versions use ranges: `package.json:15–29`.
- Test and publication workflows use `npm install`: `.github/workflows/test.yml:18` and `.github/workflows/publish-npm.yml:23`.
- The local lock inventory includes install scripts for `ssh2` and `cpu-features`.

**Impact**

Fresh CI and publication runs can resolve different transitive dependencies and execute different installation code without changes to tracked project source. The local lockfile cannot establish what the public repository's fresh workflows install.

This does not establish that any dependency is vulnerable or malicious.

**Suggested fix**

Commit and maintain the lockfile, then use `npm ci` for CI and publication. Review required install scripts and consider whether optional native dependencies are necessary in the publication job.

A committed producer lock improves CI reproducibility; it does not by itself freeze dependencies selected by every downstream npm consumer.

### F7 — Medium: Go cache identity can become stale after authentication configuration changes

**Classification:** Verified observation from source; the resulting token mix-up was not dynamically executed.

**Evidence**

- `ParseRC()` stores serialized authentication configuration in private `rc.authKey`: `rc.go:313–326`.
- `RC.AuthKey()` returns that stored serialization whenever it is nonempty: `rc.go:33–35`.
- Cache keys use `RC.AuthKey()`: `cache.go:25–30`.
- Login uses the current exported `RC.SSHAuth` or `RC.JWTAuth` fields: `vauth.go:255–262`.
- Node instead hashes current authentication configuration: `index.js:108–112`.

**Impact**

A Go consumer that parses configuration and subsequently changes its role, JWT, or authentication path can retain the old cache key while authenticating with new settings. It may reuse a token associated with the previous role or write a newly issued token into that previous configuration's cache slot.

This undermines cache isolation and Node/Go consistency for programmatic integrations.

**Suggested fix**

Make authentication configuration immutable, or invalidate/recompute its serialized identity whenever it changes. Ensure the settings used for authentication are exactly those used for cache selection.

Add tests that mutate parsed authentication configuration and verify cache separation.

### F8 — Low: Response bodies are buffered without a size limit

**Classification:** Verified observation.

**Evidence**

- Node drains the complete response at `index.js:315`.
- The installed drain helper accumulates all chunks: `node_modules/nyks/stream/drain.js:12–26`.
- Go uses unrestricted `io.ReadAll`: `vault.go:73`.

**Impact**

A faulty or hostile endpoint can consume substantial memory before the request timeout expires. This matters more when embedded in a long-running consumer or when requests run concurrently.

**Suggested fix**

Set a small, configurable response-size limit appropriate to Vault authentication and metadata responses. Abort immediately when exceeded, including on unexpected HTTP statuses.

### F9 — Low: Decrypted cache metadata is insufficiently validated

**Classification:** Verified observation.

**Evidence**

- Node returns arbitrary successfully parsed decrypted JSON: `index.js:119–125`.
- Expiry calculations assume metadata fields exist: `index.js:178–188`.
- Go accepts any successfully unmarshaled cache with a nonempty token: `cache.go:55–59`.
- A missing Go `expires_at` becomes nil and is treated like an unlimited expiry: `cache.go:16–20`; `vauth.go:218–228`.

An in-memory Node probe confirmed that a cache with a token but no `expires_at` is reused.

**Impact**

Malformed but decryptable cache data can be treated as reusable without a meaningful expiry. Arbitrary unauthenticated ciphertext is not sufficient: the cryptographic layer rejects it. The concern is authenticated malformed data, implementation mistakes, or incompatible cache producers.

**Suggested fix**

Validate an explicit cache schema before reuse: token type, finite nonnegative lease duration, renewable type, and a required expiry field. Distinguish a missing expiry from an explicitly unlimited lease.

### F10 — Low: Cyclic YAML aliases crash Node configuration traversal

**Classification:** Verified observation.

**Evidence**

- Node passes selected parsed configuration directly into recursive traversal: `index.js:40–42`.
- The installed walker has no visited-object or depth guard: `node_modules/nyks/object/walk.js:8–10`.
- A safe in-memory cyclic-alias probe produced `RangeError`.

**Impact**

A project-controlled configuration can make the Node CLI fail through stack exhaustion. This is an availability issue, not demonstrated code execution or credential disclosure.

**Suggested fix**

Reject cyclic aliases or traverse with cycle detection and a depth limit. Validate authentication fields against an explicit schema before environment expansion.

## 3. Strengths

- **Small, focused CLI surface.** Both executables reject unsupported arguments before authentication. Help and version paths avoid configuration loading: `bin/vauth-login.js:7–18`; `cmd/vauth-login/main.go:36–58`.
- **Useful project-address protection.** Unknown project-selected Vaults are rejected before fresh login and renewal. The principal gap is its absence from SDK transport helpers.
- **Inherited-token discipline.** Normal inherited-token handling does not look up, renew, or persist the token: `index.js:163–168`; `vauth.go:202–206`.
- **Authenticated encryption instead of plaintext persistence.** The inspected dependency uses randomized salt and IV, separate encryption/MAC keys, AES-256-CBC, and HMAC-SHA256 verified before decryption. V3 authenticates its header and uses an SSHSIG namespace. This is not a blanket cryptographic certification.
- **Careful cache replacement.** Node uses exclusive creation of a unique temporary file and rename; Go uses `CreateTemp` and rename. New directories and files request restrictive permissions. Cache failures do not intentionally print credentials.
- **Controlled renewal fallback.** Renewal failures trigger login only for 400/403; other errors propagate rather than generating extra tokens.
- **Default redirect protection.** Go rejects redirects explicitly. Node does not enable the installed helper's redirect-following option.
- **Safer ordinary HTTP errors.** Both implementations' normal HTTP error strings omit server bodies. Node additionally hides the body from ordinary enumeration.
- **Substantial test definitions.** Tests cover offline reuse, renewal thresholds, rejected renewals, inheritance, cache disabling, corrupt/plaintext cache rejection, CLI restrictions, trust decisions, response validation, and transport behavior.
- **Public distribution foundations.** The ISC license is present. Go dependencies are versioned with checksum entries. Binary releases configure checksums, trimmed build paths, version injection, and a Windows signing hook.
- **CI permissions are differentiated.** Ordinary testing uses read-only repository permissions; npm publication uses OIDC capability rather than an explicitly configured long-lived npm token.

## 4. Limitations and Operational Considerations

- **This is not a vulnerability-database audit.** Dependency versions were inspected, but current advisory status was not established. No CVE claims are made.
- **Tests were read, not executed.** Syntax checks, formatting checks, and narrow in-memory probes cannot establish full runtime correctness.
- **Published artifacts were not examined.** This review cannot confirm that existing npm contents or release binaries match the assessed source, that signatures validate, or that checksum files are authentic.
- **Hosted protections remain unknown.** Tag restrictions, environment approvals, npm trusted-publisher settings, signing-service controls, and actual workflow execution are outside source-only visibility.
- **Offline reuse is not online validation.** Both implementations deliberately reuse locally unexpired cached tokens without checking revocation. A successful connection therefore does not prove current server acceptance. Tests explicitly encode this behavior.
- **Connected instances retain tokens.** `index.js:159–161` and `vauth.go:198–200` return an already established token without rechecking expiry. Long-lived integrations must not assume repeated calls refresh it.
- **Clients expose mutable state without synchronization.** Configuration and tokens can change independently of cached trust decisions. Concurrent Go use and overlapping Node connection calls require consumer discipline.
- **Interoperability is only partly substantiated.** The inspected formats and ordinary key fixtures align, but no actual Node-to-Go and Go-to-Node exchange was performed. Exotic YAML/JSON serialization cases and configuration mutation need additional coverage.
- **Atomic replacement is not a complete filesystem security policy.** Preexisting directory permissions are not tightened, crash durability is not established, and Windows ACL behavior was not tested.
- **SSH-agent authority remains trusted.** Cache encryption protects stored bytes, not a process capable of using the same agent or private key. Legacy armor is also accepted by the inspected dependency.
- **Windows coverage is limited.** The workflow builds on Windows but runs Go tests only on Linux: `.github/workflows/test.yml:37–40`. Actual Pageant/OpenSSH behavior and signed-binary operation were not checked.
- **External-consumer acceptance remains necessary.** In particular, the pending `vvauth` integration should verify destination trust before metadata requests, token refresh semantics, immutable cache identity, and log redaction.

## 5. Scores

These are subjective engineering assessments, not probabilities of compromise or release approvals.

| Dimension | Score | Justification |
|---|---:|---|
| **Coolness** | **17/20** | A compact dual-language Vault login tool with agent-backed encrypted caching, shared interfaces, and useful public distribution channels is technically compelling. |
| **Robustness** | **13/20** | Clear lifecycle code and substantial test definitions are offset by mutable-state/cache inconsistencies, weak cache validation, unbounded responses, and unverified cross-platform behavior. |
| **Safety** | **11/20** | Encryption, restricted CLIs, redirect controls, and login-time address checks are meaningful strengths. SDK credential routing, parser-log disclosure, plaintext transport acceptance, and publication reproducibility need improvement for external adoption. |

**Overall conclusion:** The implementation has a credible security foundation, especially for its narrow CLI use case. It should not yet be treated as a uniformly guarded SDK: the most important remediation is to enforce Vault-destination trust where credentials are actually sent. Public adoption also makes redacted failure handling and a reproducible, tightly controlled publication pipeline essential.