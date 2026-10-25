# Host provenance — GPT 6.1 Sol, post-publication assessment

- Assessed release: **vauth-login 1.1.4**, tag `v1.1.4`, clean commit `b80d3113509f8fb065b3b78f12636b2a1cefeef5`.
- Date: **October 25, 2026**. Publication completed and was verified **before** this independent assessment; this report is a later documentation-only publication on main, not part of the immutable release tag/npm tarball.
- Actual execution model: **`gpt-6.1-sol_codeassist`**, provider `azure`, Codex CLI `0.164.0`, session `01a17244-8e82-74e1-b1b9-2ec6ca8dbbe2`, exit `0`. Claude prepared the exact Sol stdin; the host executed it unchanged in a new default-profile session.
- Input SHA256: `aece5302016ca534a56d54d925c6fe03ad0902b4026056dbae6cf9448f35d859`.
- Raw report SHA256: `61e2ad694bda1b036e8af4871ddbfbdc17892b98784fbac51d5aecea406e6eec`. The raw response is preserved byte-for-byte after the separator below.
- Both reviewers inventoried current inputs and excluded previous assessment contents, README at every depth, personal tasks/sa materials and coordinator history. Current API documentation was isolated through headings/ranges. Host inspection of executed command inventories found no prohibited report reads. Tracked source and checked client configuration hashes were unchanged before/after reviews.
- Supporting dependency inputs included local installed sources and an ignored local npm lockfile; that lockfile is not a committed release manifest.
- Check scope: Sol ran Node syntax checks, gofmt and bounded stubbed/in-memory probes. It did not run ESLint, Go vet/builds or full test suites. An exploratory macro assertion failed before a distinct escaped-recursion case was verified; the report distinguishes the two.
- Host release checks, separate from reviewer checks: 85 Node24 tests, ESLint, Go vet/race, Linux/Windows builds; successful test/publish/release CI; npm latest tarball integrity and exact source; Go proxy manifest/source; GitHub asset checksums; Linux version/help; Windows Authenticode verification.
- Limitations and hypotheses remain the reviewer's judgments. No live vulnerability scan was performed. No real cache, agent, credentials or Vault was used in its synthetic probes. Neither scores nor findings were rewritten to agree with the other report.

- Coordination acceptance: both complete reports were checked in a separate Claude validation phase after independent outputs finished, without score/severity calibration.
- Local-lockfile caveat: lockfile-integrity and lockfile-root-version observations concern the ignored local installation file, not the immutable published artifacts; host checks separately verified those artifacts against the tag.

### Exact host command

```bash
command codex exec --ephemeral --sandbox read-only -c 'web_search="disabled"' --output-last-message /tmp/tasks/FLEURENT-09/release-vauth-login-20261025T085000Z/codex-report.md - < /tmp/tasks/FLEURENT-09/release-vauth-login-20261025T085000Z/codex-input.txt > /tmp/tasks/FLEURENT-09/release-vauth-login-20261025T085000Z/codex-run.log 2>&1
```

## Raw reviewer response

---

# Security Assessment — vauth-login v1.1.4

- **Assessed commit:** `b80d3113509f8fb065b3b78f12636b2a1cefeef5`
- **Tag:** `v1.1.4`
- **Branch:** `main`
- **Assessment date:** October 25, 2026
- **Execution model:** `gpt-6.1-sol_codeassist`
- **Method:** Independent, read-only, offline source assessment.

## Provenance

This assessment was derived from my own inspection of the current implementation, selected test bodies, dependency manifests, selected locally available dependency sources, and release workflows. Local Git metadata confirmed that HEAD and `v1.1.4` resolve to the assessed commit, with a clean working tree.

Neither existing `SECURITY_AUDIT*.md` document was read. README files at every depth, assessment documentation, historical assessments and related commit messages, personal task indexes, prior findings and handoffs, and dependency Markdown advisories were excluded. `API_and_tests.md` was inspected by listing heading line numbers first, then reading only the isolated API and CLI sections at lines 3–137.

Publication status supplied by the operator was treated as context, not as evidence that the implementation is secure. No registry, release artifact, deployed service, credential, or live Vault was accessed. No files were modified, and no publication, versioning, deployment, or additional review session was initiated.

## 1. Scope and Method

### Input inventory

The initial repository filename inventory identified the following selected inputs:

| Area | Selected inputs |
|---|---|
| Node implementation | `index.js`, `bin/vauth-login.js` |
| Node tests | `test/token-cache.js`, including fixture setup and selected authentication, cache, transport, CLI, and getter tests |
| Go implementation | `vauth.go`, `vault.go`, `rc.go`, `cache.go`, `humandiff.go` |
| Go tests | Selected bodies in `vauth_test.go`, `auth_api_test.go`, and `cmd/vauth-login/main_test.go` |
| Go CLI | `cmd/vauth-login/main.go` |
| Dependency manifests | `package.json`, `package-lock.json`, `go.mod`, `go.sum` |
| CI and release | `.github/workflows/test.yml`, `.github/workflows/publish-npm.yml`, `.github/workflows/release.yml`, `.goreleaser.yaml` |
| API documentation | `API_and_tests.md`, lines 3–137 only |

Additional dependency inputs were explicitly selected after filename discovery:

- `node_modules/nyks/http/request.js`
- `node_modules/nyks/stream/drain.js`
- `node_modules/nyks/object/{freeze,walk,jqdive}.js`
- `node_modules/nyks/string/replaceEnv.js`
- `node_modules/ssh-agent-crypt/index.js`
- Package-version metadata from the installed `nyks`, `ssh-agent-crypt`, `ssh2`, and `yaml` manifests.
- Selected cryptographic and agent-handling sections of the locally cached Go dependency `github.com/131/ssh-agent-crypt@v1.4.1`:
  - `sshagentcrypt.go`
  - `agent_unix.go`
  - `agent_windows.go`

Applicable instructions were read from `$AGENT_WORKSPACE/AGENTS.md` and its `monolith/AGENTS.md`. Ancestor instruction-file existence was checked. No matching internal project mapping was applied to this external checkout, and neighboring project rules were not borrowed. README and personal-context requirements were skipped under the assessment’s explicit exclusions.

### Review approach

The review traced:

- Configuration precedence and authentication-only environment expansion.
- Project-selected Vault destination checks.
- Inherited-token, cached-token, SSH, JWT, and forced-login behavior.
- Login and renewal response validation.
- Token-cache encryption, naming, expiry, persistence, and interoperability.
- Public `Connect`, `LookupSelf`, and `Request` behavior.
- Read-only configuration and token/address readers.
- HTTP construction, redirects, deadlines, and response buffering.
- CI permissions, dependency installation, publication, and binary signing configuration.

The threat model includes hostile network intermediaries when insecure transport is configured, malicious or compromised permitted endpoints, malformed configuration, and attackers with limited cache-file access. Arbitrary code already executing as the user is outside a meaningful SDK containment boundary: such code can directly access the environment, client token readers, and SSH agent.

### Safe local checks run

Local tools were Node.js `v22.22.2` and Go `go1.24.0`, on Linux amd64.

| Check | Result |
|---|---|
| Git HEAD, branch, remote, tag target, and status inspection | Expected commit and tag; clean working tree |
| `node --check index.js` | Passed |
| `node --check bin/vauth-login.js` | Passed |
| `node --check test/token-cache.js` | Passed |
| `gofmt -l` over selected Go implementation and test files | No filenames reported |
| In-memory lockfile inspection | 267 non-root package entries; all had integrity metadata and HTTPS resolution URLs |
| Installed dependency-version inspection | Selected installed versions matched their lockfile entries |
| Stubbed Node `Request` | Accepted a plaintext HTTP target without opening a socket |
| Stubbed Node cache reuse | Accepted an entry missing `expires_at` |
| Repeated Node connection check | Established connection bypassed subsequent cache processing |
| Nested Node RC immutability check | Passed |
| In-memory malformed-YAML check | Parser exception contained a synthetic credential marker; marker was not printed |
| Cyclic YAML authentication subtree | Parsed and froze, then recursive traversal raised `RangeError` |
| Escaped recursive environment macro | Raised `RangeError` |
| Source-equivalent cache-key comparison | Explicit null authentication member produced different Node/Go key representations |

The probes used synthetic values, an empty process environment, virtual configuration reads, and a stubbed transport. They did not decrypt a real cache or contact an agent.

An initial exploratory assertion incorrectly expected an ordinary self-referential macro to recurse. It failed because JavaScript replacement-string handling changed the expansion. That result was not treated as a finding; a separate escaped recursive case was subsequently verified.

### Checks not run

- **`node --test`, `npm test`, and `go test`:** The test setup creates files, generates keys, starts SSH agents, and opens loopback listeners. Those operations were outside this strictly read-only, no-network execution.
- **`go vet`, Go builds, and race tests:** These ordinarily require writable build-cache or temporary output. They were not run by bypassing the sandbox or redirecting writes elsewhere.
- **ESLint:** Not executed; this review used syntax checks and source inspection rather than loading the lint-plugin execution path.
- **`npm install`, `npm ci`, `go mod download`, `npm audit`, and live vulnerability scanners:** Not authorized.
- **Release reproduction, Windows execution, signature verification, and artifact comparison:** Not performed in this independent source-only phase.

Accordingly, this document does not claim that the full test suites passed during this assessment.

## 2. Prioritized Findings

Severity reflects the stated prerequisites, not merely the presence of a missing safeguard. “Verified observation” means the behavior is supported by source or a safe local check; it does not imply demonstrated exploitation.

### F1 — High: Non-loopback plaintext HTTP can carry authentication credentials

**Classification:** Verified observation; impact conditional on configuration.

**Evidence:**

- `index.js:293–309` constructs the URL and passes its protocol to the HTTP dependency without enforcing HTTPS.
- `node_modules/nyks/http/request.js:63` selects HTTP when the protocol is not HTTPS.
- `vault.go:55–65` constructs and sends requests without an HTTPS policy.
- JWT login sends credentials at `index.js:214–216` and `vauth.go:258–263`.
- Explicit tokens are placed in `X-Vault-Token` at `index.js:301` and `vault.go:62–63`.

A stubbed local check confirmed that Node `Request` accepts an HTTP destination.

**Impact:** A configured or allowlisted non-loopback HTTP endpoint exposes bearer tokens and JWT login material to network observation and modification. The project-address allowlist establishes destination approval, not transport confidentiality or authenticity.

**Suggested fix:** Require HTTPS by default. Permit loopback HTTP only through a narrowly defined development exception or explicit insecure-transport setting. Validate the scheme centrally before any authentication request.

### F2 — Medium: Node configuration errors can echo credential-bearing source lines

**Classification:** Verified observation.

**Evidence:**

- `index.js:75–77` directly parses the complete configuration document.
- `bin/vauth-login.js:25–26` prints the resulting exception message.
- An in-memory malformed inline `jwt_auth` document caused the installed YAML parser’s exception message to include a synthetic credential marker from that line.

**Impact:** A syntax error can disclose a literal JWT or other sensitive configuration content to stderr, terminal capture, CI logs, or support transcripts. Status-only HTTP errors do not protect this separate parser-error path.

**Suggested fix:** Catch configuration-parser exceptions at the configuration boundary and emit a sanitized filename, line/column, and generic error description without a source excerpt. Apply similar sanitization to other externally influenced diagnostics. Add regression tests using synthetic sensitive markers.

### F3 — Medium: HTTP response buffering has no byte limit

**Classification:** Verified observation.

**Evidence:**

- `index.js:309–310` drains the entire response.
- `node_modules/nyks/stream/drain.js:12–26` retains every chunk and concatenates them.
- `vault.go:69–70` uses unrestricted `io.ReadAll`.

**Impact:** A malicious or compromised permitted endpoint can send a large response quickly enough to exhaust memory within the configured deadline. Both success and error responses are affected; constructing an HTTP error may also create an additional string representation.

**Suggested fix:** Enforce an explicit response-size limit while streaming, close or destroy oversized responses, and return a sanitized size-limit error. Use a configurable SDK limit and a conservative authentication-response default. A time limit is not a memory limit.

### F4 — Medium: Cache ciphertext is not authenticated to its Vault/configuration context

**Classification:** Hypothesis grounded in verified source structure.

**Evidence:**

- Configuration context determines the filename through `index.js:111–119` and `cache.go:25–36`.
- The encrypted plaintext contains token and lifetime metadata, but no context identifier: `index.js:138–145`, `cache.go:16–20,66–71`.
- Reads decrypt the file selected by the current context without checking an embedded context: `index.js:122–127`, `cache.go:43–59`.
- The dependency authenticates its armor, but does not receive the Vault/configuration cache key as authenticated context.

**Impact:** An attacker able to read one valid encrypted cache and substitute it at another cache path may cause the same user’s agent to decrypt and reuse that token under a different configuration. A subsequent request could send it to a different permitted Vault.

This requires cache access and a usable matching agent key. No ciphertext-substitution attack was executed, and this is not a remote cache-forgery claim.

**Suggested fix:** Include a versioned context identifier inside the authenticated encrypted payload and verify it before reuse. The identifier should bind the selected Vault and authentication configuration. Keep the hashed filename as indexing, not as the only context binding.

### F5 — Medium: Release jobs execute mutable external references

**Classification:** Verified observation; compromise scenario is hypothetical.

**Evidence:**

- Workflow actions use mutable major tags:
  - `.github/workflows/test.yml:14–15,30–31`
  - `.github/workflows/publish-npm.yml:15–20`
  - `.github/workflows/release.yml:15–18,22–27`
- The signing helper is checked out from `131/gh-actions` at `ref: v1`: `.github/workflows/release.yml:22–26`.
- GoReleaser is selected through a version range: `.github/workflows/release.yml:27–30`.
- The release job receives the GitHub token and signing-server secret: `.github/workflows/release.yml:31–33`.
- Node jobs use `npm install`, rather than a fail-on-lock-drift installation: test workflow line 18 and publish workflow line 23.

**Impact:** Compromise or unexpected movement of an action/helper reference can affect privileged release execution. Dependency resolution is also less strictly enforced than with `npm ci`. No compromised component was identified.

**Suggested fix:** Pin actions and the signing-helper checkout to reviewed immutable commit IDs, pin the release tool version, and use `npm ci` with a synchronized lockfile. Maintain controlled update automation and narrowly scoped release permissions.

The actual contents of the external signing helper and repository environment protections were unavailable to this review.

### F6 — Low: Decrypted cache metadata is insufficiently validated

**Classification:** Verified observation.

**Evidence:**

- Node accepts any successfully decrypted, JSON-parsed value at `index.js:122–128`.
- Node lifetime decisions assume usable cache fields at `index.js:181–191`.
- Go validates JSON decoding and a nonempty token, but not field presence or lifetime consistency: `cache.go:55–59`.
- Go’s missing `expires_at` becomes a nil pointer, which the connection path treats as unlimited: `vauth.go:225–234`.

A stubbed Node cache with no `expires_at` was accepted.

**Impact:** Authenticated but malformed, old, or incorrectly produced cache entries can bypass intended expiry handling or produce invalid SDK return values. In Node, missing expiry produces a non-finite computed TTL that does not trigger the renewal threshold. In Go, missing expiry is indistinguishable from explicit unlimited validity.

Encryption prevents arbitrary unauthenticated JSON substitution; this finding does not negate that protection.

**Suggested fix:** Validate a versioned schema after decryption: nonempty string token, valid lease duration, boolean renewable field, and explicitly present expiry. Distinguish missing expiry from deliberate unlimited validity and reject inconsistent entries as cache misses.

### F7 — Low: Established clients do not re-evaluate token expiry

**Classification:** Verified observation.

**Evidence:**

- Node immediately returns the established token at `index.js:162–164`.
- Go does the same at `vauth.go:205–207`.
- Existing reuse tests intentionally assert this short-circuit behavior.

**Impact:** A long-lived SDK client can keep returning an expired or revoked token from `Connect(false)`. The expiry and last-third renewal logic applies when establishing a connection, not on every subsequent call.

This does not extend a token’s server-side privileges or validity; Vault can still reject it. It is primarily an availability and integration hazard.

**Suggested fix:** Track established-token expiry and re-enter the renewal/login path when appropriate. Preserve the documented offline treatment of inherited tokens, and make clear that returning a token is not proof of current server-side validity.

### F8 — Low: Recursive Node configuration processing can fail on accepted structures

**Classification:** Verified observation.

**Evidence:**

- `index.js:85` recursively walks the cloned authentication view.
- `node_modules/nyks/object/walk.js:8–10` has no cycle detection.
- `node_modules/nyks/string/replaceEnv.js:23–24` recursively expands without a depth bound.
- Go bounds macro expansion to 16 iterations at `rc.go:135–154`.

Safe local checks confirmed that a cyclic YAML authentication subtree reaches a traversal `RangeError`, and an escaped recursive macro also reaches a `RangeError`.

**Impact:** Malformed or hostile project configuration can prevent client construction through stack exhaustion. Recursive processing is inconsistent between the implementations.

**Suggested fix:** Validate configuration structure, reject cyclic authentication subtrees, and bound traversal and macro expansion. Return sanitized configuration errors rather than raw stack failures.

### F9 — Low: Interoperability and release metadata have concrete edge-case drift

**Classification:** Verified observation; interoperability consequence derived from source.

**Evidence:**

- Node serializes explicit null authentication members into its cache-key input: `index.js:112–115`.
- Go skips null authentication members: `rc.go:323–326`.
- `package.json:3` declares `1.1.4`, while `package-lock.json:3,9` retains `1.1.3`.

A source-equivalent comparison confirmed different cache-key inputs when one authentication member is explicitly null.

**Impact:** A document containing a valid JWT authentication section and `ssh_auth: null` can produce separate Node and Go cache files, causing extra logins rather than interoperable reuse. The stale lockfile root version is a reproducibility and maintenance inconsistency, not evidence that the wrong package was published.

**Suggested fix:** Define and test canonical cache-key handling for missing, null, empty, and reordered authentication members. Synchronize lockfile root metadata in a future authorized change. Preserve context isolation when changing key normalization.

## 3. Strengths

- **Destination checks precede requests.** Unknown project-selected Vaults are rejected in Node `Request` and Go `Request`, including login, renewal, and lookup operations. There is no interactive acceptance bypass.
- **Default transports refuse redirects.** Node does not enable dependency redirect following; Go explicitly returns `http.ErrUseLastResponse`. This reduces credential forwarding through redirected requests.
- **Normal HTTP errors avoid body disclosure.** Error messages report status, while response bodies remain available to SDK callers. Node makes its body property non-enumerable.
- **Cache writes are encrypted and atomic.** Both implementations use temporary files and rename; newly created Unix cache files/directories request restrictive permissions.
- **Current cache encryption authenticates ciphertext.** The inspected `ssh-agent-crypt` v3 implementations use random salt and IV, separate encryption/MAC keys, HMAC verification before decryption, and constant-time MAC comparison. CBC is not used unauthenticated.
- **Current cryptographic derivation is namespaced.** The dependency uses an SSHSIG envelope with a dedicated namespace and supports deterministic RSA/Ed25519 derivation.
- **Inherited-token handling is conservative.** Ordinary connection returns an inherited token offline without lookup, renewal, or persistence. Forced login does not silently reuse it.
- **Renewal failure handling is restrained.** Invalid-token statuses permit reauthentication; network/server renewal failures are propagated rather than automatically generating additional credentials.
- **Login/renewal responses require usable metadata.** Both implementations reject missing or negative lease durations and missing tokens; lookup requires TTL.
- **Configuration readers protect internal state.** Node recursively freezes the complete parsed document; Go returns independently decoded snapshots. Authentication expansion operates separately from the public document view.
- **CLI dispatch is narrow.** Unknown arguments are rejected before configuration loading or credential output. Help and version avoid authentication initialization.
- **Tests cover security-relevant behavior.** Inspected cases cover destination refusal, redirects, stalled responses, plaintext-cache rejection, cache permissions, inheritance, renewal errors, CLI output, and immutable readers.
- **CI has useful separation and checks.** Test workflows have read-only repository permissions; publication workflows include tests; Go checks cover Linux and Windows builds. Release configuration includes checksums and a Windows signing hook.
- **Dependency manifests provide integrity metadata.** The inspected npm lockfile entries have integrity values and HTTPS resolution URLs; Go dependencies have pinned module versions and checksums.

These are source observations and inspected test intentions, not substitutes for executing the tests or validating operational controls.

## 4. Limitations

- **No network access and no live vulnerability-database scanning were performed.** This assessment cannot establish that the direct or transitive dependency graph is free of known vulnerabilities.
- Dependency inspection was selective, not a complete audit of YAML, SSH, HTTP, cryptographic, operating-system, or transitive dependency implementations.
- Locally installed dependency versions were checked against lockfile metadata, but their complete contents were not independently verified against registry artifacts.
- Full tests, race detection, builds, and `go vet` were not executed under this execution’s restrictions.
- Windows agent behavior, ACLs, cache replacement semantics, and signed binaries were not dynamically validated. Unix mode arguments do not establish Windows ACL protection or repair pre-existing directory permissions.
- No real Vault policy, SSH authentication plugin, JWT issuer/audience policy, TLS configuration, or deployment was assessed.
- SSH login signs the server-provided nonce directly (`index.js:254–261`, `vault.go:134–159`). Server challenge generation and cross-protocol resistance depend on an unreviewed plugin/protocol. No cross-protocol attack was demonstrated.
- Agent operations do not show explicit application deadlines in the inspected paths. HTTP response deadlines therefore do not establish a bound for the entire authentication operation.
- A caller-supplied Go `HTTPClient` can replace default redirect and timeout behavior. The default-client strengths do not automatically apply to custom clients.
- Cache encryption protects storage, not a process already able to use the relevant agent or read returned tokens. It also does not provide replay prevention.
- RC intentionally exposes the complete document, potentially including literal credentials. “Read-only” means immutable state, not redacted content.
- External signing-helper code, branch/tag protections, npm trusted-publisher settings, production-environment approvals, and signing-service authorization were not available as source inputs.
- The prototype API is not assumed to be concurrency-safe or compatibility-stable. No separate consumer, including `vvauth`, was inspected.
- The operator’s successful publication checks were not reused as security proof.

## 5. Scores

| Dimension | Score | Justification |
|---|---:|---|
| **Coolness** | **17/20** | A compact dual-language SDK/CLI with SSH-agent-backed encrypted caching, JWT support, aligned public methods, and a practical native release pipeline. |
| **Robustness** | **13/20** | Good failure handling and substantial regression coverage, offset by unlimited buffering, weak cache-schema validation, established-token expiry shortcuts, and configuration/interoperability edge cases. Full tests were not executed here. |
| **Safety** | **12/20** | Destination approval, redirect refusal, authenticated cache encryption, and restrained normal logging are valuable. Plaintext transport, parser-error disclosure, unbound cache context, and mutable privileged release inputs leave meaningful conditional risks. |

**Overall assessment:** The released source contains useful security controls, but those controls do not justify treating successful publication as a security proof. The highest-priority future changes are secure transport enforcement and sanitized configuration errors, followed by response limits, authenticated cache-context binding, strict cache validation, and immutable release inputs. This assessment authorizes no software change or further release.