<!-- Host-verified provenance; the raw standalone reviewer output is preserved verbatim below. -->

## Host-verified release-assessment provenance

- Date: October 24, 2026. Clean functional source commit `41f56c1a8e7effe655e2b6034f934780f99fcdef` on `main`.
- This snapshot has version 1.1.2; the operator-authorized patch 1.1.3 is prepared after the independent assessments through documentation-only consolidation and metadata-only ppackage versioning. The report is not an audit of downloaded release binaries.
- Actual model: `gpt-6.1-sol_codeassist`; provider `azure`, profile `default`, Codex CLI `0.164.0`.
- Session: `01a16f71-0128-7ee2-9edc-4364240da257`; exit status `0`.
- Exact successful expanded stdin SHA256: `c5beea5c3142761fab406eab7eddc82876cfd3dcaf7cd6b83bdae14368d3dc06`.
- Raw final output SHA256: `ca98db488df9605af5fd0e16fa4652ef44f255c6c3ae26b00b657212f865b125`.
- Invocation: `codex exec --ephemeral --sandbox read-only -m gpt-6.1-sol_codeassist -c 'web_search="disabled"' --output-last-message <raw-report> -`, with exact prompt bytes supplied through stdin.
- Exact successful input, command and provenance are maintained in `$AGENT_WORKSPACE/users/fleurent/sa/codex-sa-prompt.md`. Scratch materials: `/tmp/tasks/FLEURENT-09/release-vauth-login-20261024T194258Z/` (temporary, not durable).
- The host verified immutable tracked source, both preexisting reports and checked client configuration/catalog files during independent analysis. Logged commands were checked for input exclusions. Models did not receive earlier findings, scores, conversation or task handoffs.
- Claude prepared Sol's prompt without a source assessment; the host ran its bytes unchanged. Subsequent Claude coordination accepted completeness/exclusion compliance, not the correctness of every finding, and did not rewrite scores or conclusions.
- Sol used isolated README ranges 1–132, 140–144 and 197–end and API documentation lines 1–114, confirmed by host heading inspection; prior audit sections were not emitted.
- Sol performed syntax/format/ESLint and bounded in-memory checks, not complete runtime suites, builds, or a live vulnerability-database scan.
- Full local release validation is separate from the reviewers' checks. This report does not certify production settings, current advisory status, artifact identity, or absence of vulnerabilities.

---

# Independent Security Assessment — vauth-login

- **Assessed commit:** `41f56c1a8e7effe655e2b6034f934780f99fcdef`
- **Branch:** `main`
- **Assessment date:** October 24, 2026
- **Reviewer model:** `gpt-6.1-sol_codeassist`
- **Method:** Independent, read-only, source-only review of the current working tree and selected locally available dependency sources.

## 1. Provenance

This assessment was derived from my own inspection of implementation code, tests, dependency manifests, and release configuration. It was not based on either existing security assessment.

Excluded inputs were not read: `SECURITY_AUDIT*.md` contents at any depth; documentation security-assessment sections; previous reports, findings, or scores; Git history and historical assessment content; personal READMEs, task indexes, handoffs, or coordination material; files under `sa/`; and dependency Markdown containing advisories or audits. Documentation headings were listed before selected non-assessment ranges were printed.

The applicable workspace `AGENTS.md` was read for instructions only. The external checkout is unmapped, and no neighboring project rules or conclusions were adopted. Personal-context and handoff instructions were not followed where they conflicted with the explicit input exclusions.

The repository remote and assessed commit were checked locally. Public repository status, npm publication, Go distribution, and the existing GitHub release are operator-provided context, not independently reverified through network access.

No files were written or modified. No credentials, real Vault services, network services, publication commands, or release operations were used. This report does not authorize release `1.1.3` or certify existing distributed artifacts.

## 2. Scope and Method

### Explicit input inventory

The initial filename inventory covered repository files outside `.git` and `node_modules`. The following files were selected as reviewer inputs:

| Area | Inputs |
|---|---|
| Node implementation | `index.js`, `bin/vauth-login.js` |
| Node tests | `test/token-cache.js` |
| Go implementation | `vauth.go`, `vault.go`, `cache.go`, `rc.go`, `humandiff.go`, `cmd/vauth-login/main.go` |
| Go tests | `vauth_test.go`, `auth_api_test.go`, `cmd/vauth-login/main_test.go` |
| Dependency manifests | `package.json`, `package-lock.json`, `go.mod`, `go.sum` |
| Workflows | `.github/workflows/test.yml`, `.github/workflows/publish-npm.yml`, `.github/workflows/release.yml` |
| Release configuration | `.goreleaser.yaml` |
| Supporting configuration | `.gitignore`, `.eslintignore`, `.eslintrc`, `LICENSE` |
| Isolated documentation | `README.md` lines 1–132, 140–144, and 197–end; `API_and_tests.md` lines 1–114 |

`README.md` sections headed **Security** and **Security audit** were excluded. The **Verification** section of `API_and_tests.md` was also skipped; verification conclusions below come from executable source and checks, not that section.

Additional local dependency inputs were selected to inspect transport, configuration expansion, and encryption:

- `node_modules/nyks/http/request.js`
- `node_modules/nyks/stream/drain.js`
- `node_modules/nyks/string/replaceEnv.js`
- `node_modules/nyks/object/walk.js`
- `node_modules/nyks/object/jqdive.js`
- `node_modules/ssh-agent-crypt/index.js`
- JSON package manifests for locally resolved `nyks`, `ssh-agent-crypt`, `ssh2`, `yaml`, and `semver`
- Locally cached Go module `github.com/131/ssh-agent-crypt@v1.4.1`:
  - `sshagentcrypt.go`
  - `agent_unix.go`
  - `agent_windows.go`

Dependency inspection was targeted, not exhaustive. The lockfile was inspected through its header and parsed package metadata, including resolution URLs, integrity fields, and install-script markers.

### Threat model

This is a public authentication tool, not merely a trusted local helper. Relevant boundaries include:

- Project-controlled configuration versus operator-approved destinations.
- JWTs, inherited tokens, cached tokens, and SSH-agent signing operations.
- HTTP transport between external consumers and Vault.
- Cache confidentiality, integrity, session isolation, and token lifecycle.
- Dependencies and automation producing publicly installed packages and binaries.
- Long-lived SDK clients, including the pending separate `vvauth` integration.

The prototype API is evaluated as implemented: `Connect`, `LookupSelf`, and `Request`, with language-native constructors, errors, and return values. Missing compatibility aliases are not findings.

### Safe checks run

| Check | Result |
|---|---|
| Local Git commit, remote, and tracked working-tree status | Commit and remote matched the supplied context; tracked tree remained clean |
| Tool versions | Node `v22.22.2`; Go `go1.24.0 linux/amd64`, with `GOTOOLCHAIN=local`, `GOPROXY=off`, and `GOSUMDB=off` |
| `node --check` on the implementation, CLI, and test file | Passed |
| `gofmt -l` on explicitly selected Go files | No formatting discrepancies |
| ESLint on the three selected JavaScript files, using the installed executable and `--no-cache` | Passed |
| Parsed local lockfile inspection | 268 package entries; recorded resolution URLs were npm-registry URLs; resolved entries had integrity fields |
| In-memory Node probes, without constructors, filesystem access, agents, or transport | Confirmed unchanged trust after destination mutation, reuse of cache metadata missing expiry, and acceptance of a non-string login token |

An additional exploratory assertion predicting a `RangeError` for a cyclic macro did **not** hold. A follow-up probe showed that the expression returned a changed value. That experiment does not support a cyclic-expansion finding and is not counted as a passing security check.

### Checks not run

- **`node --test`, `npm test`, and `go test`:** The suites create temporary files, generate keys, launch SSH agents, and open loopback listeners. Some tests also invoke Go tooling. These operations do not meet this invocation’s read-only/no-network constraints.
- **`go vet` and Go builds:** They can create build-cache or temporary artifacts; no writable build environment was authorized.
- **Dependency installation, `npm audit`, `govulncheck`, and remote advisory lookups:** Installation would write files, and current advisory checks would require external information or network access.
- **Real Vault, SSH-agent, JWT, TLS, Windows, signing-server, or consumer integration tests:** They require resources outside the permitted review.
- **Publication, packaging, release, and artifact verification:** Not authorized and not performed.

Test source was reviewed as evidence of intended coverage, not as evidence that tests passed during this assessment.

## 3. Prioritized Findings

Severity reflects public distribution and plausible consumer use. A **verified observation** is supported by source or a safe local probe; it does not imply that an end-to-end exploit was executed.

### F1 — High: Credential-bearing requests permit plaintext HTTP

**Classification:** Verified observation.

**Evidence**

- `index.js:286–301` constructs the request from the configured address without requiring HTTPS.
- `index.js:293` attaches `X-Vault-Token`; `index.js:207–209` sends JWT authentication payloads.
- Local `node_modules/nyks/http/request.js:63` selects the HTTP transport unless the protocol is `https:`.
- `vault.go:55–65` constructs and sends requests, including token headers, without enforcing HTTPS.
- `vauth.go:251–256` sends JWT login data through that transport.

**Impact**

An approved address can still use `http://`. Destination approval does not provide confidentiality or authenticate the server. On an observable or attacker-controlled network path, bearer tokens and JWTs can be captured, and authentication responses can be altered.

The SSH flow also receives and signs challenges over this transport. This assessment does not establish a separate cross-protocol signature exploit, but plaintext transport weakens the authenticity of those challenges.

**Suggested fix**

Require HTTPS by default before any credential-bearing request. If development HTTP is necessary, expose an explicit insecure option and narrowly restrict automatic exceptions to loopback destinations. Add equivalent Node and Go tests proving that ordinary remote HTTP addresses are refused before sending credentials.

### F2 — Medium: Destination trust is a construction-time flag, not a binding to the current address

**Classification:** Verified observation; exploitability depends on consumer-controlled address mutation.

**Evidence**

- `index.js:84–88` records `_safe_vault` during construction.
- `index.js:99–101` checks only that boolean.
- `index.js:286–299` uses the current, mutable `VAULT_ADDR`.
- `vauth.go:139–142` records `unknownVault` during construction.
- `vauth.go:179–183` checks only that flag.
- `vault.go:36–65` uses the current, exported `VaultAddr`.
- An in-memory Node probe confirmed that changing the address does not invalidate the recorded trust decision.

**Impact**

An SDK consumer can initialize a client for an approved destination, subsequently assign an address from less-trusted input, and send a token or JWT to the new destination while retaining the old approval.

This is not an arbitrary remote bypass in the standalone CLI: it requires mutation by embedding code. It is nevertheless relevant to external integrations that reuse clients or switch destinations.

**Suggested fix**

Bind approval to an immutable normalized destination, or revalidate the actual destination on every request. Provide an explicit reconfiguration operation that recomputes trust and clears connection state. Add tests for destination mutation after construction and after token acquisition.

### F3 — Medium: Resource limits do not cover all response and connection paths

**Classification:** Verified observation.

**Evidence**

- `index.js:301–302` drains the complete HTTP response.
- Local `node_modules/nyks/stream/drain.js:12–26` accumulates chunks without a byte limit.
- `vault.go:70` uses unrestricted `io.ReadAll`.
- Local `node_modules/nyks/http/request.js:111–119` starts its deadline after the request emits `finish`, rather than before connection establishment.
- `vault.go:123–150` performs SSH-agent connection, listing, and signing without setting a connection deadline.
- Go dependency `agent_unix.go:11–12` uses `net.Dial`; `agent_windows.go:22–23` supplies no pipe timeout.

**Impact**

A malfunctioning or compromised approved endpoint can cause excessive memory consumption by returning a large body. HTTP response deadlines do not substitute for byte limits.

A stalled connection or SSH-agent exchange can also delay or block authentication beyond the intended response deadline. This matters especially for SDKs embedded in services or automation.

**Suggested fix**

Introduce configurable response-size limits, with small defaults for authentication responses. Bound connection establishment and agent exchanges as well as HTTP response reading. Where practical, provide cancellation or context support for SDK calls. Test oversized bodies and stalled connection/agent paths.

### F4 — Medium: npm dependency resolution is not reproducible from the assessed commit

**Classification:** Verified observation; supply-chain compromise is a conditional risk, not an observed incident.

**Evidence**

- `.gitignore:2` ignores `package-lock.json`; a local Git query confirmed that it is untracked.
- The local lockfile identifies version `1.1.1` at `package-lock.json:3,9`, whereas `package.json:3` identifies `1.1.2`.
- `package.json:15–29` permits dependency ranges.
- `.github/workflows/test.yml:18` and `.github/workflows/publish-npm.yml:23` use `npm install`.
- Local lock metadata records install scripts for `ssh2` and `cpu-features`.

**Impact**

A clean checkout cannot reproduce the local dependency graph from this commit. Separate CI runs can resolve different permitted versions, and installation executes dependency-provided code.

The ignored lockfile’s integrity values describe local resolutions; they are not a committed release baseline. This does not demonstrate a known vulnerable dependency, but it weakens reproducibility and the evidential connection between reviewed source and publication.

**Suggested fix**

Commit a current lockfile and use `npm ci` in test and publication workflows. Review dependency changes explicitly, including install scripts. Keep the distinction clear: a repository lockfile stabilizes CI, while public library consumers may still resolve dependency ranges differently.

### F5 — Medium: Release execution trusts mutable external references

**Classification:** Verified observation; exploitation requires compromise or alteration of a referenced upstream component.

**Evidence**

- Workflow actions use movable major-version references such as `actions/checkout@v4` and `actions/setup-go@v5`.
- `.github/workflows/release.yml:22–26` checks out executable helper code from `131/gh-actions` at `ref: v1`.
- `.github/workflows/release.yml:27–30` uses `goreleaser/goreleaser-action@v6` and a floating GoReleaser version range.
- `.goreleaser.yaml:18–19` executes the external signing helper.
- `.github/workflows/release.yml:31–33` supplies `GITHUB_TOKEN` and `SIGNING_SERVER` to the release process.

**Impact**

Release behavior can change without a change to this repository. Compromised helper or action code could alter public binaries or misuse release/signing capabilities.

Checksums detect corruption only relative to a trusted checksum source; they do not establish that a compromised release process produced trustworthy software.

**Suggested fix**

Pin actions and executable helper checkouts to reviewed commit hashes, and pin the release tool version. Update pins through reviewed changes. Minimize credential exposure and add independently verifiable build provenance or attestations.

### F6 — Low: Cached credentials are not cryptographically bound to their session filename

**Classification:** Verified observation; cross-session consequences are conditional.

**Evidence**

- `index.js:104–112` and `cache.go:25–36` encode the Vault/authentication configuration in a hashed filename.
- `index.js:132–135` and `cache.go:16–20` store no session identifier or destination in the encrypted payload.
- `index.js:119–120` and `cache.go:47–59` decrypt and accept the payload without verifying its association with the selected session.
- The encryption dependency authenticates its armor, not the caller’s cache filename.

**Impact**

Filename separation prevents accidental ordinary lookup collisions, but does not reject an intact encrypted cache copied into another session’s filename.

An actor able to replace cache files—or an incorrect restore operation—could substitute a credential from a different configuration. A later renewal or external consumer request might then send that credential to an unintended destination.

This requires cache replacement access and a decryptable copied entry; it is not a demonstrated remote attack or a break of ciphertext authentication.

**Suggested fix**

Include a versioned session identifier inside the authenticated payload and compare it with the current session before reuse. Add transplantation tests between different destinations and authentication configurations.

### F7 — Low: Node cache and login response validation is incomplete

**Classification:** Verified observation.

**Evidence**

- `index.js:119–120` accepts any JSON returned by decryption.
- `index.js:175–184` uses cache fields without enforcing a schema.
- `cache.go:55–59` checks JSON decoding and a nonempty token, but does not distinguish omitted expiry from explicitly unlimited expiry.
- `index.js:229–231,280–282` checks token truthiness, not that `client_token` is a string.
- `vault.go:94–103` is stricter about token type and explicit lease presence.
- In-memory Node probes confirmed reuse of cache metadata with omitted expiry and acceptance of an object-valued login token.

**Impact**

Malformed but authenticated cache data can bypass intended expiry interpretation. Node may return a value that violates its documented token contract, causing downstream failures or inconsistent behavior between implementations.

Normal writers produce the expected fields, so this is principally a malformed-data, migration, or consumer-boundary robustness issue rather than an ordinary unauthenticated cache-tampering attack.

**Suggested fix**

Validate a versioned cache schema, including token type, required expiry semantics, lease range, and renewable type. Reject malformed cache entries as misses. Require a nonempty string `client_token` in Node login and renewal responses, and add shared malformed-input fixtures.

## 4. Strengths

- **Small, coherent public API.** Both implementations expose the intended client methods without a broad command-dispatch surface.
- **Restrained CLI behavior.** Unknown arguments are rejected before credential output; help and version paths avoid configuration loading.
- **Useful project-address protection.** Unknown project-selected Vault addresses are refused before HTTP requests under normal construction and unchanged configuration.
- **Redirect protection by default.** Node does not enable redirect following; Go’s default client returns redirects without following them.
- **Encrypted, authenticated cache writes.** The inspected v3 dependency uses random salt and IV, separate encryption/MAC derivation, and constant-time authentication checks before decryption.
- **Private and replace-based persistence.** Cache writers request restrictive POSIX modes and use distinct temporary files followed by replacement.
- **Nonfatal persistence failure.** Cache errors do not discard an otherwise acquired token, and diagnostics avoid printing token contents.
- **Deliberate inherited-token handling.** Inherited tokens are returned without lookup, renewal, or persistence unless fresh authentication is requested.
- **Controlled renewal fallback.** Renewal failures trigger reauthentication for 400/403 responses rather than indiscriminately generating new tokens after server failures.
- **Substantial test intent.** Tests cover lifecycle thresholds, cache disabling, plaintext-cache rejection, destination refusal, argument handling, response validation, and diagnostic secrecy.
- **Release safeguards are present.** Test/publication permissions are restricted, the binary release job names a production environment, and release configuration includes checksums and a Windows signing hook.

These are source observations. Runtime success, Windows signing validity, and production-environment enforcement were not verified.

## 5. Limitations

- No test suite, real authentication flow, or distributed artifact was executed or validated.
- Current dependency vulnerability status is unknown. Versions and integrity metadata are not a substitute for advisory analysis.
- The local npm dependency tree and ignored lockfile are supplemental working-tree inputs, not committed dependency provenance.
- Cryptographic inspection was targeted; it is not a formal review of `ssh-agent-crypt`. Its decryptors also accept legacy formats, which were not independently exercised.
- POSIX mode arguments do not establish equivalent Windows ACL protection.
- Repository settings such as tag protection, environment approvals, npm trusted-publisher policy, and signing-server controls are unavailable from source alone.
- Go’s exported custom `HTTPClient` can change redirect, timeout, and TLS behavior. Consumers must preserve the intended security properties.
- `Connect(false)` is not an online token-validity guarantee. Cache reuse deliberately skips revocation checks, and an already connected instance returns its token without re-evaluating expiry. Consumers needing current validity must use `LookupSelf` or an explicitly designed lifecycle policy. Vault remains responsible for enforcing expiry and revocation.
- SSH authentication signs server-provided nonces and tries agent identities. The Vault plugin protocol and server-side challenge protections were outside scope.
- Cache-key and armor compatibility have source-level support, but the inspected tests do not establish comprehensive bidirectional Node/Go interoperability across versions, configurations, and real Windows transports.
- The pending `vvauth` consumer was not read. Its destination handling, token lifecycle, cancellation, concurrency, and logging behavior require separate integration verification.
- Independent npm, Go-tag, and binary publication can partially succeed. This assessment does not establish coordinated channel consistency or validate the proposed release metadata.
- Scores are qualitative judgments of this snapshot, not certifications or probabilities.

## 6. Scores

| Category | Score | Justification |
|---|---:|---|
| **Coolness** | **17/20** | A compact cross-language Vault client, raw-token CLI, SSH-agent authentication, and shared encrypted caching make a useful and distinctive integration tool. |
| **Robustness** | **13/20** | Clear lifecycle logic and extensive test intent are offset by incomplete validation, resource bounds, long-lived-client behavior, and unverified runtime/platform interoperability. |
| **Safety** | **13/20** | Cache authentication, restrained logging, destination approval, and redirect protection are meaningful safeguards. Plaintext credential transport, mutable destination trust, and release/dependency provenance gaps remain material concerns for public adoption. |

**Overall assessment:** The implementation has a focused design and meaningful security controls, but it should not be treated as hardened solely because authentication and cache reuse work in ordinary cases. HTTPS enforcement is the highest-priority correction, followed by binding trust to the actual request destination, bounding resource use, and strengthening dependency and release provenance.