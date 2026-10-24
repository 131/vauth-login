# Independent Security Assessment: vauth-login

- **Assessed commit:** `51039540a00c58a577605b241823f7d19e6f2947` — release `v1.1.2`
- **Assessment date:** 2026-10-24
- **Model:** GPT-6.1-sol, acting as Codex
- **Method:** Independent, source-only review of the current working tree, selected locally installed dependency source, and safe read-only checks.

**Provenance:** This assessment was derived independently from implementation code, tests, manifests, and release workflows. Neither `SECURITY_AUDIT_fable-5.1.md` nor `SECURITY_AUDIT_gpt-6.1-sol.md` was read. All other `SECURITY_AUDIT*.md` contents, documentation assessment sections, historical assessments and assessment-related commit messages, and Markdown dependency advisories were excluded. No comparison, consolidation, additional review session, network request, publication, or repository modification was performed.

## 1. Scope and Method

### Project and threat context

The supplied project context identifies the canonical upstream as the public ISC-licensed repository `https://github.com/131/vauth-login`, distributed through:

- The npm package `vauth-login`.
- The Go module `github.com/131/vauth-login`.
- GitHub releases containing Linux amd64 and signed Windows amd64 binaries.

The local Git remote and manifests agree with that repository identity. Publication status, installed release artifacts, and signature validity were accepted as supplied context rather than independently verified online.

This review considers external users and integrators, not just trusted local development. Relevant trust boundaries include:

1. Project configuration versus user-approved Vault destinations.
2. Credentials versus network transport and error output.
3. Encrypted cache files versus filesystem access and SSH-agent access.
4. Public SDK configuration versus security defaults.
5. Maintainer source versus dependencies, CI actions, signing infrastructure, and distributed artifacts.

A clean tracked working-tree status was observed. Importantly, the local `package-lock.json` is ignored and is not tracked.

### Explicit input inventory

Filename inventory preceded implementation reading. Selected inputs were:

**Node implementation and tests**

- `index.js`
- `bin/vauth-login.js`
- `test/token-cache.js` — test names, setup, and selected authentication, cache, configuration, transport, and CLI test bodies.

**Go implementation and tests**

- `vauth.go`
- `vault.go`
- `cache.go`
- `rc.go`
- `humandiff.go`
- `cmd/vauth-login/main.go`
- `vauth_test.go` — setup and selected cache, interoperability, and destination-trust tests.
- `auth_api_test.go`
- `cmd/vauth-login/main_test.go`

**Manifests, packaging, and automation**

- `package.json`
- `package-lock.json`
- `go.mod`
- `go.sum`
- `.github/workflows/test.yml`
- `.github/workflows/publish-npm.yml`
- `.github/workflows/release.yml`
- `.goreleaser.yaml`
- `.gitignore`
- `.eslintrc`
- `.eslintignore`
- `LICENSE`

**Safely isolated project documentation**

Heading line numbers were listed before printing selected ranges:

- `README.md`: lines **1–132**, **140–144**, and **181–end**. The `Security` and `Security audit` sections were excluded.
- `API_and_tests.md`: lines **1–132**, after heading inspection identified API, CLI-contract, and verification sections rather than an assessment section.

Documentation supplied API context; findings below are grounded in code and checks.

**Selected local dependency source**

- `node_modules/ssh-agent-crypt/index.js`
- `node_modules/ssh-agent-crypt/package.json`
- `node_modules/nyks/package.json`
- `node_modules/nyks/http/request.js`
- `node_modules/nyks/stream/drain.js`
- `node_modules/nyks/string/replaceEnv.js`
- `node_modules/nyks/object/walk.js`
- `node_modules/nyks/object/jqdive.js`
- `node_modules/ssh2/package.json`
- `node_modules/yaml/package.json`
- `node_modules/yaml/dist/errors.js`
- Cached Go dependency `github.com/131/ssh-agent-crypt@v1.4.1`:
  - `sshagentcrypt.go`
  - `agent_unix.go`
  - `agent_windows.go`
- Selected redirect-handling source in the installed Go standard library: `/usr/local/go/src/net/http/client.go`.

Applicable workspace instructions and safely selected workspace documentation were also read. No matching project namespace map was identified; the explicit review scope and applicable workspace rules were retained.

### Checks performed

| Check | Result |
|---|---|
| Commit, remote, tracked status, and lockfile tracking metadata | Expected commit and repository identity; no tracked changes; lockfile untracked/ignored |
| `node --check index.js` | Passed |
| `node --check bin/vauth-login.js` | Passed |
| `node --check test/token-cache.js` | Passed |
| `gofmt -l` on the nine selected Go files | No formatting discrepancies |
| JSON parsing and summary of the complete local lockfile | Parsed successfully; 268 package entries; all 267 resolved URLs use HTTPS |
| In-memory malformed YAML check, with synthetic sensitive-field text | Confirmed that the parser error message includes that text |
| In-memory recursive YAML alias passed through the Node configuration walker | Confirmed `RangeError` |
| In-memory macro replacement checks | Initial self-reference assertion failed; follow-up confirmed stack exhaustion for a replacement containing `$&` |

Synthetic checks used an empty process environment apart from `PATH`, did not instantiate a configured authentication client, and printed outcomes rather than credential material.

Available runtimes were Node **22.22.2** and Go **1.24.0**. CI selects Node **24.x** and obtains its Go version from `go.mod`.

### Checks not performed

- **`node --test`, `npm test`, and Go test suites:** Their setup writes temporary files, generates keys, starts SSH-agent processes, and opens loopback listeners. Those operations are incompatible with this invocation’s strict read-only constraints.
- **`go vet`, Go compilation, race testing, and Windows cross-builds:** Go tooling normally writes build caches and temporary work files. No writable execution allowance was available.
- **ESLint:** Not run; verification was limited to syntax and formatting rather than executing the installed lint-plugin chain.
- **Dependency installation, `npm audit`, vulnerability-database queries, and online module verification:** Prohibited network access and installation writes.
- **Live Vault, real SSH-agent/Pageant, actual token-cache, release-binary, and signing-server checks:** Outside authorization and potentially involving real credentials or external services.

The existing tests were inspected, not represented as passing.

## 2. Prioritized Findings

Severity describes plausible impact under the stated prerequisites. A verified observation may be established by source inspection; it does not necessarily mean an end-to-end exploit was executed.

### F1. Remote plaintext HTTP is permitted for authentication and token-bearing requests

**Severity: High — Verified observation**

**Evidence**

- `index.js:304–314` forwards the configured URL protocol and attaches `X-Vault-Token`.
- `index.js:213–215` sends the JWT authentication payload.
- `node_modules/nyks/http/request.js:63` selects HTTP unless the protocol is HTTPS.
- `vault.go:58–68` constructs and sends the configured URL without enforcing HTTPS.
- `vauth.go:257–262` sends JWT credentials through that transport.

**Impact**

A user-approved destination can still use `http://` on a remote network. JWTs, issued tokens, renewal headers, and SSH authentication exchanges then lack transport confidentiality and server authentication.

The destination allowlist prevents an unapproved project endpoint from initiating login or renewal, but does not make an approved plaintext endpoint safe. An on-path attacker could capture bearer credentials or manipulate responses.

**Suggested fix**

Require HTTPS by default for non-loopback destinations. Permit HTTP only through an explicit insecure-development option, preferably restricted to literal loopback addresses. Validate the scheme before credentials or agent signatures are produced, and add equivalent Node and Go tests.

### F2. Privileged release steps execute dependencies selected by mutable references

**Severity: High — Verified observation**

**Evidence**

- `.github/workflows/release.yml:7–8` grants release-content write permission.
- `.github/workflows/release.yml:22–26` checks out `131/gh-actions` at mutable ref `v1`.
- `.goreleaser.yaml:18–19` executes that checkout’s Windows signing helper.
- `.github/workflows/release.yml:27–33` uses `goreleaser-action@v6`, a floating GoReleaser version range, and exposes release/signing credentials.
- Checkout and setup actions use version tags throughout the workflows.

**Impact**

The distributed binaries depend on code outside the reviewed commit. A compromised or moved action/helper reference could alter artifacts or execute code in a job with release authority and access to signing infrastructure.

This is a supply-chain exposure, not evidence that the upstream helper, actions, or signing service are compromised.

**Suggested fix**

Pin actions and the signing-helper checkout to reviewed full commit hashes; pin the GoReleaser version. Update those pins through reviewed changes. Minimize credential exposure to the steps that require it, verify signatures and checksums after signing, and generate verifiable artifact provenance.

### F3. npm publication is not based on a tracked, reproducible dependency resolution

**Severity: Medium — Verified observation**

**Evidence**

- `.gitignore:2` ignores `package-lock.json`; `git ls-files -- package-lock.json` returned no tracked entry.
- `package.json:15–29` specifies dependency ranges.
- `.github/workflows/publish-npm.yml:23` and `.github/workflows/test.yml:18` run `npm install`, not `npm ci`.
- The local lockfile identifies root version `1.1.1` at `package-lock.json:3,9`, while `package.json:3` is `1.1.2`.
- `.github/workflows/publish-npm.yml:23–28` tests and publishes without an explicit tag/package-version consistency check.

**Impact**

A clean CI checkout resolves dependencies afresh. The dependencies tested during publication can differ from the local tree or earlier successful CI runs. The local lockfile’s integrity hashes therefore do not establish the dependency graph used by the release workflow.

Installation also executes dependency lifecycle scripts: the inspected lockfile marks `ssh2` and `cpu-features` as having installation scripts.

**Suggested fix**

Track a synchronized lockfile and use `npm ci` in CI and publication. Assert consistency between the release tag, npm version, and Go release metadata. Review lifecycle-script requirements and reduce unused development dependencies.

A tracked lockfile improves publisher reproducibility; it does not freeze dependency resolution for every downstream npm consumer.

### F4. Node configuration parse errors can disclose credential text

**Severity: Medium — Verified observation**

**Evidence**

- `index.js:40–42` parses raw configuration with default YAML error behavior.
- `bin/vauth-login.js:25–26` prints the resulting error message.
- `node_modules/yaml/dist/errors.js:22–55` appends source-line context to parser errors.
- An in-memory malformed YAML check confirmed inclusion of a synthetic marker placed in a JWT field.

**Impact**

Malformed configuration containing a literal JWT or another sensitive value can expose that value on stderr. CI logs and diagnostic captures may then retain credentials despite the normal HTTP-error path avoiding response-body disclosure.

No real configuration or credential was read to establish this finding.

**Suggested fix**

Disable parser source snippets, or catch and replace parser errors with a sanitized filename, line/column, and error category. Apply the same redaction policy to configuration-derived URL and validation errors. Add regression tests asserting that sensitive-field markers never appear in CLI errors.

### F5. A custom Go HTTP client can silently remove redirect protection and deadlines

**Severity: Medium — Verified observation**

**Evidence**

- `vauth.go:45` exposes `HTTPClient`.
- `vault.go:83–92` returns a supplied client unchanged, bypassing the safe default’s redirect rejection and 60-second timeout.
- `vault.go:65–68` sends `X-Vault-Token` through that client.
- Installed Go source, `net/http/client.go:803–813`, does not classify `X-Vault-Token` among headers restricted during cross-origin redirects; `818–822` permits redirects by default.

**Impact**

An external integrator supplying an ordinary `http.Client` to configure transport behavior can inadvertently enable cross-origin forwarding of `X-Vault-Token`. A zero-timeout client also permits indefinite blocking.

The built-in default remains protected. Existing redirect tests inspect that default, not a replacement client.

**Suggested fix**

Clone supplied clients and enforce redirect rejection and a bounded timeout independently of their transport customization. Prefer exposing transport/TLS configuration without requiring replacement of the entire security policy. Add custom-client redirect and timeout tests.

### F6. SSH login signs server-controlled bytes without a protocol-specific envelope

**Severity: Medium — Hypothesis concerning cross-protocol abuse**

**Evidence**

- `index.js:257–264` accepts any nonempty nonce string, signs its raw bytes, and sends the signature to the server.
- `vault.go:136–162` performs the equivalent operation.
- Both implementations enumerate agent identities rather than requiring a dedicated login identity.

**Impact**

A compromised approved Vault endpoint—or an on-path attacker when HTTP is used—can request signatures over chosen strings. Whether these signatures can be reused for another protocol depends on byte encoding, signature algorithms, agent restrictions, and the target protocol.

Cross-protocol exploitation was not demonstrated. The verified underlying behavior is a raw signing oracle behind the destination trust boundary.

**Suggested fix**

Coordinate with the server/plugin to define a bounded, domain-separated challenge including protocol identity, audience, and expiry. Require a dedicated authentication identity where practical. Existing protocol compatibility may constrain immediate changes; in that case, document the server’s signing authority and use appropriately restricted keys.

### F7. HTTP response bodies are buffered without a size limit

**Severity: Medium — Verified observation**

**Evidence**

- `index.js:314–315` drains the complete response.
- `node_modules/nyks/stream/drain.js:12–26` collects all chunks and concatenates them.
- `vault.go:72–78` uses unrestricted `io.ReadAll`.

**Impact**

A faulty or hostile configured endpoint can cause substantial memory consumption or process termination with a large response. Request deadlines do not bound the number of bytes received before the deadline.

The exposure includes authentication responses and public SDK requests.

**Suggested fix**

Set a conservative maximum response size, count streamed bytes, and abort once the limit is exceeded. Reject oversized declared lengths early without relying on `Content-Length` alone. Apply the limit to error bodies as well as successful responses.

### F8. Parsed Go authentication configuration retains a stale cache identity after mutation

**Severity: Medium — Verified observation**

**Evidence**

- `rc.go:17–28` exposes mutable authentication fields while retaining private `authKey`.
- `rc.go:33–35` returns the saved key whenever it is nonempty.
- `rc.go:313–326` saves that key during parsing.
- `cache.go:25–30` uses it to select the token-cache filename.
- `vauth.go:255–262` uses the current mutable authentication fields for login.

**Impact**

An integrator can parse configuration, then modify its role, JWT, or authentication path before using a new client. Cache selection still reflects the original parsed configuration, while a fresh login would use the modified values.

An existing cache entry can consequently be reused under an authentication context the caller did not intend, including a token associated with a different role. This concerns SDK mutation; unchanged CLI configuration does not exhibit it.

**Suggested fix**

Make parsed authentication configuration immutable, or recompute cache identity from the effective configuration whenever fields change. Preserve any ordering metadata separately from cached scalar values. Test mutation of parsed configuration and Node/Go parity explicitly.

### F9. Node configuration traversal and macro expansion lack recursion safeguards

**Severity: Low — Verified observation**

**Evidence**

- `index.js:40–42` passes parsed YAML through the dependency walker.
- `node_modules/nyks/object/walk.js:8–10` recursively traverses objects without cycle detection.
- A recursive YAML alias in an authentication subtree caused `RangeError` in an in-memory check.
- `node_modules/nyks/string/replaceEnv.js:20–24` uses replacement-string semantics and unbounded recursion.
- A synthetic environment replacement containing `$&` caused stack exhaustion.
- By comparison, Go macro expansion is bounded to 16 iterations at `rc.go:134–153`.

**Impact**

Crafted or unusual project configuration can crash Node initialization before destination checks. Replacement-string metacharacters can also transform values differently from the Go implementation.

This is primarily local denial of service and interoperability risk, not a demonstrated credential-exfiltration mechanism.

**Suggested fix**

Use cycle-aware traversal with depth and size limits. Bound macro expansion, detect non-progress, and use a replacement callback so environment values are inserted literally. Add shared tests for aliases, replacement metacharacters, unresolved variables, and recursion limits.

## 3. Strengths

- **Meaningful project-destination protection.** Node `index.js:82–105` and Go `vauth.go:139–142,178–183` refuse fresh login and renewal to unknown project-selected Vault addresses.
- **Encrypted-only normal persistence.** Cache writers encrypt before writing payloads. They use restrictive POSIX creation modes, temporary files, and rename-based replacement. Cache failures produce a generic warning rather than revealing tokens or preventing successful authentication.
- **Authenticated cache encryption.** The inspected `ssh-agent-crypt` implementations use random salt/IV material, separate encryption and MAC keys, and authenticate ciphertext before decryption. The v3 format includes its header in authentication and uses a dedicated SSHSIG namespace.
- **Deliberate inherited-token handling.** Inherited tokens are returned without online lookup, renewal, or persistence. This avoids unintended credential transmission by ordinary CLI login.
- **Safe default redirects and bounded HTTP duration.** Both default transports avoid following redirects. Go has a 60-second client timeout; the Node dependency maintains a request deadline through response consumption.
- **Strict standalone CLIs.** Unknown arguments are rejected before loading authentication state. Help and version paths avoid configuration loading, and token output is separated from status output.
- **Response validation.** Authentication and lookup handling validate required token/lease or TTL fields rather than blindly accepting missing metadata.
- **Substantial regression-test intent.** Inspected tests cover cache corruption, plaintext rejection, offline reuse, renewal thresholds, server failures, output secrecy, destination trust, and CLI behavior.
- **Interoperability is designed explicitly.** Both implementations use matching cache fields and authentication-based filename derivation. Go tests include Node-shaped hash vectors; Node tests include encrypted-format CLI interoperability.
- **Public distribution has useful foundations.** Explicit npm file selection, Go module checksums, production release-environment selection, Windows signing hooks, and release checksums provide a basis for stronger release assurance.

## 4. Limitations and Security Boundaries

- This is not a complete dependency vulnerability audit. No current advisory database, npm registry, Go proxy, or upstream service was queried.
- Local dependency source and the ignored lockfile describe this checkout, not necessarily the dependencies used to publish `v1.1.2`.
- Tests were inspected selectively and were not executed. Dynamic authentication correctness, race behavior, Windows behavior, and end-to-end Node/Go encrypted-cache exchange remain unverified in this invocation.
- Actual release binaries, npm tarballs, Authenticode signatures, signing-helper implementation, signing service, and artifact provenance were not inspected.
- Repository-host settings are unavailable: tag protection, environment approval rules, trusted npm publishing configuration, and maintainer account protections cannot be established from workflow YAML alone.
- Offline cache reuse deliberately does not establish current server-side validity. Revoked cached tokens can be returned until a later online operation rejects them. An already-connected client also returns its remembered token without rechecking expiry. Integrators requiring validation should use `LookupSelf` or fresh authentication.
- Cache encryption protects stored payloads, not against a process able to use the same unlocked agent or read returned tokens from application memory/stdout. Identity selectors can also designate local key files in the encryption dependency.
- Cache context is principally enforced by filename selection; the cached plaintext does not embed the Vault/authentication context. Cross-file transplantation and rollback resistance are not established cryptographic guarantees.
- POSIX creation modes do not establish secure permissions on pre-existing directories or prove equivalent Windows ACL protection.
- Home configuration, explicit `VAUTHRC`, and environment variables are trusted inputs. Public SDK request methods expose lower-level capability and do not themselves apply the project-login allowlist.
- No conclusion here establishes a remotely exploitable default-install compromise or a compromised release. The most consequential findings depend on insecure transport configuration, compromised release dependencies, or SDK integration choices.

## 5. Scores

These scores are qualitative engineering judgments, not certifications.

| Dimension | Score | Justification |
|---|---:|---|
| **Coolness** | **17/20** | A compact dual-language Vault login tool with agent-backed encrypted caching, practical CLIs, and intentional interoperability is useful and distinctive. |
| **Robustness** | **13/20** | Cache failure handling, response validation, and extensive test intent are strong. Configuration recursion, unbounded responses, mutable SDK state, and incomplete reproducibility weaken reliability. |
| **Safety** | **12/20** | Destination trust checks, ciphertext-only persistence, sanitized HTTP errors, and safe default redirects are substantial protections. Remote HTTP, fragile SDK transport policy, and mutable privileged release dependencies remain important gaps for external adoption. |

**Overall:** The project has a credible security-conscious foundation. The highest-value next steps are enforcing secure transport, pinning the privileged release chain, making npm CI resolution reproducible, sanitizing configuration failures, and preserving security policy when external users customize the SDKs.