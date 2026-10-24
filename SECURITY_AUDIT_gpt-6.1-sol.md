# Security audit — Codex (OpenAI GPT 6.1-sol)

**Review provenance:** This completed independent assessment covers the same
functional source as commit `b7fba0c` (source hashes verified). It ran before the
later prompt explicitly announced the public/ISC distribution context. Subsequent
public-context attempts, including a second pass with Claude's file present but
excluded from reading, were blocked by the service without a final report.
The completed assessment is retained unchanged in substance and scores; it is
not presented as the outcome of those blocked attempts. No Claude findings or
scores were supplied to this completed review.

**Assessment date:** 24 October 2026
**Target:** Current working tree of `github.com/131/vauth-login`
**Assessment type:** Independent, source-based defensive review

## Executive summary

The repository provides a focused Vault authentication client with useful protections: encrypted token caching, project-address allowlisting, restrained error logging, and redirect rejection.

The main concerns are:

1. Credentials can be transmitted over plaintext HTTP.
2. Go configuration serialization bypasses YAML alias-expansion safeguards.
3. HTTP response bodies have no size limit.
4. Release inputs are not fully immutable or reproducible.

These are **verified source-level findings**, not demonstrated exploits. Their severity depends on the prerequisites described below. A separate connection-timeout concern remains a hypothesis.

## Scope and method

Filenames were inventoried before selecting inputs. Reviewed inputs included:

- Go implementation: `vauth.go`, `vault.go`, `cache.go`, `rc.go`, `humandiff.go`, and the Go CLI.
- Node implementation: `index.js` and `bin/vauth-login.js`.
- Existing Go and Node tests.
- `go.mod`, selected `go.sum` entries, `package.json`, lint configuration, GitHub workflows, and GoReleaser configuration.
- Relevant source from local dependency caches, principally `ssh-agent-crypt`, `nyks`, and `yaml.v3`.
- Non-audit documentation sections filtered **before output**.

No uncommitted tracked changes were present when checked. Assessment used working-tree files rather than historical versions.

`SECURITY_AUDIT*` documents, previous advisories, task handoffs, prior findings and scores, and Git history were excluded from content inputs. `REVIEW_SCOPE.json` was not read. No additional review sessions, comparison, or consolidation were performed.

Applicable workspace instructions were consulted through filtered inputs. No project-local instruction file was found in the repository inventory; the external navigation instructions did not establish a matching project-specific map.

## Prioritized findings

### F1 — High, conditional: Plaintext HTTP is accepted for credential-bearing requests

**Status:** Verified from source.

**Evidence**

- `vault.go:43–44` constructs the API URL directly from `VaultAddr`.
- `vault.go:58–68` creates and sends requests without requiring HTTPS; tokens are placed in `X-Vault-Token`.
- `vauth.go:257–262` sends JWT authentication material through this transport.
- `index.js:300–314` preserves the configured URL protocol and attaches tokens and authentication payloads.
- `node_modules/nyks/http/request.js:63` selects HTTP unless the protocol is `https:`.

**Impact and prerequisites**

If an operator trusts or configures a non-loopback HTTP Vault address, JWTs and Vault tokens cross the network without transport confidentiality or server authentication. A network observer or intermediary could obtain credential material or alter authentication responses.

The address allowlist limits *which address* a project may select; it does not establish a secure transport. This finding does not imply exposure when a correctly validated HTTPS endpoint is used.

**Suggested fix**

Require HTTPS for credential-bearing operations. If local development needs HTTP, provide an explicit insecure-mode opt-in, preferably restricted to loopback addresses. Validate URL scheme and authority centrally in both implementations, and document the exception clearly.

---

### F2 — Medium: Go cache-key serialization bypasses YAML alias safeguards

**Status:** Verified source-level defect; runtime failure was not demonstrated.

**Evidence**

- `rc.go:286–310` parses configuration into a raw `yaml.Node`, filters top-level fields, and decodes recognized configuration.
- `rc.go:313–324` subsequently serializes the original `ssh_auth` and `jwt_auth` subtrees.
- `rc.go:170–197` recursively traverses mappings, sequences, and aliases. In particular, `rc.go:173–175` follows `node.Alias` without cycle detection or an expansion budget.
- The cached `yaml.v3` decoder has alias protections in `.review-go-modcache/gopkg.in/yaml.v3@v3.0.1/decode.go:484–500` and `533–542`.
- Unknown struct fields are skipped by that decoder at `decode.go:921–945`, while the repository’s later serializer still traverses them.

**Impact and prerequisites**

A project-controlled configuration can contain alias structures in authentication-subtree fields that typed decoding ignores but cache-key serialization processes. The custom traversal can expand repeated aliases excessively or recurse through cycles, exhausting memory or stack space.

Configuration parsing happens before project-selected Vault trust is evaluated (`vauth.go:128–141`). Consequently, the address allowlist does not protect this parsing boundary.

This is a local availability issue affecting users or automation that invoke the Go client in an untrusted checkout—not evidence of credential disclosure.

**Suggested fix**

Validate the complete authentication subtree before serialization. Add cycle detection, nesting limits, alias-expansion limits, and an output-size budget. Prefer canonicalizing a validated representation rather than recursively rendering arbitrary raw YAML nodes. Preserve Node/Go cache-key compatibility deliberately when changing this logic.

---

### F3 — Medium: HTTP response bodies are buffered without a size limit

**Status:** Verified from source.

**Evidence**

- `vault.go:72–78` calls `io.ReadAll(res.Body)` before checking the expected status.
- `index.js:314–317` drains the complete response before checking status.
- `node_modules/nyks/stream/drain.js:12–26` retains every received chunk and concatenates the complete body.

**Impact and prerequisites**

A compromised trusted endpoint, malfunctioning proxy, or plaintext intermediary under F1 can return an oversized response and exhaust client memory. Error responses are affected as well as successful authentication responses.

The existing timeouts limit duration in covered phases, but do not bound bytes received within that period. The risk is more consequential when the SDK runs inside a long-lived service or shared automation worker.

**Suggested fix**

Introduce a conservative configurable response-size limit suitable for authentication metadata. Enforce it during streaming, abort the request when exceeded, and return a sanitized error. Keep error-body retention bounded too. Apply equivalent limits in both implementations.

---

### F4 — Medium: Release inputs are mutable and npm dependency resolution is not locked

**Status:** Verified configuration weakness; no compromised dependency or publisher was identified.

**Evidence**

- `package.json:15–29` uses dependency ranges; the repository inventory contains no tracked npm lockfile.
- `.github/workflows/publish-npm.yml:23–28` resolves dependencies with `npm install`, then publishes.
- `.github/workflows/test.yml:18–20` independently resolves npm dependencies.
- `.github/workflows/release.yml:22–30` checks out signing support at mutable `ref: v1`, uses a major-version action reference, and selects GoReleaser through a version range.
- `.goreleaser.yaml:18–19` executes the checked-out signing helper during release.
- `.github/workflows/release.yml:31–33` supplies release credentials and signing configuration to the release step.

**Impact and prerequisites**

The same repository revision can resolve different npm dependency trees or release tooling over time. A faulty or compromised upstream update could therefore influence package publication or binary production without a corresponding source change.

Tests provide an important gate, but run after dependencies have been resolved and do not establish artifact identity. This is an integrity and reproducibility weakness, not a claim that the configured vendors are untrusted.

**Suggested fix**

Commit an npm lockfile and use `npm ci` for CI and publication. Pin actions and signing-support code to reviewed immutable commits, and pin the release-tool version. Maintain those pins through controlled updates. Where supported, add artifact provenance and an explicit protected publication environment.

## Hypothesis requiring further verification

### H1 — Node’s configured timeout may not cover connection establishment

`index.js:309–313` delegates its timeout to `nyks`. In the installed dependency, the timer starts only on the request’s `finish` event (`node_modules/nyks/http/request.js:111–119`).

A DNS lookup, connection attempt, or TLS handshake that stalls before that event may not be governed by the configured 60-second deadline. The existing test at `test/token-cache.js:850–857` covers a stalled **response body**, not connection establishment.

**Potential impact:** Authentication calls may remain pending longer than intended.

**Recommendation:** Enforce an absolute deadline starting before connection establishment and extending through response consumption.

**Confidence:** Medium. The timer-placement gap is visible in source; exact runtime behavior across connection phases was not verified here.

## Strengths

- **Project-address trust boundary:** Unknown project-selected Vaults are rejected before fresh login or renewal (`vauth.go:139–142,178–183`; `index.js:82–105`).
- **Encrypted, authenticated caching:** The reviewed v3 crypto implementations authenticate ciphertext and headers, use random salt/IV material, and compare authentication tags in constant time.
- **Restrictive cache writes:** Cache directories and files request private permissions; writes use temporary files and rename operations (`cache.go:72–110`; `index.js:128–149`).
- **Reduced diagnostic leakage:** HTTP errors report status without routinely printing response bodies; cache failures use generic messages.
- **Redirect resistance:** The default Go client refuses redirects (`vault.go:83–86`); the Node request configuration does not enable dependency redirect-following.
- **Focused tests:** Existing suites cover cache lifecycle, inherited-token handling, trust decisions, malformed responses, output behavior, and renewal failures.

## Local checks

Checks used sanitized environments, temporary homes, offline Go dependency resolution, and build outputs under `/tmp`.

| Check | Result |
|---|---|
| Go vet, project packages | Passed |
| Linux Go CLI build | Passed |
| Windows amd64 cross-build | Passed |
| Go formatting lint, selected source/tests | Passed |
| ESLint, project JavaScript implementation/tests | Passed |
| Existing Go informational CLI test | Passed |
| Full existing Go suite | Blocked: temporary SSH-agent and loopback sockets are prohibited |
| Full existing Node suite | Exited before completing tests; suite setup requires prohibited sockets |

The blocked suites are **not** reported as application regressions or successful validation.

Not run: live Vault authentication, real-agent validation, native Windows execution, signing, publication, deployment, external vulnerability-database checks, or additional adversarial tests. No exploitation proofs, attack payloads, or new tests were created. No repository source files were changed.

## Limitations

- Source verification establishes the described code paths, not exploitation in a deployed environment.
- Real endpoint configuration, Vault policies, runner protections, npm publisher settings, and signing-service behavior were outside scope.
- Native Windows behavior was not executed.
- Dependency inspection was selective; no exhaustive dependency vulnerability assessment or CVE clearance is claimed.
- Full runtime verification was constrained by sandbox socket restrictions.

## Scores

These are qualitative scores for the reviewed snapshot, not standardized security ratings.

| Dimension | Score | Justification |
|---|---:|---|
| **Coolness** | **17/20** | Focused dual-language tooling, interoperable encrypted caching, and convenient cross-platform CLI distribution. |
| **Robustness** | **13/20** | Strong lifecycle tests and successful static/build checks, offset by unchecked YAML traversal, unbounded responses, and uncertain connection-deadline coverage. |
| **Safety** | **12/20** | Good caching, allowlisting, redirect, and logging safeguards; plaintext transport remains permitted, and publication inputs lack complete immutability. |

**Recommended order:** Enforce secure transport, constrain YAML traversal, bound response sizes, then harden release reproducibility and verify connection deadlines.


## Release verification (coordinator, separate from the assessment)

The reviewed functional source matches commit `b7fba0c`. Independent review
sandboxes restricted network/listening sockets. The coordinator separately
passed all 80 Node tests on Node 24, ESLint, `go vet ./...`, `go test -race ./...`,
and a Windows cross-build. Node/Go CLI outputs matched byte-for-byte for nine
normal, informational, and invalid-argument cases. These checks do not change
the assessment's findings or scores. Release version markers are subsequently
aligned by `ppackage version patch`; the assessments precede that metadata-only
versioning step.
