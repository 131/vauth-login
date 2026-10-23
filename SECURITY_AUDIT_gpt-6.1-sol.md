# Security audit — Codex (OpenAI GPT 6.1-sol)

One of two independent reviews of the design and of the two implementations of [vauth-login](README.md), scoring Coolness, Robustness and Safety out of 20. The other review is in [SECURITY_AUDIT_fable-5.1.md](SECURITY_AUDIT_fable-5.1.md).

## Scope and method

Source review of version 1.0.0: `index.js`, `vauth.go`, `vault.go`, `cache.go`, `rc.go`,
`cmd/vauth-login`, tests, documentation and CI/release configuration. Relevant installed nyks,
cnyks, ssh2 and ssh-agent-crypt 1.4.1 code was inspected, including Go's Windows discovery.
This is not a formal security proof, dependency-vulnerability inventory, server-plugin audit,
published-binary verification or native Windows runtime audit.

On Linux/amd64, Go 1.24.0 and Node 22.22.2, `go test -race -count=1 ./...`, `npm test`,
`go vet ./...` and `npx eslint .` all pass. The uncached Go race run passes for the module and
CLI, with no races reported; npm passes all 65 tests, with none skipped. Tests use temporary
identities, isolated SSH agents and loopback fixtures. Dependency downloads were disabled;
no real Vault or user cache was accessed. Additional in-memory Node probes confirmed macro
replacement/recursion, YAML error source disclosure and connected-client short-circuit behavior.

## Design, restated

`New()`/`VauthLogin` select the first existing configuration from `VAUTHRC`, the current directory and
the home directory. Only `vault_addr`, `ssh_auth`, `jwt_auth` and `token_cache` are retained;
authentication configuration and address strings can expand `$${env.NAME}`. Configuration overrides
the address environment variable. An authentication method must be configured to use a token.

`Connect`/`connect` prefer an inherited token, then an encrypted disk cache, then SSH or JWT login.
SSH authentication lists agent identities, obtains a server nonce for each attempted key, signs its
raw bytes and posts the public key, role, base64 nonce and base64 signature. JWT login posts the
configured JWT and role. SSH takes precedence when an agent address is available.

The cache is `~/.vauth/tokens/<hash>.creds`; its name hashes serialized address/authentication
configuration with SHA-256. JSON contains the token, original lease duration, renewable flag
and absolute millisecond expiry; null expiry means
unlimited. Writers use ssh-agent-crypt v3 and temporary-file replacement. Readers also inherit its
legacy-format support. Cache encryption selects the identity/mail variables before the dependency's
default selector; decryption selects the embedded fingerprint. This protects stored bytes, not a
process or attacker with access to the signing capability.

Matching caches are reused locally until expiry or the final third of their lease. Renewable tokens
then use `renew-self`; others trigger login. An uncached inherited token uses `lookup-self`.
`--renew` means fresh login, not token renewal. The Node module returns a token for cnyks raw
rendering; Go writes it directly. `export VAULT_TOKEN=$(vauth-login)` is an unusually convenient
interface, but bearer-token disclosure through shell tracing or consumers remains possible.

## What holds
- The separation is clean: nyks supplies HTTP/stream/configuration utilities, cnyks supplies the Node
  runner, and ssh-agent-crypt supplies authenticated encryption rather than a second home-grown
  cipher. Go preserves the small API.
- Both cache writers encrypt before writing credential content. v3 authenticates its header and
  ciphertext before decryption; random salt/IV and separate encryption/MAC keys come from the
  dependency. Tokens are not intentionally persisted in plaintext. An unlocked agent is still a
  decryption oracle.
- The lifecycle preserves the original lease baseline across lookups, replaces it after renewal, and
  avoids cache writes on normal reuse. Lookup/renewal 400/403 responses trigger login; network/server
  failures instead propagate.
- Unique temporary files and replacement avoid partial destination contents on the ordinary
  local-filesystem path. Cache errors produce generic stderr warnings and leave the token usable for
  the current invocation.
- Default transports reject redirects: Go explicitly uses `ErrUseLastResponse`; Node does not enable
  nyks's redirect option. Ordinary TLS verification is not disabled by repository code. Go closes HTTP
  bodies and agent connections; ssh2 closes its per-operation streams on completion/failure.
- Passing local suites exercise lifecycle, encrypted storage, disabled/corrupt caches, API and
  output behavior. Common JSON/session serialization and the shared crypto format support interchange;
  actual Node-to-Go-to-Node cache reuse was not executed here. Passing tests establish covered Linux
  behavior, not exhaustive protocol or native Windows conformance.

## Weaknesses and remaining work

1. **High priority: distinguish cached validity from server validity.** `connect`/`Connect`
   deliberately skip `lookup-self` for a matching cache; revocation, policy changes and server-side
   lease limits are not discovered before handing out that credential. Null expiry can permit
   indefinite local reuse. Their connected-client fast path also bypasses expiry/renewal checks on
   every later non-forced call, making long-lived SDK clients stale even after finite expiry. Add an
   explicit online-validation mode and check time on repeated calls; keep offline reuse as a
   documented availability choice. Fresh login does not revoke the previous token or delete superseded
   entries.

2. **High priority: make lookup/renew metadata assumptions explicit.** `_lookup_token`/`lookupToken`
   validate remaining TTL, but not a positive, coherent `creation_ttl` baseline. Missing/zero
   baselines disable proportional renewal for an uncached finite token. Zero TTL is always treated as
   unlimited, without another validity discriminator. Lookup/renew 400/403 handling is coarse, not
   proof that every such failure means expiration. Node login and renewal require a truthy token
   rather than a string; Go uses typed fields. Validate metadata consistently and test missing,
   contradictory and zero values.

3. **High priority: bind cache content to its session; tighten file handling.**
   `_read_token_cache`/`readTokenCache` authenticate the armor, not its destination hash: the
   encrypted JSON contains no session identifier. Someone able to copy a valid cache to another
   configuration's filename, with the same available decryption key, can substitute a token without
   forging a MAC. Local reuse accepts it without checking its origin; later renewal can send it to the
   wrong server. Authenticate the expected session hash inside the payload and compare it on read.
   Also validate lease/expiry fields: Go accepts missing expiry as unlimited; Node accepts arbitrary
   parsed JSON without a cache schema.

   Reads follow symlinks and have no regular-file, ownership or size checks. `mkdir`/`MkdirAll` do not
   repair preexisting directories or reject linked parents. Node uses exclusive temporary creation; Go
   `saveTokenCache` closes its `CreateTemp` descriptor and `writeTokenCache` reopens the name, adding
   a substitution window if the directory is writable by another principal. Keep the descriptor open.
   Neither implementation locks competing writers, rejects stale replacement or fsyncs file/directory
   for crash durability. Go's `os.Rename` is not guaranteed atomic on non-Unix systems; Windows mode
   bits are not an audited ACL policy. These are conditional risks, not evidence that a private,
   correctly owned cache directory has already been compromised.

4. **High priority: configuration is a credential-routing trust boundary.** The constructor and
   `LocateRC` trust the first existing file, including one in an untrusted checkout; neither verifies
   ownership, permissions or origin. That file can route inherited credentials/JWTs and request agent
   signatures at its chosen endpoint. Environment expansion is data substitution, not shell execution,
   but can select any process environment value. Pin a reviewed `VAUTHRC` and offer explicit
   trust/origin controls before signing or sending. Go `ReplaceEnv` stops after 16 passes; nyks
   recursively calls itself without a bound and uses a replacement string. A literal `$&` expansion
   reproduces the match until stack overflow; `$$` loses a dollar. Use literal replacement callbacks
   and bounded, cycle-aware expansion with agreed missing-key behavior.

5. **Medium priority: strengthen the HTTP boundary beyond the good defaults.** `request` in both
   implementations permits HTTP; HTTPS is not enforced and addresses/auth mount paths are concatenated
   without an origin/path policy. Validate configuration and document any intentional plaintext
   exception. Go's default 60-second timeout covers the request/body; Node's nyks timer starts on
   request `finish`, not before connection/upload. Existing Node tests target stalled headers/body,
   not a pre-send stall. Neither API takes a caller cancellation context/signal. Go's injected
   `HTTPClient` can remove deadlines and redirect rejection. Both drain entire success/error bodies
   without a cap. Limit responses and apply an end-to-end deadline; reject redirects even with custom
   clients unless explicitly authorized. `HTTPError` hides bodies from normal string rendering, but Go
   exports `Body`: struct/JSON logging can expose it. Node's non-enumerable `body` is safer, not an
   access-control boundary.

6. **Medium priority: bound nonce signing and preserve meaningful failures.**
   `_login_vault_ssh`/`loginVaultSSH` reject empty nonces, but impose no nonce-size, key-count or
   overall attempt limit. They sign server-selected raw data, with no client-enforced signing
   namespace. Endpoint trust and server replay/expiry enforcement are therefore essential; the Vault
   plugin was not reviewed. Identity/mail selection only controls cache encryption, not which login
   keys are offered. Both swallow all per-key login errors, including 5xx/transport failures, then
   report a generic failure. Node aborts on an agent refusal; Go continues. Add login-key selection,
   bounded attempts and failure classes.

7. **Medium priority: Windows discovery is not verified fallback behavior.** Go delegates to
   ssh-agent-crypt `DefaultAgentAddress`: explicit socket, existing Pageant pipe, otherwise OpenSSH
   pipe. A selected but unusable Pageant pipe does not trigger an OpenSSH retry. Node chooses ssh2's
   `pageant` transport without a socket and has no equivalent default OpenSSH fallback. Go's winio
   dial has a two-second default, but subsequent agent requests have no deadline; Node agent
   operations are also unbounded. CI builds Windows rather than running agent tests; Node's Windows
   test mocks the platform and login method. Test real discovery, ACLs, unavailable/stalled agents and
   both RSA/Ed25519 identities.

8. **Medium priority: JWT fallback and persistence need explicit policy.** JWT authentication itself
   requires no agent, but disk encryption does. An available address plus SSH configuration wins even
   if that agent/login fails; neither client then falls back to JWT. Preserve this intentionally or
   provide an opt-in fallback policy. The expanded JWT participates in the cache hash, so rotation
   creates another entry and old files are not collected. Hashing configuration is not anonymization
   or a binding to the server session.

9. **Medium priority: maintain the raw-output contract on failures too.**
   `tokenStatus`/`_token_status` write to stderr; Go `run` checks token-output errors and rejects an
   empty login. Node's unbound default invocation can instead succeed with empty stdout, as its CLI
   test specifies. Go help uses stdout; cnyks help uses stderr. Align empty-result exit behavior and
   test broken stdout pipes. The convenient shell `export` form can mask substitution failure;
   capture/check command success before exporting in fail-closed scripts.

10. **Medium priority: sanitize errors, not just successful token status.** `HTTPError` messages and
    cache warnings avoid credentials, and login debug messages contain roles/key comments rather than
    nonce/signature/JWT values. Nevertheless cnyks `bundle` prints raw errors/stacks, YAML parse
    errors can include the offending source line, and nyks timeout messages include the formatted
    request address. Go also propagates parser/transport errors to `main`. Redact configuration
    source, URL credentials/query values and control characters before diagnostics; test malformed
    sensitive config, timeouts and verbose SDK logging, not only an HTTP status failure.

11. **Medium priority: release evidence is weaker than the signing headline.** `.github/workflows/*`
    use `npm install`; the local lockfile is Git-ignored, so npm dependency selection is not
    reproducibly locked. Actions use mutable version tags, the signing helper uses `ref: v1`, and
    GoReleaser uses a version range. Pin reviewed inputs and use an enforced lockfile/`npm ci`. npm
    publish has Node/Go checks; binary release runs Go checks without installing Node, and its
    optional CLI interoperability check can skip. Neither release gate runs race tests.
    `.goreleaser.yaml` hooks Windows signing and emits checksums, but published signatures, helper
    behavior and installed artifacts were not verified here. Add tag/package-version agreement and
    installed-artifact gates.

12. **Retain Node/Go parity and support cautions.** Shared serialization is carefully implemented in
    `TokenCacheKey`/`AuthKey`, but permissive Node objects and typed Go YAML differ on invalid/null
    values, aliases, scalar types and programmatically constructed auth objects. Version checks also
    differ: Go skips malformed manifests/non-semver builds, while Node parses the current manifest
    directly. Add bidirectional cache fixtures, malformed-cache/config matrices, concurrent-write
    tests and an SSH challenge mock suite. The top-level lifecycle fixtures predominantly use JWT,
    not an independently checked nonce protocol. The passing Linux suites do not establish native
    Windows behavior or cover the additional malformed-input and concurrency cases above.

## Scores

| Criterion | Score / 20 | Justification |
| --- | ---: | --- |
| Coolness | 18 | Elegant agent reuse, small nyks/cnyks-based Node surface, a practical native Go companion and raw-token shell ergonomics. A common encrypted cache is valuable; differing fallback and edge-case serialization reduce the otherwise excellent interoperability story. |
| Robustness | 14 | Lease-baseline preservation, selective reauthentication, generic cache failures and replacement writes support the normal path, backed by passing Linux suites and uncached Go race tests. Stale SDK state, incomplete schema validation, unbounded agent work, write races and Windows runtime gaps remain. |
| Safety | 13 | Authenticated encrypted storage, redirect rejection, normal TLS verification and restrained status logging are meaningful protections. Unbound cache sessions, configuration-controlled credential routing, unchecked cached revocation and unsanitized error paths require clearer boundaries and hardening. Not a security certification. |

**Release recommendation:** suitable for a controlled, trusted-configuration workflow, not an
unrestricted credential helper. Before broad security-sensitive release, bind cache payloads to
sessions, fix repeated-client expiry and Node substitution, sanitize error disclosure, and obtain
native Windows agent/artifact evidence beyond the passing Linux suites. Keep offline cache semantics
explicit and do not market encryption, signing hooks or these scores as certification.
