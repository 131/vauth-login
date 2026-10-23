# Security audit — Codex (Anthropic Claude Fable 5.1)

One of two independent reviews of the design and of the two implementations
of [vauth-login](README.md), scoring Coolness, Robustness and Safety out of
20. The other review is in
[SECURITY_AUDIT_gpt-6.1-sol.md](SECURITY_AUDIT_gpt-6.1-sol.md).

Reviewed: `index.js`, `vauth.go`, `vault.go`, `cache.go`, `rc.go`,
`cmd/vauth-login`, the Node and Go test suites, `.goreleaser.yaml` and the
three workflows. `go vet ./...`, `go test -race ./...`, `npm test` (65 tests)
and `eslint .` pass locally. Behaviour claims below were checked in code and,
where cheap, by running both CLIs against a closed port and an empty
configuration. No real Vault was contacted.

## Design, restated

One job: produce a `VAULT_TOKEN`. The first `.vauthrc` found (`VAUTHRC`,
`./.vauthrc`, `~/.vauthrc`) names the Vault and one authentication method,
`ssh_auth` (Vault ssh plugin: fetch a nonce, have the agent sign it, post
`public_key`/`nonce`/`signature`) or `jwt_auth`. Precedence is the inherited
`VAULT_TOKEN`, then the disk cache, then a fresh login; `--renew` skips
straight to login. An uncached inherited token is validated with
`lookup-self`; a cached one is trusted until its recorded `expires_at`.
In the last third of the lease a renewable token is renewed, a
non-renewable one is replaced. Only 400/403 from lookup or renewal fall
through to login; every other failure propagates. The cache is
`~/.vauth/tokens/sha256({vault_addr, ssh_auth, jwt_auth}).creds`, a JSON
`{token, lease_duration, renewable, expires_at}` armored by ssh-agent-crypt
v3, so the same SSH agent that logs in also guards the cache. The token
leaves on stdout, raw, without a newline; everything else goes to stderr.

## What holds

- The CLI contract is exactly what a shell wants: `export
  VAULT_TOKEN=$(vauth-login)`, one status line on stderr (`Vauth token:
  reused · 11h`), unknown flags and positional arguments refused.
- The token never reaches a log line. `HTTPError.Error()` prints the status
  only; the response body is a non-enumerable property (Node) or a plain
  field hidden from `Error()` (Go). Debug output names roles and key
  comments, not tokens. Tests pin this (`CLI errors do not print server
  response bodies or inherited tokens`).
- Cache at rest is ciphertext only, written to a `0700` directory as a
  `0600` file via a unique temporary name (`wx` + `randomUUID()` in Node,
  `os.CreateTemp` in Go) and an atomic rename; the temporary is always
  removed. A plaintext file in place of the armor is rejected, and a cache
  failure degrades to "token not persisted" rather than to a failed login.
- The cache key and payload are byte-identical between Node and Go
  (`TokenCacheKey` reproduces `JSON.stringify` ordering, including YAML
  document order of `ssh_auth`/`jwt_auth`), so one agent, one file, two
  readers. Normal reuse never rewrites the file.
- Transport is strict in both: 60 s deadline covering headers and body,
  redirects refused (`http.ErrUseLastResponse`; nyks without
  `followRedirect`), non-200 is an error, system TLS verification on.
- Lease arithmetic is defensive: `ttl`/`lease_duration` missing, `null`, or
  negative are rejected rather than read as "unlimited"; only an explicit
  `0` means indefinite. Renewal re-baselines `lease_duration`; a mere lookup
  does not.
- `.vauthrc` is read through a four-key allow-list before any `$${env.X}`
  expansion, so the environment-dependent `env.*`/profile sections of a
  broader vauth file are never interpreted here. `token_cache: false` skips
  every filesystem access and leaves an existing armor untouched.
- Node runs the real CLI in subprocesses with a fake Vault; Go runs its CLI
  through `os.Executable()` with a cleaned environment; both check exit
  status, stdout bytes and stderr text, and the ssh-agent-crypt CLI reads
  the Node cache in a test.
- Signed Windows binary, `SHA256SUMS`, tests before `npm publish` and
  before `goreleaser`, OIDC publication without a long-lived npm token.

## Weaknesses

Ordered by what I would fix first.

1. **`./.vauthrc` is a signing and exfiltration oracle.** By design the
   configuration is a project file, like direnv's `.envrc`, and `~/.vauthrc`
   is only a fallback: the project chooses the Vault, and nothing tells the
   user which one before the tool acts. Such a file picks `vault_addr`, so
   (a) with `ssh_auth` the agent signs server-chosen bytes with *every* key
   it holds — raw `agent.sign`/`client.Sign` over the "nonce", not an
   SSHSIG-namespaced signature — and (b) with
   `jwt_auth: {jwt: "$${env.ANYTHING}"}` any environment variable is posted
   to that server as the login payload. The nonce is a JSON string, so an
   attacker cannot shape arbitrary bytes (an ssh-agent-crypt blob or a
   session id would not survive UTF-8), which limits (a) to a
   signature-collection oracle today; (b) is a complete secret-exfiltration
   path and needs no cryptography. On Linux `ssh-add -c` makes (a) visible;
   Pageant and the Windows OpenSSH agent prompt for nothing. The fix is
   consent, not a different lookup order: print the Vault origin on stderr
   before signing or sending, remember allowed origins the way direnv
   remembers allowed `.envrc` files, and restrict `$${env.*}` in `jwt` to an
   explicit allow-list.
2. **An inherited `VAULT_TOKEN` is persisted.** When the environment
   carries a token that is not the cached one, a successful `lookup-self`
   ends in `_save_cached_token`/`saveTokenCache`. A token the operator
   exported for one shell (a root token, a CI-injected one) now lives in
   the user's home for its full TTL and will be reused by later calls
   with no token in the environment. The test `an existing environment
   token is respected and cached` makes this intentional; it still widens
   the scope of a credential the tool did not create. Consider caching only
   tokens vauth-login obtained itself, or at least not when `ttl == 0`.
3. **Cached tokens are trusted until `expires_at`.** No `lookup-self` is
   made on the cache path, so a revoked token is served (the test says so:
   `cached tokens are reused without checking revocation`) and a token with
   `ttl: 0` is cached with `expires_at: null`, i.e. forever. The caller
   discovers revocation only from the first Vault 403 downstream. One
   lookup per process is cheap next to a signature prompt; a time-based
   re-check (e.g. once per hour) would preserve the offline-ish ergonomics.
4. **Node exits 0 with an empty token when no method is configured.** With
   a `.vauthrc` that has `vault_addr` only, Go fails (`Could not login to
   vault: no authentication method available`, exit 1); Node's `connect()`
   returns `undefined`, cnyks renders nothing, and `export
   VAULT_TOKEN=$(vauth-login)` silently sets an empty variable. Same when
   `VAULT_ADDR` is unset: Go says `Not bound to any vault` on stderr and
   then dials a relative URL; the Node side prints nothing. Both should
   refuse to produce "no token" with a zero exit.
5. **Every agent key is offered, and the cache costs two signatures.**
   `loginVaultSSH` iterates the whole identity list, fetching a nonce and
   requesting a signature per key until one role matches; a user with
   several keys gets several prompts and discloses every public key to the
   configured server. On the cache path `readTokenCache` is called in
   `Connect` and again inside `lookupToken`, i.e. two SSHSIG derivations
   where one would do. A `key`/fingerprint selector in `ssh_auth` and a
   single read passed down would fix both.
6. **No CA or TLS knobs.** `VAULT_CACERT`, `VAULT_SKIP_VERIFY` and friends
   from the official clients are not honored; a private CA must be in the
   system store. That is the safe default, but it means some users will be
   tempted to run the tool over plain `http://`, which nothing warns about.
7. **Release pipeline is reproducible only by convention.**
   `package-lock.json` is git-ignored and both workflows run `npm install`,
   so the Node tree that is tested and the one that is published are
   whatever the registry served that minute; `cnyks`/`nyks`/`ssh2` are
   caret ranges. Actions are tag-pinned (`@v4`, `@v5`, `@v6`, `131/gh-actions@v1`),
   not SHA-pinned. Go tests run on Linux only (Windows is a build check),
   so Pageant pipe discovery and the Windows home-directory choice are
   never exercised in CI. `.gitignore` also lists `token-cache.js`, which
   would silently ignore any new file of that name next to the tracked one.
8. **Minor hygiene.** Node still throws strings (`throw 'Could not login to
   vault'`) and relies on `module.parent`, both deprecated paths; `400` is
   treated as "invalid token" although Vault also returns it for malformed
   requests, so a bug on our side would be masked by a new login; the
   project-manifest version pin reads `./package.json` from the current
   directory, one more cwd-controlled input (denial-of-service only).

## Scores

| Criterion | Score / 20 | Justification |
| --- | ---: | --- |
| ✨ Coolness | 17 | A one-line `export VAULT_TOKEN=$(vauth-login)` that is the same from a Node package, a Go module or a signed `.exe`, sharing one encrypted cache that either implementation can read, with the SSH agent as the single root of trust for both login and cache. Reuse of ssh-agent-crypt, nyks and cnyks keeps the code small and legible. Deducted for the silent `./.vauthrc` pickup and the two-signature cache path. |
| Robustness | 16 | 65 Node tests and 43 Go tests that drive the real CLIs, a race-clean Go suite, cross-implementation cache fixtures, strict lease parsing, deadlines, refused redirects and atomic cache writes. Deducted for the empty-token exit 0 in Node, the lockfile-free CI and the absence of Windows runtime tests. |
| Safety | 14 | Tokens are never logged, rest encrypted under the user's own SSH key with authenticated armor, and the trust decisions (400/403 only, no redirects) are the right ones. Deducted for the cwd-controlled `.vauthrc` acting as an env-exfiltration and signing oracle, inherited tokens being persisted, and revocation never being re-checked while a cache is valid. Not a security certification. |

**Release recommendation:** no blocker for users who own the `.vauthrc` they
run under and who understand that anything with `VAULT_TOKEN` in its
environment can now also write it to disk. Before promoting vauth-login as
the login step of a broader tool, decide the `./.vauthrc` trust model and
align the Node CLI with Go's non-zero exit when no token is produced.
