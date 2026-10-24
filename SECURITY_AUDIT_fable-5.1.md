# Security audit — Codex (Anthropic Claude Fable 5.1)

One of two independent reviews of the design and of the two implementations
of [vauth-login](README.md), scoring Coolness, Robustness and Safety out of
20. The other review is in
[SECURITY_AUDIT_gpt-6.1-sol.md](SECURITY_AUDIT_gpt-6.1-sol.md).

Reviewed: `index.js`, `vauth.go`, `vault.go`, `cache.go`, `rc.go`,
`cmd/vauth-login`, the Node and Go test suites, `.goreleaser.yaml` and the
three workflows. `go vet ./...`, `go test -race ./...` (43 tests), `npm test`
(75 tests, under Node 22 and 24) and `eslint .` pass locally. Behaviour
claims below were checked in code and, where cheap, by running both CLIs
against a closed port, with and without a configuration file, with a
project `.vauthrc` naming a Vault unknown to `~/.vauthrc`, without a
terminal, and with piped stdin. No real Vault was contacted.

## Design, restated

One job: produce a `VAULT_TOKEN`. The first `.vauthrc` found (`VAUTHRC`,
`./.vauthrc`, `~/.vauthrc`) names the Vault and one authentication method,
`ssh_auth` (Vault ssh plugin: fetch a nonce, have the agent sign it, post
`public_key`/`nonce`/`signature`) or `jwt_auth`. Only five keys are read
(`vault_addr`, `ssh_auth`, `jwt_auth`, `token_cache`, `known_vaults`);
`$${env.X}` macros are expanded inside them.

Precedence is the inherited `VAULT_TOKEN`, then the disk cache, then a fresh
login; `--renew` skips straight to login. An inherited token is the caller's:
it is printed back with `Vauth token: inherited`, never looked up, renewed or
written to disk, and no request is made. A cached token is trusted until its
recorded `expires_at`; in the last third of the lease a renewable one is
renewed, a non-renewable one is replaced. Only 400/403 from renewal fall
through to login; every other failure propagates.

A `./.vauthrc` is a project file, like direnv's `.envrc`: the checkout
chooses the Vault. Before the first request to that Vault (renewal or login),
its `vault_addr` must be the `vault_addr` or one of the `known_vaults` of
`~/.vauthrc`; otherwise the user is asked once on the terminal (`Unknown
vault <addr>, selected by <file>` … `Continue? [y/N]`, default no), and the
run is refused without a terminal. `--accept` skips that one check, for CI.
`VAUTHRC` and `~/.vauthrc` are the user's own choice and never ask.

The cache is `~/.vauth/tokens/sha256({vault_addr, ssh_auth, jwt_auth}).creds`,
a JSON `{token, lease_duration, renewable, expires_at}` armored by
ssh-agent-crypt v3, so the same SSH agent that logs in also guards the
cache. The token leaves on stdout, raw, without a newline; everything else
goes to stderr.

## What holds

- The CLI contract is what a shell wants: `export VAULT_TOKEN=$(vauth-login)`,
  one status line on stderr (`Vauth token: reused · 11h`), the prompt itself
  on stderr so a command substitution never captures it.
- The consent gate is placed where it matters for `login`.
  `_trust_vault`/`trustVault` runs before the renewal request and before the
  login request, which is
  before any nonce is fetched, any agent signature is requested or any
  `jwt_auth.jwt` is posted. Checked: a project `.vauthrc` with `jwt_auth:
  {jwt: "$${env.SECRET}"}` pointing at an unknown Vault is refused without
  a terminal, in both implementations, before any connection attempt. An
  inherited token short-circuits everything and so needs no consent; with
  `--renew` the inherited token is ignored and the gate applies again.
- Only `./.vauthrc` is gated, and only when it names a `vault_addr`. When the
  current directory is the home directory the file is the user's own and is
  not gated. `~/.vauthrc` is parsed through the same allow-list, so a
  hostile `./.vauthrc` cannot vouch for itself.
- The token never reaches a log line. `HTTPError.Error()` prints the status
  only; the response body is a non-enumerable property (Node) or a plain
  field hidden from `Error()` (Go). Debug output (`DEBUG=vauth-login`) names
  roles and key comments, not tokens. Tests pin this (`CLI errors do not
  print server response bodies or inherited tokens`).
- Cache at rest is ciphertext only, written to a `0700` directory as a
  `0600` file via a unique temporary (`wx` + `randomUUID()` in Node,
  `os.CreateTemp` in Go) and an atomic rename; the temporary is always
  removed. A plaintext file in place of the armor is rejected, and a cache
  failure degrades to "token not persisted" rather than to a failed login.
  Normal reuse never rewrites the file.
- The cache key and payload are byte-identical between Node and Go
  (`TokenCacheKey` reproduces `JSON.stringify` ordering, including YAML
  document order of `ssh_auth`/`jwt_auth`), so one agent, one file, two
  readers; cross-implementation fixtures prove it.
- Transport is strict in both: 60 s deadline covering headers and body,
  redirects refused (`http.ErrUseLastResponse`; nyks without
  `followRedirect`), non-200 is an error, system TLS verification on, request
  options built from a parsed URL (no string concatenation past `/v1/`).
- Lease arithmetic is defensive: `ttl`/`lease_duration` missing, `null`, or
  negative are rejected rather than read as "unlimited"; only an explicit
  `0` means indefinite. Renewal re-baselines `lease_duration`.
- The Go CLI is strict about its surface: unknown flags, extra positional
  arguments and unknown commands are refused; `--accept=false` means false.
- Both suites drive the real CLIs as subprocesses with a fake Vault, a fake
  agent and a scratch `HOME`, and cover the consent path (known, unknown,
  `--accept`, no TTY), the inherited token, renewal, expiry and the
  encrypted cache. The Go suite is race-clean.

## Weaknesses

Ordered by what I would fix first.

1. **Node exits 0 with an empty token when it cannot authenticate.** With
   no `.vauthrc` at all, with `vault_addr` only, or with `ssh_auth` but no
   `SSH_AUTH_SOCK` on Linux, `connect()` returns `undefined`, cnyks renders
   nothing, and the process exits 0 with an empty stdout *and* an empty
   stderr. `export VAULT_TOKEN=$(vauth-login)` silently sets an empty
   variable and the next tool fails far away from the cause. Go, in the
   same three cases, prints `Could not login to vault: no authentication
   method available` and exits 1. Node only throws when `--renew` is given
   or when a cached token existed. The fix is one line in the CLI path:
   refuse to produce "no token" with a zero exit, as Go's `run()` does.
2. **The Node CLI exposes ungated commands.** cnyks publishes every public
   method as a command, so `vauth-login --help` lists `lookupSelf [$token]`
   and `request $method, $apiPath, [$token, …]` next to `login`. Neither
   calls `_trust_vault`: checked, `VAULT_TOKEN=tok vauth-login lookupSelf`
   in a directory whose `.vauthrc` names a Vault unknown to `~/.vauthrc`
   connects to it and sends the token, without a terminal and without a
   prompt; `request` lets a script hit any path with it. Go's CLI accepts
   only `login`/`connect`/`version`/`help`. Mark the two methods
   `@interactive_runner hide`, or better, move the gate into `request()`
   so the SDK is covered too (the inherited-token fast path makes no
   request and stays offline).
3. **The two consent bypasses re-open the project-file problem.** By
   design a `./.vauthrc` can pick `vault_addr`, `ssh_auth.path`/`role` and
   `jwt_auth.jwt: "$${env.ANYTHING}"`. The prompt closes this for a human
   at a terminal; `--accept` and `VAUTHRC` do not. A CI job that runs
   `vauth-login --accept` on a freshly cloned repository will post any
   environment variable the repository names to any server it names, and
   will sign server-chosen bytes with every key its agent holds, with no
   output but `Vauth token: generated`. The README's `--accept` example
   does not say "only on checkouts you trust". Mitigations, in order of
   cost: document it; have `--accept` still require that the project's
   `vault_addr` equals `VAULT_ADDR` from the environment when that is set
   (CI usually sets it); refuse `$${env.*}` in `jwt` outside an explicit
   allow-list; and have the prompt list what is about to be sent (the
   expanded environment variable *names*, the role, the number of agent
   keys), not only the address.
4. **Cached tokens are trusted until `expires_at`.** No `lookup-self` is
   made on the cache path, so a revoked token is served (the test says so:
   `cached tokens are reused without checking revocation`) and a token with
   `ttl: 0` is cached with `expires_at: null`, i.e. forever. The caller
   discovers revocation only from the first Vault 403 downstream. One
   lookup per process is cheap next to a signature prompt; a time-based
   re-check (e.g. once per hour, recorded in the cache) would preserve the
   offline-ish ergonomics.
5. **The Node CLI surface is loose.** cnyks accepts any flag: `vauth-login
   --foo` runs normally, and `--accept=false` is the string `"false"`,
   which is truthy, so it *accepts*. A typo in a CI script (`--acept`) is
   silent in Node and an error in Go; `--renew=false` forces a login for
   the same reason. Validate the flag dictionary in the
   `module.parent === null` shim (only `renew`, `accept`, `help`,
   `version`, `ir://*`) and coerce booleans before handing over to cnyks.
6. **Terminal detection differs.** Go uses `ModeCharDevice`, which is true
   for `/dev/null`, so `vauth-login </dev/null` prints the full prompt,
   reads EOF and then says `refused`; Node uses `isTTY` and prints the
   one-line refusal with the `known_vaults` hint. Same outcome, different
   stderr, and the Go check would also accept a serial device or a pty
   driven by a script. `golang.org/x/term.IsTerminal` is the right test.
7. **Every agent key is offered, and the signature is raw.** `loginVaultSSH`
   iterates the whole identity list, fetching a nonce and requesting a
   signature per key until one role matches; a user with several keys gets
   several prompts (`ssh-add -c`) or none (Pageant, Windows OpenSSH agent),
   and discloses every public key to the server. The signature is
   `agent.sign`/`client.Sign` over the nonce bytes without an SSHSIG
   namespace; the nonce is a JSON string so an accepted server cannot make
   the agent sign an ssh-agent-crypt blob or a session id, which limits
   this to a signature-collection oracle on Vaults the user has vouched
   for. A `key`/fingerprint selector in `ssh_auth` would reduce both the
   prompts and the disclosure.
8. **`known_vaults` matching is textual.** Addresses are compared after
   trimming `/` only: `HTTP://`, an explicit `:443`, or a different case in
   the host are "unknown". The failure mode is a spurious prompt, never a
   spurious trust, so this is ergonomics; still, normalising scheme and
   host case through the URL parser both sides already use is cheap.
9. **Release pipeline is reproducible only by convention.**
   `package-lock.json` is git-ignored and both workflows run `npm install`,
   so the Node tree that is tested and the one that is published are
   whatever the registry served that minute; `cnyks`/`nyks`/`ssh2` are
   caret ranges. Actions are tag-pinned (`@v4`, `@v5`, `@v6`), and the
   Windows signing hook executes `131/gh-actions@v1`, a mutable ref, with
   the release token in scope. Go tests run on Linux only (Windows is a
   build check), so Pageant/OpenSSH pipe discovery and the Windows home
   directory are never exercised in CI. CI uses Node 24 while
   `package.json` declares no `engines`.
10. **Minor hygiene.** Node still throws strings (`throw 'Could not login to
   vault'`), relies on `module.parent`, and lets cnyks print the stack trace
   twice on stderr (paths, no secrets) where Go prints one line; `400` is
   treated as "invalid token" although Vault also returns it for malformed
   requests, so a bug on our side would be masked by a new login; the
   project-manifest version pin reads `./package.json` from the current
   directory, one more cwd-controlled input (denial-of-service only); the
   expanded `jwt` is part of the cache-key hash, so a rotated JWT leaves
   the previous `.creds` behind (encrypted, but never cleaned).

## Scores

| Criterion | Score / 20 | Justification |
| --- | ---: | --- |
| ✨ Coolness | 17 | A one-line `export VAULT_TOKEN=$(vauth-login)` that is the same from a Node package, a Go module or a signed `.exe`, sharing one encrypted cache that either implementation can read, with the SSH agent as the single root of trust for both login and cache, and a direnv-style consent gate that names the Vault and tells the user how to stop being asked. Reuse of ssh-agent-crypt, nyks and cnyks keeps the code small and legible. Deducted for the loose Node flag handling and the prompt saying *where* but not *what* will be sent. |
| Robustness | 15 | 75 Node and 43 Go tests that drive the real CLIs, a race-clean Go suite, cross-implementation cache fixtures, strict lease parsing, deadlines, refused redirects and atomic cache writes. Deducted for Node exiting 0 with an empty token and an empty stderr, the silently accepted unknown flags, the lockfile-free CI and the absence of Windows runtime tests. |
| Safety | 14 | Tokens are never logged, rest encrypted under the user's own SSH key with authenticated armor, inherited tokens are never persisted, a project file cannot make `login` reach the network without the user vouching for its Vault, and the trust decisions (400/403 only, no redirects) are the right ones. Deducted for the ungated `lookupSelf`/`request` commands of the Node CLI, for `--accept`/`VAUTHRC` re-opening the env-exfiltration and signing oracle on hostile checkouts, and for revocation never being re-checked while a cache is valid. Not a security certification. |

**Release recommendation:** no blocker for interactive use of `login`. Hide
or gate `lookupSelf`/`request` in the Node CLI first; before relying on
`--accept` in CI, read weakness 3 and pin `VAULT_ADDR` in the job; before
wiring vauth-login as the login step of a broader tool, align the Node CLI
with Go's non-zero exit when no token is produced.
