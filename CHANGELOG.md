# Changelog

All notable changes to arca are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches 1.0.

## [Unreleased]

## [0.10.0] - 2026-08-14

### Security
- **Extending or clearing an expiry now needs an operator terminal (T13 residual).** The anchor
  that closed T13 covered five relaxation flags but stopped at `--ttl` / `--expires-at`, which
  overwrote `ExpiresAt` unconditionally: `arca set NAME --ttl 30d` extended a secret due to expire
  tomorrow, headless. Three things were filed as blocking it and all three are resolved. "Extend
  versus shorten" turned out not to need a rule per spelling, because resolving both to an instant
  *before* comparing collapses it to one time comparison. There is now a clearing path, a flag
  given empty removes the expiry, matching `--rate ""`. And `rotate`, the third command that can
  move an expiry and the only one with no anchor at all, now goes through the same predicate.
  The ordering: no expiry is the least protected state a secret can be in, and an earlier expiry
  is tighter than a later one. Extending or clearing is a downgrade and prompts; shortening, or
  setting an expiry where there was none, is not and stays headless. A flag that is absent still
  leaves an existing expiry alone, so re-running a write command never silently drops one.
  With this, `docs/THREAT-MODEL.md` has no open findings for the first time.
  **This changes a documented workflow, so it is worth stating plainly.** `arca rotate NAME --ttl
  1h` on an *already expired* secret was the documented way to revive it, and reviving is the
  largest extension there is: a dead credential becomes live again. It now prompts, which means it
  no longer works unattended in CI or a script. Rotating without an expiry flag is unaffected and
  stays headless, as does shortening. If you revive expired secrets from automation, that job
  needs a terminal now, or should create the secret fresh instead.
- **A recipient that arrives by sync is now reported (T12).** `recipients add` and `reencrypt` are
  both anchored to an operator terminal, so a key cannot be added *on this machine* without someone
  seeing it. Neither covers a key added on **another** machine: the store arrives carrying a
  recipient nobody here was shown, and no read path looks at the recipient set at all. Every
  per-secret control is irrelevant to it, because re-wrapping never calls `gate()`.
  `recipients.pin` (state dir, `0600`, never synced) records the set this machine has accepted. A
  recipient in the store but not in the pin is reported on every load and raises `doctor`'s
  readership check to HIGH, naming the key. That check previously reported a count at LOW, which is
  a fact rather than a finding, since there was nothing to compare it against.
  The pin does not behave like `store.gen`. That high-water mark advances by itself on seeing a
  higher number, because it exists to catch a generation going *backwards*; a recipient set going
  *forwards* is the attack. So the pin is edited, never rewritten from the store: `recipients add`
  accepts only the keys just shown, and `recipients rm` drops only what it removed. That distinction
  is load-bearing for `rm`, which is deliberately unanchored on the grounds that removal only
  restricts — had it re-pinned from the store, removing any key at all would have silently accepted
  an injected one, an unanchored path to silencing this very warning. Loading never accepts either:
  the warning repeats until an operator runs the new `arca recipients pin`, which is itself anchored,
  lists the unaccepted keys in its prompt, and records `op=recipients-pin`.
  The residual is trust-on-first-use: the baseline is set silently on first load, so a key injected
  before that is never reported. Warning on every store that predates the check would train
  operators to ignore the one warning that matters.

### Changed
- **`stale --missing` is now `ls --no-rotation`.** It asked a different question from the rest of
  `stale`: which secrets have no rotation policy at all, rather than which are due. It also
  produced different output, and that had a consequence beyond tidiness. `stale --json` emitted
  rotation rows normally and `ls`-shaped rows under `--missing`, so a command whose JSON shape
  `STABILITY.md` promises as stable actually had two shapes depending on a flag, and a consumer
  parsing it could be handed either. It lives on `ls` now because the rows it emits were already
  `ls` rows, which makes it an ordinary filter that composes with `--tag` rather than a mode that
  silently ignored `--within`. The old flag is hidden and fails with a message naming its
  replacement, rather than disappearing into "unknown flag".

## [0.9.2] - 2026-08-14

A dependency-only release with no code changes. Both entries below are upstream security fixes
that arca reaches on real call paths.

### Security
- **The Go toolchain moved to 1.26.6.** The nightly `govulncheck` job started failing against an
  unchanged `main`: Go 1.26.6 shipped and the vulnerability database published five advisories
  against the 1.26.5 standard library, all of them on paths arca actually calls. Quadratic
  complexity in `resolvePath` ([GO-2026-6218](https://pkg.go.dev/vuln/GO-2026-6218), `net/url`);
  unbounded post-handshake messages ([GO-2026-6090](https://pkg.go.dev/vuln/GO-2026-6090),
  `crypto/tls`); a missing recursion-depth guard on decode
  ([GO-2026-6088](https://pkg.go.dev/vuln/GO-2026-6088), `encoding/xml`) and the same gap in
  `encoding/asn1` ([GO-2026-5972](https://pkg.go.dev/vuln/GO-2026-5972)); and `x/net/idna`
  accepting ASCII-only Punycode labels through `net/http`
  ([GO-2026-5026](https://pkg.go.dev/vuln/GO-2026-5026)). The tls, xml, asn1 and http traces all
  enter the standard library through the S3 client in `internal/remote`, and the `net/url` one
  arrives via the MCP server's `init` path. Every workflow resolves its toolchain with
  `setup-go`'s `go-version-file: go.mod`, so the `toolchain` directive is the only place this is
  pinned and the bump is the whole fix.
- **`modernc.org/sqlite` 1.55.0 to 1.56.0.** Picks up the upstream SQLite 3.53.3 fix for a
  data-corruption bug in journal recovery: a zeroed super-journal name still passes the
  plain-byte-sum checksum, so `pager_playback()` could delete a hot journal without replaying it,
  leaving a partially-applied transaction on disk. arca keeps its audit log in SQLite, and the
  audit log is precisely the record a tampered-with run is supposed to be caught by.

### Changed
- GitHub Actions pins refreshed across the workflow set (harden-runner, codeql-action,
  attest-build-provenance and two others), each still pinned to a SHA with the version carried in
  a trailing comment.

## [0.9.1] - 2026-08-01

### Changed
- Go modules (main and `tools/docsgen`) and GitHub Actions pins refreshed to latest
  ([#115](https://github.com/arenzana/arca/pull/115)).

## [0.9.0] - 2026-07-27

### Security
- **`set` and `generate` can no longer relax the policy on an existing secret without an operator
  terminal (T13).** The control-plane anchor covered the six commands that exist to widen access; it
  did not cover the two whose job is to write a value and whose policy flags ride along. So
  `arca set NAME --require-approval=false` — likewise `--no-print=false`, `--require-grant=false`,
  `--rate ""` and `--canary=false` — moved a protection off a secret that already had it, headless.
  Those five are now anchored, and the predicate is deliberately narrow: it fires only when the
  secret already exists **and** the invocation leaves it less protected than it is now. Creating a
  secret with a loose policy is unchanged, tightening never needs a terminal, and a plain
  `arca set NAME` that passes no policy flag is untouched — an anchor that prompted on ordinary
  traffic would be one operators learn to answer `y` to without reading.
  Two specifics worth knowing. **`--rate` is compared, not matched:** a caller refused `--rate ""`
  could otherwise write `--rate 1000000/1s` and keep the same capability, so clearing is treated as
  the limiting case of raising, using the same window defaulting the rate limiter enforces.
  And **`--canary=false` is included** — `set`/`generate` are the only path in the CLI that disarms a
  decoy, so the off-switch for the tripwire was the least guarded of the five.
  The refusal arrives *before* the value is read, so a refused downgrade leaves the secret and its
  decoy registration exactly as they were.
- **`recipients add` is now audited (SEC-44).** Adding an age recipient grants permanent decryption
  rights to every secret in the store, on every machine the store reaches — the widest-blast-radius
  mutation arca supports — and it previously wrote no audit event at all. The log could show a
  `reencrypt` with no trace of the key it re-wrapped to, and `log --verify` still reported a clean
  chain (correctly: the chain is honest about everything it is told, and it was never told). Each
  added key is now recorded individually as `op=recipients-add` with the key in the `name` field, so
  the log answers *which* key was added. Re-adding an existing key stays a no-op and logs nothing.
  A **relabel is also recorded** (`op=recipients-label`): labels are how an operator recognizes a key
  during review (`who-can-read`, `exposure`, `doctor`), so renaming an unfamiliar key to something
  trusted-looking is a way to hide it from exactly that check.
  This closes the audit half of the recipient-injection gap; the control-plane anchor is the entry
  below.
- **The control plane is now terminal-anchored (T11/T12).** arca's strongest per-secret controls are
  enforced on the paths that *release* a value, but the commands that *change those rules* carried no
  anchor — so every control on the disclosure path could be edited away by the party it governs. An
  agent refused by `--require-grant` could run `arca grant NAME --ttl 52w --uses 0` and retry (grants
  are keyed by name with no merge, so a self-issued one silently *replaces* the operator's narrower
  grant); an agent hidden by `mcp --strict` could run `arca agent allow NAME`; and widest of all,
  `arca recipients add <own key>` + `arca reencrypt` re-wraps every value to a key the operator does
  not hold, permanently and on every machine the store reaches, without ever entering an access path.
  `arca grant`, `agent allow`, `enable`, `recipients add`, `reencrypt` and `handle create` now refuse
  a detected agent outright and require every other caller to confirm on the controlling terminal,
  with the prompt naming the scope being widened. Deliberately an interactive **prompt** rather than
  a TTY-presence check: an agent launched from the operator's own shell inherits that terminal, so a
  predicate would pass for the primary adversary. The commands that only *restrict* — `agent deny`,
  `disable`, `recipients rm`, `handle revoke` — stay headless, so incident response is never gated on
  a terminal. **There is no environment bypass**, deliberately; `ARCA_APPROVAL=allow` was removed for
  the same reason, and a test enforces the absence. The cost is that non-interactive control-plane
  use (CI issuing a grant, a provisioning script adding a key) is now refused rather than silently
  allowed; the intended answer is an operator-minted, scoped, expiring capability, not a variable.
  Scope: this covers the commands whose job is to widen access. A policy bit cleared in passing by
  `set` / `generate` (`--require-approval=false` and friends) is **not** anchored — both overwrite
  the value first, so that path is destroy-and-downgrade and audited rather than silent escalation.
  See T11/T12/T13 in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) for the residuals.
- **An AI agent can no longer redirect its own audit log.** `$ARCA_AUDIT` was honoured
  unconditionally, and an agent controls its own environment — so pointing it at a scratch file
  bought the agent a log nobody reads, a *fresh rate-limit window on every secret* (the audit log
  is the rate counter), and a canary registry whose trips land where the operator never looks,
  while `arca log`, `arca canary --list` and `arca doctor` stayed clean against the real DB.
  A command now **refuses to run** when an agent is detected and `$ARCA_AUDIT` resolves to
  anything other than that store's own audit DB. It refuses rather than ignoring the variable:
  falling back to the real log silently would leave the agent believing it is unaudited and the
  operator holding a log that contradicts the environment they can see.
  Unchanged for everyone else: `$ARCA_AUDIT` remains the documented way for an *operator* to point
  several stores at one shared log, with or without a terminal, so scripts and CI are unaffected.
  Setting it to the path arca would have used anyway is not a redirection and is not refused.
- **A canary trip that cannot be recorded now blocks the access.** `tripCanary` discarded the
  audit write's error, which made the tripwire the one event in arca that was not fail-closed: a
  caller who had already broken the audit DB could take a decoy and leave no trace but a line on
  the stderr it was reading itself. Tripping still does **not** block the access when the trip
  records normally — the value is fake, and letting the caller take it is what keeps the trap
  useful. Both access paths carry the rule, including MCP `run_with_handle`, which bypasses the
  policy gate and so had to be fixed separately.

### Fixed
- **The MCP exec tools no longer let an agent exhaust arca's memory or wedge it indefinitely.**
  `run_with_secrets` and `run_with_handle` capture their child's output to return it in the tool
  result, and that capture had no ceiling and the child no deadline — so an agent-chosen `yes`,
  `cat /dev/urandom`, or simply a hung command could grow arca's heap without limit or block a
  worker forever. Output is now capped per stream (1 MiB, `ARCA_MCP_MAX_OUTPUT`) with an explicit
  truncation notice in the result, and the child gets a wall-clock deadline (120s,
  `ARCA_MCP_TIMEOUT`) after which it is killed and the call reported as an error. Both overrides
  are **clamped** to a range rather than honoured verbatim — an agent that owns the environment
  must not be able to spell "unlimited". `arca exec` is unaffected: it streams to stdout and was
  never unbounded. The cap deliberately sits *downstream* of redaction, so truncation can only
  ever discard bytes that already passed the redact writer's split-value hold-back.
- **arca disables core dumps at startup** (`RLIMIT_CORE` → 0, Unix), for every command rather
  than just `arca mcp`. Any command that touches a value holds it in cleartext on the heap:
  `get`/`inject` decrypt to stdout, `exec` and the MCP tools additionally hold it in the redact
  patterns and the child's environment, and `reencrypt` holds the whole store at once. A crash
  dump on a host that collects them would contain all of it, defeating the disclosure controls
  applied above. The MCP server is the sharpest case — it holds injected values for its whole
  lifetime and the agent picks the command that can crash it — but it is not a special case.
  Windows has no per-process equivalent; that remains machine-wide WER policy.
- **A sync can no longer lose a concurrent local write.** `arca sync` did its network work while
  holding no lock and then committed a decision computed *before* that network round trip, so a
  `rm` or `rotate` landing in that window was silently overwritten by the pulled payload — a
  removed secret came back and the store looked healthy afterwards. The sync is now split in two:
  an unlocked phase that writes nothing and does all the network work and refusals, and a locked
  phase that re-reads the local store and cursor, compares them byte-for-byte against the
  snapshot the decision rests on, and only then commits. A change in that window restarts the
  sync; sustained contention reports "run it again" after three attempts rather than committing
  anything. No backend call is made while the store lock is held, so a slow backend can never
  delay an incident-response command. Opportunistic auto-sync never waits for the lock: it
  checks for a concurrent writer before going to the network and skips silently, so an open
  `arca edit` session costs the next command nothing — the one exception being a push that has
  already reached the remote, which always records its cursor because failing to would surface
  later as a conflict that isn't one.
- **`arca disable` now also stops MCP handles minted before it ran.** The handle path skips
  `gate()` (a handle *replaces* grant and approval) and had lost the `Disabled` check with it, so
  the kill switch closed six access paths and not the one an agent was already holding. The check
  is at *use* time, which is the load-bearing part — a handle is minted before an incident and
  `disable` is thrown during one. Handles go inert rather than being revoked, so `enable` restores
  the pre-incident state instead of forcing a re-issue.
- **An empty stdin no longer destroys a stored secret.** `arca set NAME` with a producer that
  failed stored an empty value over the real one and exited 0, with no undo — the store keeps only
  the current value. See `--allow-empty` above.
- **A failed write no longer makes the store look rolled back.** The monotonic `generation`
  counter — the rollback tripwire that `arca doctor` warns on and that `log --verify` binds into
  every signed audit event — was bumped *before* the store was written, so any failure past that
  point left the running process one generation ahead of the file. That command's audit event then
  recorded a generation that had never existed on disk, and the next process, loading the real
  lower one, produced exactly the pattern `log --verify` reports as evidence of a restored older
  copy. The counter now advances only after the bytes have landed. A false alarm on a
  tamper-evidence signal is worse than no alarm: it teaches you to discount the one thing that
  should never be discounted.
- **A power loss immediately after a successful write can no longer lose it.** Every one of arca's
  state files — the store, a pulled store, the sync config and cursor, grants, handles, the canary
  registry, the escrow cursor and the rollback high-water mark — was published by renaming a temp
  file into place, and a rename is a change to the *directory*, which is not durable until the
  directory itself is flushed. `arca set` could report a secret stored and lose it to a power cut a
  moment later. All nine writers now go through one helper that fsyncs the parent directory after
  the rename, and that reports a failure to do so rather than swallowing it (the write is
  committed at that point; what the error means is that it may not survive a crash). On Windows
  there is no way to ask for this — a directory handle cannot be opened for the write access
  `FlushFileBuffers` requires — so the gap is named in the code rather than papered over.
- **A leftover temp file from a crashed run can no longer widen a state file's permissions or
  block a write.** Four state writers published through a fixed `<file>.tmp`, and `os.WriteFile`
  applies its mode only when it *creates* a file — so a leftover sitting at `0644` was renamed on
  top of a `0600` destination, mode and all, with nothing reporting anything wrong. The same fixed
  name was also what two concurrent writers collided on. `sync.json` had been fixed for exactly
  this and the fix was never carried back to the function directly above it. Temp files are now
  uniquely named and chmod'd before a single byte is written, everywhere.

### Added
- **Secret scanning in CI.** A `secret-scan` job runs gitleaks over the full history on every push
  and PR. arca is a secrets manager: a test fixture, doc example, or recipe carrying a real
  credential is a plausible mistake with outsized blast radius, and git history makes it permanent.
  Invoked via `go run tool@version` like the other linters, so it is verified through the Go checksum
  database and needs no marketplace action or license; `--redact` keeps a match out of the public CI
  log.
- **`--allow-empty` on `set`, `rotate` and `import`.** Storing an empty value is now refused by
  default, because the overwhelmingly common cause is a failing producer in a pipeline
  (`vault read … | arca set PRODKEY`) rather than an intent to store nothing. Pass
  `--allow-empty` when the empty value is deliberate. Whitespace is a value, not an absence: a
  single space still stores.

### Changed
- **Local state is now kept per store, under `$XDG_STATE_HOME/arca/stores/<store-key>/`.** The
  sync config and cursor, the rollback high-water mark, grants, handles, the canary registry, the
  escrow cursor, the audit DB and the session signing keys were shared by every store on a machine.
  Running two stores — the documented personal/work split, one `ARCA_STORE` away — meant a `sync`
  against store B reconciled it against store A's backend and replaced its contents, and B's
  legitimately lower generation tripped the rollback warning against A's high-water mark. The
  directory name is derived from the store's absolute path; `machine-id` deliberately stays shared,
  because it identifies the machine to escrow rather than the store.
  The first command after upgrading moves the existing state into the per-store directory for the
  store it is running against, once. Nothing is copied and nothing is deleted, and a failure warns
  rather than taking the command down. A *second* store starts with empty state — that is the fix —
  and `arca doctor` gains a `state-dir` check that names which store adopted the shared state, so
  an unexpectedly empty grants list is explained rather than mysterious. `$ARCA_AUDIT` still wins
  when set, which is how you point several stores at one audit log deliberately.

## [0.8.0] - 2026-07-24

### Added
- **User-safety release**: `doctor` and `exposure` for blast-radius visibility, safer defaults
  for AI-agent exposure, and escrow self-heal
  ([#103](https://github.com/arenzana/arca/pull/103)). Reconstructed from the release history
  rather than written at the time, so it is deliberately a summary and not invented detail.

## [0.7.2] - 2026-07-20

### Fixed
- **Escrow key regex accepts the writer's own keys past sequence 999999 (SEC-43)**
  ([#99](https://github.com/arenzana/arca/pull/99)).
- Opportunistic auto-sync made quiet and non-colliding
  ([#102](https://github.com/arenzana/arca/pull/102)).

### Changed
- Multi-machine sync surfaced on the landing page, plus a fleet setup walkthrough
  ([#95](https://github.com/arenzana/arca/pull/95)), and dependency/action bumps.

## [0.7.1] - 2026-07-10

### Security
- **Hardened the untrusted-backend pull and escrow paths (SEC-35..42)**
  ([#94](https://github.com/arenzana/arca/pull/94)).

### Added
- **`.rpm` and `.deb` packages as release assets** (linux amd64/arm64), built by nfpm inside the
  same goreleaser run — reproducible mtimes, listed in `checksums.txt`, and therefore covered by
  the release's cosign bundle. Install directly with `dnf install ./arca_….rpm` / `dpkg -i`;
  a hosted dnf/apt repo remains a possible follow-up.

## [0.7.0] - 2026-07-09

`arca sync`: first-class multi-machine replication through an untrusted S3-compatible
backend — envelope-encrypted end to end, lost-update-proof via conditional writes,
with automatic mode and off-machine audit escrow (SEC-14, Option B).

### Added
- **The audit trail follows the store off-machine (SEC-14, Option B).** Every sync escrows the
  local audit log's increment as an append-only, age-encrypted segment
  (`audit/<machine-id>/<seq>.age`, create-only on the backend; contents invisible to it). The
  local SQLite log stays the fail-closed operational witness; `log --verify --remote` now checks
  that the local chain still extends its escrowed history — self-tamper evidence a local rewrite
  cannot retract, with segment-to-segment continuity catching backend-side deletions. Escrow is
  best-effort (warn + retry next sync) and never blocks an access.
- **`arca sync` — first-class multi-machine replication through an S3-compatible backend**
  (Cloudflare R2, MinIO, Garage, AWS S3), replacing "keep the store in a git repo" as the only
  sync story. The uploaded envelope is the whole store wrapped in one more age layer to the
  store's recipients, so the backend sees nothing — not even secret names or the JSON shape.
  Pushes are compare-and-swap conditional writes with immutable per-generation revision objects:
  lost updates are impossible, conflicts are reported (never auto-merged), and a rolled-back
  remote is refused (SEC-14 extended to the network side). `sync init URL` pins the backend,
  `sync status` reports both sides, and `sync auto on` enables opportunistic mode — push after
  a mutating command, staleness-based pull — always after the command's real work, never in an
  access path, and never able to fail the command it rides on. Credentials come from the
  environment or, once persisted with `sync init --store-credentials`, from the 0600 state-dir
  config (the age-identity protection class) so automatic sync needs no ambient environment.
  New dependency: `minio-go`; a real-MinIO CI job proves the conditional-write semantics end to
  end. See docs/SYNC.md.

## [0.6.5] - 2026-07-09

Security rebuild — no functional changes.

### Security
- **Rebuilt on Go 1.26.5 for GO-2026-5856** (`crypto/tls`, fixed in 1.26.5). The vulnerable code
  is reachable in arca via `crypto.Decrypt → age.Decrypt → tls.Conn.Read` (age's plugin path),
  and the v0.6.4 binaries were compiled against the affected 1.26.4 standard library. The
  toolchain is now pinned in `go.mod` (`toolchain go1.26.5`), so CI and releases can no longer
  silently build on a stale patch release; the nightly `govulncheck` run is what caught this.

## [0.6.4] - 2026-07-08

Closes every remaining code finding from the 2026-07 security audit (the SEC-06 and SEC-14
residuals, FU-5, FU-6, FU-9), adds externally-storable audit anchors, and moves release
signatures to the Cosign v3 Sigstore bundle format.

### Added
- **External audit anchors close the joint-rollback gap (SEC-14, deeper).** Rolling the store and
  the audit DB back *together* produces a self-consistent older state that no in-DB check can see.
  A successful `log --verify` now prints an **anchor token** (`arca-anchor:v1:<n>:<hash>`) on
  stdout — store it off the machine (password manager, git note, another host) — and
  `log --verify --anchor <token>` additionally fails unless the log still extends that anchored
  head. Anchors are only as strong as the habit: mint and check them regularly.

### Security
- **`generate` refuses `--no-print` together with `--show` (FU-9).** `--no-print` promises the
  value never reaches stdout; `--show` is precisely that disclosure, and previously won. The
  pair is now rejected up front — generate with `--no-print` and consume via `exec`.
- **JSON output is control-character-sanitized, closing the FU-6 gap.** `--json` (ls/show/log/
  stale) and the MCP tool results escape C0 via Go's encoder but let DEL and C1 characters
  through raw — a crafted description or `ARCA_ACTOR` could ride a decoded field (or `jq -r`)
  into a terminal as live control sequences, the same injection SEC-07 strips from the table
  views. Marshaled JSON now passes through a byte sanitizer that drops raw DEL/C1.
- **Legacy cleartext canary flags migrate out of the synced store (FU-5).** SEC-04 moved the
  decoy designation into the local registry, but a pre-0.6.2 store still carried `canary:true`
  in the git-synced file — telling an off-host attacker exactly which secrets are traps. On load,
  arca now copies any legacy flag into the local registry and strips it from the store
  (best-effort; retried on the next load if the registry or save fails).
- **A store rollback is now detectable from the audit log itself, hardening SEC-14.** Every audit
  event records the store generation it observed, bound into the event's hash and signature — a
  tamperer can't edit or strip it without breaking the chain. `log --verify` fails loudly when the
  store's generation is behind the log's audited maximum, or when the log shows a generation going
  backwards (operations continuing against a restored older copy). The load-time high-water-mark
  warning remains as the fast, per-operation heuristic.
- **The audit escape hatches are TTY-anchored, closing the SEC-06 residual.** `ARCA_STRICT_AUDIT=0`
  (best-effort auditing) and `get --no-log` were gated on env-var-based agent detection — advisory,
  since an agent controls its own environment and can scrub the markers. Both are now honored only
  for a non-agent caller **with a controlling terminal** (`/dev/tty` / `CONIN$`), the same anchor
  `--require-approval` uses: a headless caller stays fail-closed and always leaves a read record.
  Headless automation that relied on `ARCA_STRICT_AUDIT=0` should fix its audit DB instead, or run
  the command from a real terminal session.

### Changed
- **Release signatures ship as a single Sigstore bundle** — `checksums.txt.sigstore.json`
  (signature + certificate + Rekor proof) replaces `checksums.txt.sig` + `checksums.txt.pem`.
  Cosign v3 (installed by cosign-installer v4) ignores the deprecated per-file output flags and
  fails outright without a `--bundle` path, which would have broken the next release; caught by
  the new `release-dryrun` workflow before any tag was cut. Updated verify commands are in
  SECURITY.md.

## [0.6.3] - 2026-07-03

Closes the remaining findings from the 2026-07 security audit (SEC-06, SEC-11–15, SEC-17, FU-7),
broadens AI-agent detection, and expands the unit + e2e test suite.

### Added
- **Broader AI-agent detection** for audit attribution and output redaction. Detection is now an
  extensible table: built in are Claude Code, Cursor, **Gemini CLI** (`GEMINI_CLI`), and **OpenAI
  Codex** (`CODEX_SANDBOX`). Any other agent (opencode, Kimi, Aider, Copilot CLI, …) can self-identify
  via `AI_AGENT=name`, or you can register a marker with `ARCA_AGENT_MARKERS="name=ENVVAR,…"`.
  Detection keys only on runtime markers, never on API-key variables, and remains advisory (it does
  not gate approval — see SEC-06).

### Changed
- **`disable`/`enable` are now a dedicated flag, not expiry reuse** (SEC-13). `disable` previously
  suspended a secret by stamping `expires_at` to "now", and `enable` cleared `expires_at` entirely —
  so disabling then enabling a secret that had a *legitimate* future expiry silently wiped it. Disable
  is now a distinct `disabled` field: `disable` sets it, `enable` clears only it, and a real expiry is
  preserved across the round-trip. A disabled secret shows as `DISABLED` in `show` / `[disabled]` in
  `ls` (expired shows as `[expired]`), and the MCP `list_secrets` reports `disabled`. Secrets disabled
  by a pre-0.6.3 arca still read as `EXPIRED` (they were expiry-stamped); clear that with
  `rotate` / `set --expires-at`.

### Security
- **`--require-approval` now requires an interactive terminal, with no environment bypass** (SEC-06).
  Approval was gated by env-var-based agent detection: `ARCA_APPROVAL=allow` pre-approved a release for
  a caller that didn't *look* like an AI agent. But an agent controls its own environment and could
  unset those vars to pass as a human and self-approve. arca now relies on the one thing an agent lacks
  — a controlling terminal (`/dev/tty` / `CONIN$`): a human confirms each release interactively, and
  `ARCA_APPROVAL=allow` is no longer honored (`ARCA_APPROVAL=deny` still refuses). For
  unattended-but-authorized use, issue a scoped `grant`/`handle` rather than marking the secret
  `--require-approval`. Plain secrets are unaffected and fully scriptable.
- **`exec` redaction is forced on for a detected agent even at a PTY** (SEC-11). `--redact auto`
  steps aside for a human at a real terminal, but an agent commonly allocates a PTY to capture
  output — which disabled redaction. A detected agent now always gets its injected values redacted
  from the child's output, regardless of the terminal check.
- **`--no-log` can't evade a rate limit** (SEC-12). Rate limits are counted from the audit log, but
  `get --no-log` skipped the read record — so a human could read a rate-limited secret in a loop and
  never hit the cap. `--no-log` is now ignored (with a note) for a rate-limited secret; it still
  suppresses the record for ordinary secrets, and never suppresses an agent's trail.
- **The store carries a monotonic `generation`, and a rollback is warned about** (SEC-14). The store
  is a git-synced JSON file, so restoring an older copy — a git revert, a sync conflict, or an
  attacker resurrecting a rotated or deleted secret — was previously undetectable. Every write now
  bumps a `generation` counter; on load, arca compares it to a local high-water mark and prints a
  warning if it went backwards (pointing you at the store's git history). It's a warning, not a hard
  stop — the high-water mark is a local heuristic a machine owner can reset.
- **`recipients rm` is honest about revocation, and re-encrypts automatically** (SEC-15). Removing an
  age recipient used to just edit the recipient list and tell you to run `reencrypt` — implying the
  removed key was cut off, when it can still decrypt backups, clones, and every prior version of the
  git-synced store. It now (a) re-encrypts existing secrets to the remaining keys in the same step
  (skippable with `--no-reencrypt`), so the current store immediately stops depending on the removed
  key, and (b) prints an explicit warning that this is **not** revocation of what was already read,
  listing the secrets to `rotate` for true revocation.
- **`CODEOWNERS` requires maintainer review of security-sensitive paths** (SEC-17) — `skills/**`
  (agent instructions shipped downstream), `.github/**`, `.goreleaser.yaml`, and the threat-model /
  security docs. (Enforcement also needs "require Code Owner review" enabled in branch protection.)
- **The MCP run tools refuse a secret too short to redact** (FU-7). Values under 4 characters can't
  be scanned for reliably; on the CLI the skip is warned to the operator, but over MCP that warning
  is invisible and the output goes to the model. `run_with_secrets`/`run_with_handle` now refuse
  rather than risk returning an un-redacted short value.

## [0.6.2] - 2026-07-03

### Fixed
- **Release archives are now byte-reproducible.** `mod_timestamp` pinned only the compiled binary;
  the bundled `LICENSE`/`README`/`CHANGELOG` took their checkout wall-clock mtime, so the `.tar.gz`
  headers differed between two builds of the *same commit* — the underlying reason a duplicate
  release run could diverge the GitHub release from the Homebrew cask. Pinning `archives.builds_info.mtime`
  to the commit date makes two builds of a commit produce identical archive checksums (verified with
  two local snapshot builds), so divergence is now impossible, not just serialized-against.

### Changed
- **`arca version` output is now an aligned key/value table** — the version is a labeled row like
  the others, so every value lines up in one column.

### Security
- **Follow-up hardening from the post-fix verification audit.**
  - **`list_secrets` (MCP) no longer exposes per-secret last-read time** — it advanced when a handle
    was used, letting an agent correlate a before/after `list_secrets` to recover which secret an
    opaque handle wraps (completing SEC-09; the operator keeps full read history via the CLI).
  - **`run_with_handle` re-validates the handle's env-var name** at injection time, so a tampered
    `handles.json` can't inject a reserved name like `LD_PRELOAD` into the child.
  - **`show` sanitizes the secret name it prints** — the one render site the control-char sweep
    (SEC-07) missed.
  - **`rename --force` onto an existing canary clears the stale registry entry**, so the real value
    now at that name doesn't raise a false-positive canary alert.

### Added
- **`annotate` — edit a secret's tags, description, and metadata without touching its value.**
  `arca annotate NAME [--tag …] [--add-tag …] [--rm-tag …] [--desc …] [--meta k=v] [--rm-meta k]`
  changes only the cleartext metadata: it never reads or decrypts the value, so it works on a
  `--no-print` secret (which `set` can't re-label, since `set` re-prompts for the value). `UpdatedAt`
  is left untouched — it tracks the last *value* change — and the edit is recorded as `op=annotate`.

### Security
- **The `audit_log` MCP tool no longer reveals the secret name behind a handle** (SEC-09). A
  handle-issued `exec` records the secret's name with the handle id (`hdl_…`) as caller, so an agent
  could call `audit_log` and read back the `hdl_… → name` mapping the handle exists to hide (even
  though it can't enumerate the store). Those events' name is now masked to the handle id in the MCP
  response. (Secret names remain visible to the agent via `list_secrets` by design; what a handle
  hides is *which* secret it wraps.)
- **Store lock is now ownership-checked, with a heartbeat so a live holder isn't stolen** (SEC-08).
  The lock released by deleting the lock file by path and reclaimed a stale lock with a blind
  unlink, which had two races: a process whose lock was reclaimed could delete its *successor's*
  lock on release, and two processes could both "steal" the same stale lock (→ two writers, the
  lost update the lock exists to prevent). The lock file now carries a per-acquisition token: release
  removes it only if we still own it, and a stale lock is reclaimed by winning an atomic `rename`
  rather than an unlink. A holder also heartbeats the lock's mtime while held, so a live-but-slow
  writer — notably `arca edit` across an interactive `$EDITOR` session — is no longer mistaken for a
  crash and stolen; only a process that has actually stopped ages out.
- **Terminal-control characters are stripped from rendered metadata and audit columns** (SEC-07).
  `ls` / `log` / `show` (and `grants`, `handle ls`, `canary --list`, canary alerts) wrote secret
  descriptions/tags/meta and the audit log's agent/actor/caller/session columns to the terminal
  raw. Those fields are attacker-influenced — a poisoned synced store, or a detected agent setting a
  crafted `$ARCA_ACTOR`/`$AI_AGENT` — so a crafted value could smuggle ANSI/OSC escapes into the
  operator's terminal to spoof or hide audit rows, rewrite the display, or set the window title.
  Untrusted fields are now sanitized (C0/C1 controls, DEL, ESC dropped) before rendering; arca's own
  colors, applied to trusted strings afterward, are unaffected.
- **Handle creation is operator-only and won't silently launder past an approval/grant gate**
  (SEC-05). `run_with_handle` intentionally bypasses the `--require-grant`/`--require-approval`
  gates (the handle *is* the operator's pre-authorization), but `handle create` only checked that
  the secret existed — so a detected agent could mint itself a handle and use it to get exactly the
  authorization those gates withhold. `handle create` now (1) refuses when the caller looks like an
  AI agent, mirroring the agent-can't-self-approve invariant, and (2) requires an explicit
  `--override` to mint a handle for a `--require-approval` or `--require-grant` secret, recording it
  as a distinct `handle-override` audit event.
- **Canary designation is no longer stored in the synced store** (SEC-04). The "this is a decoy"
  flag used to be a cleartext `canary` field in `store.json` — so anyone who obtained the store (the
  exact exfiltration a canary exists to catch) could tell the decoys from the real secrets and step
  around them. It now lives in a local registry (`$XDG_STATE_HOME/arca/canaries.json`), never synced;
  the decoy's value remains an ordinary-looking store entry. Canaries planted before this release
  keep working (the legacy store flag is still honored), and re-running `arca canary NAME` migrates
  the designation into the private registry. Trade-off: the registry is local, so a canary is armed
  per-machine — plant it on each machine where arca runs.

### Fixed
- **Release pipeline no longer ships a Homebrew cask whose checksums don't match the release.** A
  single `v*` tag push can be delivered twice, and with no `concurrency` guard two goreleaser runs
  raced: since the archives aren't byte-reproducible, the GitHub release and the cask ended up with
  checksums from *different* builds, so `brew upgrade` failed on a SHA-256 mismatch (hit on v0.6.1;
  the cask was corrected out-of-band). The release workflow now serializes by tag ref
  (`concurrency` with `cancel-in-progress`) so exactly one build publishes a tag, and a post-publish
  step verifies the pushed cask's checksums against the release, failing loudly on any divergence.

## [0.6.1] - 2026-07-02

### Security
- **Reserved environment-variable names are refused as secret names** (SEC-01). A name that is a
  valid identifier but would hijack a child process when injected — `PATH`, `LD_PRELOAD`,
  `DYLD_*`, `IFS`, `BASH_ENV`, `PROMPT_COMMAND`, `PYTHONPATH`, `NODE_OPTIONS`, and kin — is now
  rejected on write and re-checked (case-insensitively) at every injection site (`exec`, `env`,
  `run_with_secrets`, `handle`). Previously the shape check let these through, so anyone able to
  write the (git-synced) store could plant a correctly-encrypted `LD_PRELOAD` entry and get code
  execution on the operator's next `arca exec`. The store keeps recipient public keys in cleartext,
  so this needed no private key.
- **`edit` no longer exposes a `--no-print` secret** (SEC-02). `edit` gated the access but never
  checked `--no-print` before decrypting and handing the plaintext to `$EDITOR` — and the caller
  controls `$EDITOR` (`EDITOR=cat`, `EDITOR='cp {} …'`), so `arca edit` was a read primitive that
  `get`/`inject`/`env`/`read_secret` all refuse. It now refuses a `--no-print` secret and points to
  `rotate` (which replaces the value without revealing the old one).
- **`log --verify` no longer returns a false green after the audit log is rewritten** (SEC-03).
  Three ways a DB-writer could fake a clean verification are now refused instead of reported as
  benign: (1) a *legacy downgrade* that NULLs every row's hash so the chain walk skips them — a
  born-chained DB is recorded in `PRAGMA user_version`, so a legacy row appearing later fails; (2)
  deleting the `audit_head` row (the truncation anchor) — a missing head on a chained DB fails; (3)
  *signature stripping* — unsigned chained rows are now counted and shown, and the new
  `log --verify --require-signed` fails when any chained event is unsigned. `recordAudit` also warns
  on stderr when it has to record an unsigned event (previously silent), since a silently-unsigned
  event is indistinguishable from a stripped one at verify time.

## [0.6.0] - 2026-07-01

### Added
- **`arca version` subcommand.** Prints the version, VCS commit, build date, Go toolchain, and
  platform (with `--json` for scripts/agents); `arca --version` still prints just the version.
- **Shippable agent skill.** `skills/arca/SKILL.md` teaches an AI agent arca's "use, don't reveal"
  workflow and audited MCP tools; `skills/README.md` covers installing it and registering the MCP
  server. See [skills/](skills/).

### Fixed
- **Releases no longer strand as an unpublished draft when SLSA provenance flakes.** The
  build-provenance attestation (supplementary — every asset is already cosign-signed) is now
  best-effort (`continue-on-error`), so a transient Sigstore/Rekor outage can't block the final
  publish step. (A v0.5.0 release was stranded as a draft this way and published manually.)

## [0.5.0] - 2026-07-01

### Added
- **`disable` / `enable` — a fast, reversible kill switch.** `arca disable NAME` suspends a secret
  on every access path (`get`, `exec`, `inject`, `env`, MCP) without deleting it or changing its
  value; `arca enable NAME` restores it. Implemented over the existing hard-expiry mechanism (no
  store-schema change), so a disabled secret reads as `EXPIRED` in `show`/`ls` and the audit log
  records the `disable`/`enable` intent. It's a *local* kill switch — revoke at the issuer for a
  real compromise.
- **Styled output.** `log`, `ls`, `grants`, and `handle ls` render as color-coded tables on a
  terminal — bold teal header, dimmed timestamps, ops tinted by kind (hand-rolled ANSI, no new
  dependency) — and fall back to plain tab-separated columns when the output is piped, so scripts
  stay parseable.
- **MCP capability handles.** `arca handle create SECRET --ttl 1h [--command 'psql *'] [--as ENV]`
  mints an opaque token (`hdl_…`) that lets an agent *use* a secret through the new MCP
  `run_with_handle` tool — inject it into a command — without learning the secret's name or value,
  and without being able to enumerate the store. The handle carries the command scope, expiry, and
  the env-var name the value is injected under. `arca handle ls` / `revoke` manage them.
- **Per-secret rate limiting.**

### Fixed
- **`env` no longer aborts on one unusable secret.** `arca env` (used by `eval "$(arca env)"`)
  previously bailed out entirely on the first expired/disabled or `--require-grant` secret, blanking
  *every* export. It now skips secrets it can't release in a no-command context — matching how it
  already skips `--no-print` — and still surfaces interactive approval denials as errors.
- **MCP `run_with_secrets` now redacts the command's output** (like `arca exec`) before returning
  it to the agent — previously it returned the raw combined output, so a command that printed an
  injected secret leaked it straight into the model's context. `set`/`generate --rate N/DURATION` (e.g. `--rate 10/1h`) caps how
  often a secret may be *used* (read/exec/env/inject) within a rolling window. Once the cap is
  reached the access is refused and the throttle is recorded (`op=ratelimit`); a note warns on the
  last permitted use. The count is computed from the audit log, so it needs no extra state. Shown
  by `show`; clear it with `--rate ""`. Heuristic by design — a patient caller can spread use out.

## [0.4.0] - 2026-07-01

### Added
- **Command-scoped, just-in-time grants.** Mark a secret `--require-grant` and it becomes usable
  only via `exec`/MCP `run_with_secrets`, and only when a matching `grant` is active. `arca grant
  SECRET --command 'terraform *' --uses 3 --ttl 15m [--agent claude-code]` binds a secret to
  *what* an agent does, how many times, and for how long; `grants` lists them and `revoke` removes
  one. Use counts are derived from the tamper-evident audit log (op=exec since the grant), so they
  can't be rolled back. The command match is argv-based — a guardrail expressing intent, not a
  sandbox (see SECURITY.md).
- **Canary (honeytoken) secrets.** `arca canary NAME --template stripe|github|aws|slack|generic`
  plants a realistic-looking decoy; `set`/`generate --canary` mark an existing secret. Any *use*
  of a canary (get/exec/env/inject/MCP) trips a loud stderr alert and a distinct, signed audit
  event (`op=canary`), turning the audit log into active leak detection rather than passive
  forensics. `arca canary` (no args) lists canaries and whether each has been tripped.
- **Tamper-evident audit log.** Every event is hash-chained into the previous one and signed
  with the recording session's Ed25519 key (generated and stored per session under the state
  dir), so editing, deleting, reordering, or truncating the log is detectable. `arca log
  --verify` walks the chain and signatures and exits non-zero on any inconsistency (cron/CI
  friendly). The audit schema migrates existing DBs in place; pre-chain rows are reported as
  legacy. It's tamper-*evident*, not tamper-proof — see SECURITY.md for the boundary.
- **Output redaction on `exec`** — if a command prints an injected secret, arca replaces the
  value with `«arca:NAME»` in the captured stdout/stderr before it reaches whoever is reading
  (an AI agent, a log), and records the catch in the audit log (`op=redact`). It's streaming
  (a value split across writes is still caught) and on by default for captured output, stepping
  aside for an interactive terminal. `--redact on|off` forces the behavior; `--reveal` shows a
  partial mask of long values instead of the name. Values under 4 characters aren't scanned.
- `STABILITY.md` — the v1.0 SemVer policy: which surfaces (commands, exit codes, store schema,
  `arca://` references, `ARCA_*` config, `--json` output, MCP tools) are stable, and what isn't.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and issue/PR templates.
- `MAINTAINERS.md` — maintainers, roles, and who holds access to sensitive resources.
- `docs/ARCHITECTURE.md` — design documentation (actors, components, and the agent-aware
  policy invariant) and `docs/THREAT-MODEL.md` — the documented security assessment.
- Developer Certificate of Origin: a `Signed-off-by` trailer is now required on every commit
  and enforced by a `dco` CI check; `CONTRIBUTING.md` documents `git commit -s`.
- `CONTRIBUTING.md` now documents how dependencies are selected, obtained, and tracked.
- `import --json` reads a JSON object `{"KEY":"value"}` from stdin — the shape most secret
  stores emit (AWS Secrets Manager, Vault, 1Password, gcloud) — so they pipe in without `jq`
  reshaping. String values pass through (a JSON-escaped multi-line key round-trips), numbers and
  booleans are stringified, and null/nested values are skipped.
- An "Importing & migrating" guide in the README, with a source recipe matrix and `set NAME <
  file` for single multi-line blobs (PEM keys, service-account JSON).
- `import` flags: `--dry-run` (preview without writing), `--overwrite` (replace existing
  secrets), `--prefix` (namespace imported names), and `--tag` (attach tags on import).

### Changed
- `import` now records each imported secret in the audit log, so a bulk load is no longer a
  blind spot — it was previously the only write that wrote nothing to the log.
- `import` now **skips a name that already exists** by default instead of silently overwriting
  it; pass `--overwrite` to restore the previous replace-in-place behavior.
- Increase the store-lock acquisition timeout from 5s to 15s, so heavily contended writes
  (many concurrent processes, or a slow/networked filesystem) don't spuriously fail before
  acquiring the lock.

## [0.3.0] - 2026-06-30

### Added
- `generate NAME` creates a secret with a cryptographically-random value (`--length`,
  `--charset alnum|hex|full|<custom>`, `--show`), so a password/token is never typed.
- `edit NAME` opens a secret's value in `$EDITOR` and re-encrypts it on save (the plaintext
  touches a `0600` temp file, scrubbed and removed afterward).
- `rename OLD NEW` (alias `mv`) renames a secret while preserving its metadata and history.
- Homebrew install via a tap: `brew install arenzana/tap/arca` (the cask is published to
  `arenzana/homebrew-tap` on each release).
- Scoop install on Windows (the manifest is published to `arenzana/scoop-bucket` on release).
- `go install` builds now report the module version (from build info) instead of `dev`.
- Windows support for the approval prompt: `--require-approval` now reads from the Windows
  console (`CONIN$`/`CONOUT$`) instead of `/dev/tty`, which does not exist on Windows.
- Store-level locking: every mutation (`set`/`rotate`/`rm`/`import`/`reencrypt`/`recipients`)
  takes an exclusive lock around its read-modify-write, so concurrent writers can no longer lose
  an update. A lock left by a crashed process (older than 30s) is reclaimed automatically.
- Schema-migration framework: an older store is upgraded to the current schema on load, so a
  future incompatible change can ship a migration rather than break existing stores. A store
  with no version field is treated as the v1 baseline.

### Changed
- CI now runs the unit and end-to-end suites on Linux, macOS, and Windows (previously Linux
  only; release targets were cross-compiled but never tested).

## [0.2.0] - 2026-06-30

### Added
- TTL / ephemeral secrets: `set --ttl 30m|12h|7d|2w` or `--expires-at`; an expired secret is
  refused on every access path and surfaced by `stale`.
- JSON output: `--json` on `ls`, `show`, `log`, and `stale`.
- Shell completion with dynamic secret-name and tag suggestions.
- Multi-recipient / teams: `recipients add`/`rm` plus `reencrypt` to re-wrap the whole store to
  the current age recipient set.
- MCP server (`arca mcp`): lets an agent use secrets through audited tools without the value
  entering the model context.

### Security
- Secret-name validation blocks shell injection via `eval "$(arca env)"` and `LD_PRELOAD`-style
  environment hijacking.
- Agent-aware policy: a detected AI agent cannot self-approve a `--require-approval` secret,
  suppress its own read record, or weaken fail-closed auditing.
- Store hardening: reject null, oversized, or newer-versioned store files; bounded stdin reads;
  the private key is created with `O_EXCL`; the store is fsynced before the atomic rename.
- Release pipeline runs `vet`/`test`/`govulncheck` before building; the cosign certificate is
  published alongside the signature; build provenance covers `checksums.txt`.
- CI gained a `gosec` + `staticcheck` lint job, and CodeQL now scans the workflows themselves.

## [0.1.0] - 2026-06-29

### Added
- Initial release: age-encrypted per-value secrets with cleartext metadata in a single JSON
  store, and a local SQLite audit log of every access attributed to the calling AI agent.
- Commands: `init`, `set`, `get`, `rotate`, `ls`, `show`, `stale`, `rm`, `import`, `inject`,
  `exec`, `env`, `log`.
- Per-secret policy: `--no-print` (exec-only) and `--require-approval` (human gate).
- `arca://NAME` references resolved by `inject`; least-privilege `exec --only`.
- Fail-closed auditing by default; agent name/version/session auto-detection.
- Supply chain: reproducible static builds, cosign keyless signatures, SLSA build-provenance,
  CycloneDX SBOM, govulncheck, CodeQL, OpenSSF Scorecard, SHA-pinned actions.

[Unreleased]: https://github.com/arenzana/arca/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/arenzana/arca/compare/v0.9.2...v0.10.0
[0.9.2]: https://github.com/arenzana/arca/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/arenzana/arca/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/arenzana/arca/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/arenzana/arca/compare/v0.7.2...v0.8.0
[0.7.2]: https://github.com/arenzana/arca/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/arenzana/arca/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/arenzana/arca/compare/v0.6.5...v0.7.0
[0.6.5]: https://github.com/arenzana/arca/compare/v0.6.4...v0.6.5
[0.6.4]: https://github.com/arenzana/arca/compare/v0.6.3...v0.6.4
[0.6.3]: https://github.com/arenzana/arca/compare/v0.6.2...v0.6.3
[0.6.2]: https://github.com/arenzana/arca/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/arenzana/arca/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/arenzana/arca/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/arenzana/arca/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/arenzana/arca/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/arenzana/arca/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/arenzana/arca/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/arenzana/arca/releases/tag/v0.1.0
