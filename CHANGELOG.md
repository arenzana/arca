# Changelog

All notable changes to arca are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches 1.0.

## [Unreleased]

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

[Unreleased]: https://github.com/arenzana/arca/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/arenzana/arca/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/arenzana/arca/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/arenzana/arca/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/arenzana/arca/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/arenzana/arca/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/arenzana/arca/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/arenzana/arca/releases/tag/v0.1.0
