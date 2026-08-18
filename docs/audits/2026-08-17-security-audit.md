# Security audit — 2026-08-17

External-style audit of the arca codebase (post-0.10.2, commit `d8b7cec`), performed by an
independent agent that did not write the code under review. Four parallel review streams covered
the crypto/key-management, exec/agent-policy, MCP-server, and sync/filesystem surfaces, followed
by automated checks.

**Automated checks:** `go vet ./...` clean. `govulncheck ./...` reports no reachable
vulnerabilities; the only module-level advisory is GO-2026-5932 (`golang.org/x/crypto/openpgp`
unmaintained) — arca does not import `openpgp`.

**Overall verdict:** the codebase is well-hardened against its stated threat model (SEC-01…SEC-43
annotations, fail-closed auditing, terminal-anchored control plane, atomicfile discipline, tests
that mirror the threat model). The audit found **2 High**, **9 Medium**, and a batch of
Low/Info findings. The two High findings each break a headline security property under realistic
preconditions; remediation plans for both are in
[2026-08-remediation-plan-H1-H2.md](2026-08-remediation-plan-H1-H2.md).

---

## High

### H1 — Pulled stores have no writer-authentication: the "untrusted backend" claim does not fully hold
**sync.go:820–874 (`pullStore`), acknowledged in code comments and docs/SYNC.md**

age provides confidentiality, not authentication, and the store's recipient public keys are
cleartext metadata in `store.json` — a file the documented workflow commits to a (possibly
hoster-readable) git repo. All pull-side refusals (rollback floor via `store.gen` HWM,
head-vs-envelope generation check, recipient-broadening refusal) key on values **inside** the age
envelope.

A malicious backend operator who obtains the recipient public keys (read access to the dotfiles
repo, a former teammate, `who-can-read` output) can build a fresh store JSON: recipients unchanged
(passes broadening check), `generation` = HWM+1 (passes rollback floor), old rotated secret values
spliced back in from revision objects it already hosts, and every policy field stripped
(`no_print`, `require_approval`, `require_grant`, `rate_limit`, `expires_at`, `disabled`). Sealed
to the known recipients and installed as head, the next `arca sync` pulls it with **zero
warnings**, atomically replacing the local store on every machine.

The code comments and SYNC.md disclose this ("treat the backend as honest-but-curious today;
operator signature planned"), but severity stays High because the preconditions are close to free
in the documented deployment. **Plan:** see the remediation plan — add an operator-held Ed25519
signature over the store payload, verified on pull against a locally pinned signer key.

### H2 — MCP `audit_log` tool bypasses strict-mode allowlist and leaks hidden secret names
**mcp.go:432–462 (`mcpAuditLog`); cleartext-name writes at e.g. cmd_secrets.go:88, cmd_rotate.go:81, manage.go:178**

`mcpAuditLog` never consults `agentDenied()`. Audit events record secret **names in cleartext**
for every op; the only masking applied is for `hdl_`-caller events (SEC-09). Under
`arca mcp --strict`, an agent that sees zero secrets via `list_secrets` can call `audit_log {}`
and enumerate every secret the operator has ever touched through the CLI — names, timestamps, ops,
actors, sessions — including secrets deliberately not exposed. The `name` filter turns it into a
targeted existence/history probe. This silently defeats deny-by-default for metadata.
**Plan:** see the remediation plan — filter events through the same exposure rule as
`list_secrets`, with adjacent fixes M5/M6 folded in.

---

## Medium

### M1 — Terminal-escape injection into approval/operator prompts
**main.go:663 (`approve`), main.go:673–689 (`approverWho`), grants.go:176–177, operator.go:333**

Agent-controlled strings (`$AI_AGENT`, session IDs, grant names/commands) are printed
**unsanitized** to `/dev/tty` in the exact prompts the human gate relies on — while the same
strings are sanitized everywhere else they reach the terminal (SEC-07: `tripCanary`, `cmd_log.go`
tables). An agent setting `AI_AGENT=$'\x1b[2J\x1b[H…'` can clear/redraw the operator's terminal so
the operator answers `y` to a prompt they never saw. This attacks the load-bearing control
(SEC-06) itself. Fix: pass all attacker-influenced prompt components through `sanitize()`/`%q`.
**Cheapest high-value fix in this report.**

### M2 — Escrow segment authentication rests on a non-secret anchor
**escrow.go:207–231 (`reconcileEscrowCursor`), 271–318 (`fetchEscrowedSegments`), 336–348 (`verifyAgainstEscrow`); enabled by cmd_log.go:152–157**

Escrow segments are age-*encrypted* (to public recipients — anyone can encrypt) but **not signed**.
The only binding to the real chain is `PrevAnchor` continuity plus `CheckAnchor(tail.Anchor)`,
and anchors are printed to stdout on every `log --verify` — low-secrecy in a deployment whose
agents capture stdout. Given one genuine past anchor, a backend attacker can (a) serve a fully
fabricated, self-consistent segment history whose events are never recomputed against the anchor,
passing `log --verify --remote`; and (b) freeze future escrow silently by winning the
`PutIfAbsent` race with a forged segment whose `LastID` is huge — `reconcileEscrowCursor` adopts
it with no sanity check against the local log's max ID, after which `escrowOnce` becomes a
permanent no-op while verification keeps passing. Fix directions: stop printing anchors to
agent-visible stdout; re-chain each segment's rows against its claimed anchor; reject
`tail.LastID` greater than the local max row id during reconcile.

### M3 — Grant MaxUses / rate-limit check-then-record TOCTOU
**grants.go:114–134, consumed at cmd_run.go:180–191 and mcp.go:271–282; same shape in main.go:746–765 (`checkRateLimit`)**

Grant use-counting derives from the audit log (`CountOpSince`), but the check and the
after-the-gate `logAudit` are separate SQLite transactions. N concurrent `exec` /
`run_with_secrets` calls against a `--uses 1` grant (or a `--rate 1/1h` secret) all observe
`used=0`, all pass, all run. Fix: perform check-and-record in one `BEGIN IMMEDIATE` transaction
(insert the event first, count, abort on excess), or take a per-secret mutex across gate+audit.

### M4 — Grant `--agent` restriction is spoofable
**grants.go:106–110 vs main.go:498–543 (`detectIdentity`)**

Agent scoping of grants rests on environment sniffing: any process can run `CLAUDECODE=1 arca
exec …` and satisfy a `--agent claude-code` grant. The rest of the codebase correctly treats this
detection as advisory; `grants.go:92–93` claims "the agent/uses/expiry checks are firm" — the
agent check is not. Either drop the claim in docs or treat agent scoping as display-only.

### M5 — MCP existence oracle via distinguishable error messages
**mcp.go:191–196 (`show_secret`), 212–217 (`read_secret`), 261–266 (`run_with_secrets`)**

All three handlers check `sec == nil` → `"no such secret: NAME"` *before* `agentDenied(...)` →
`"not exposed to agents…"`. Under `--strict` the two messages partition the namespace: an agent
can dictionary-probe candidate names and map the hidden store even with H2 fixed. Fix: in strict
mode return the same "not exposed" message for nil and denied (reorder the checks).
Folded into the H2 remediation plan.

### M6 — MCP `audit_log` limit overflow → unbounded full-log dump
**mcp.go:433–436, internal/audit/audit.go:652–653**

`limit` is read as `float64`, gated only on `v > 0`, then `int(v)`. Out-of-range float→int is
implementation-defined: on amd64 it yields a negative, which SQLite treats as `LIMIT -1` = no
limit. `audit_log {limit: 1e18}` returns the entire audit database in one tool result. Fix: clamp
(`min(limit, 500)`) before conversion. Folded into the H2 remediation plan.

### M7 — Sync backend credentials inherited by every exec'd/MCP child
**cmd_run.go:163, mcp.go:257, mcp.go:416 (all `env := os.Environ(); append(...)`)**

`ARCA_SYNC_ACCESS_KEY`/`ARCA_SYNC_SECRET_KEY` and the `AWS_*` fallbacks flow into every child
environment; the redact writer only scans for *injected* secret values, so a child running
`printenv` exfiltrates live backend keys unredacted into an agent's context. With H1 unfixed,
stolen keys + public recipients = full store substitution; even with H1 fixed, stolen keys allow
backend vandalism (delete revisions/escrow, wedge the head). Fix: scrub `ARCA_SYNC_*`/`AWS_*`
from child environments in `exec` and MCP, or document + warn loudly at `sync` setup.

### M8 — Store JSON parser silently drops unknown fields: policy downgrade via forward-compat
**internal/store/store.go:104–133 (`Decode`)**

`json.Unmarshal` without `DisallowUnknownFields`. The `Version > 1` gate only fires if a future
schema bumps the version; adding a new *policy field* does not. An older arca that loads and
re-saves such a store (any `set`/`rotate`/`edit`, or a sync pull followed by a local mutation)
silently strips the unknown policy fleet-wide. Related, minor: duplicate JSON keys parse
last-wins, so a hand-edited/hostile store can smuggle two spellings of a policy field past a
human review of the first. Fix: `DisallowUnknownFields` (breaking, needs migration care) or
preserve-and-pass-through unknown fields.

### M9 — `reencrypt` prompt doesn't enumerate recipients; drift warning fires only after confirmation
**recipients.go:327–343**

RunE order is `requireOperator(...)` → `lockStore()` → `openStore()` (which calls
`warnIfRecipientsChanged`). Unlike `recipients add`/`pin` (which enumerate the keys in the
prompt), `reencrypt` — the payload step of a recipient-injection attack, per its own comment —
asks a bare yes/no, and the one-line drift warning appears on stderr milliseconds *after*
confirmation, before every secret is wrapped to the drifted key. Fix: include the recipient set
in the prompt and run the drift check before `requireOperator` returns success.

---

## Low

| # | Location | Finding |
|---|---|---|
| L1 | internal/audit/audit.go:141–167 | Audit DB created at process umask before the best-effort chmod; WAL/SHM sidecars (which carry the event rows) never chmod'd at all. Bites when `$ARCA_AUDIT` points outside the 0700 state dir. |
| L2 | internal/atomicfile + statedir.go | State dir perms are create-only (`MkdirAll` 0700 is a no-op on a pre-existing dir); nothing — including `doctor` — checks the state dir's own mode. A pre-existing 0755 dir exposes every 0600 inside, incl. `sync.json` credentials. |
| L3 | sign.go:47–63 | Session seed silently regenerated on a corrupt/truncated file → every prior event for that session id fails verification — a permanent *false* tamper alarm that trains the operator to discount real ones. Write is also non-atomic (all other state writers use atomicfile). |
| L4 | cmd_run.go:163, mcp.go:257 | Injected env vars are appended, not replaced: a pre-existing same-name variable shadows the secret under glibc first-match `getenv` semantics (Python keeps the last — runtime-dependent). Confused-deputy: child uses the wrong value while the audit log claims a release. |
| L5 | internal/secretname | Reserved env-name gaps: `HOME`, `SHELL`, `TMPDIR`, `XDG_*` are the same hijack class as already-blocked entries (requires store-write access, which the model treats as semi-trusted). |
| L6 | redact.go:96–137 | Redaction is exact-bytes only: base64/URL-encoded/JSON-escaped renderings of a secret evade it. Inherent boundary of stream redaction — document the evasion class explicitly. |
| L7 | main.go:664 | `approve()` lacks the 5s bounded-input timeout `requireOperator` has (operator.go:113–132); a held-open pty wedges `--require-approval` execs forever. Fails closed; share the existing helper. |
| L8 | sync.go:507,736,845,863,870 | `--force` bundles four distinct overrides (rollback refusal, tamper refusal, HWM floor, recipient-broadening). The common legitimate use (admit a teammate's key) silently accepts a rolled-back/replayed store in the same motion. Split the flags. |
| L9 | escrow.go:188,280 | Escrow segment ordering is lexical (`%06d` + `sort.Strings`): past segment 999999 continuity breaks permanently (`"1000000.age" < "999999.age"`). Numeric sort on parsed seq. |
| L10 | cmd_import.go:29–52 | dotenv import has no total size cap (per-line only; the JSON path caps at 16 MiB); quote-stripping corrupts values that legitimately begin/end with quotes (stores an altered secret silently); JSON numbers lose precision via float64. |
| L11 | sign.go, main.go:498–533 | Session-signature binding is "this unix user", not "this session": all session keys are same-uid-readable, and an agent that scrubs its markers signs as `local`. Docs should state this precisely. |
| L12 | statedir.go:258–278, 214 | Adoption lock uses blind-unlink stale reclaim (the races lock.go fixed); `adopted-by` claim written non-atomically. |
| L13 | sync.go:518–555 | `sync reset-escrow` is unanchored and orphans the prior off-machine witness (`--remote` only lists under the current machine-id). Consider anchoring it and warning when prior prefixes exist. |
| L14 | internal/crypto/age.go, sign.go | No best-effort zeroization of plaintext/key material (largely a Go limitation; `rlimit_unix.go` already shows core-dump awareness — wipe the easy buffers). |

## Info

- **Audit tamper-evidence vs same-UID attacker** (internal/audit, sign.go): signing keys live in
  the same state dir and the signer table is inside the verified DB, so a local attacker can
  rewrite and re-sign history cleanly. Documented honestly as tamper-*evident*; the external
  anchor + escrow are the sanctioned mitigations — which is why M2 matters. A fully-NULLed legacy
  DB verifies as `OK` with 0 chained events; that caveat could be louder.
- **`insecure=1`** (internal/remote/s3.go:48): SigV4 credentials over plaintext HTTP with no
  warning; a one-line stderr notice on first use would close the "forgot it in the pinned URL"
  case.
- **Backend that strips user-metadata wedges sync** with a false "ROLLBACK detected" (s3.go:117,
  sync.go:736); the pull path handles the same situation gracefully, the Head path doesn't.
- **MCP exec accounting**: `exec` is logged before `tooShortToRedact` refusal / `cmd.Run()`
  (mcp.go:274–286) — a refused run still consumes grant/rate budget; a patient agent can also
  grow the audit DB indefinitely since tool calls aren't rate-limited.
- **MCP inbound stdio has no message-size bound** (mcp-go `ReadString` uncapped): one multi-GB
  JSON-RPC line grows the server's heap without limit. Wrap stdin with a capped reader.
- **`read_secret` returns the raw value unsanitized** (mcp.go:236) — intended disclosure path,
  but C0/C1 sequences ride into whatever renders tool results; invalid UTF-8 breaks client JSON.
- **Handles**: sound (96-bit CSPRNG, merged unknown/revoked error, kill-switch/expiry/rate-limit
  re-checked at use), but no use-count bound (TTL-only) — a documented asymmetry vs grants.
- **Audit `caller` records only the executable basename**, not argv — forensically thin for
  `sh -c …` invocations.
- **Store reads follow symlinks; writes replace them** (safe direction). Same-UID/misconfiguration
  only.
- **`edit` temp-file scrub follows a replaced symlink** (manage.go:104–109); `$EDITOR` is
  operator-controlled, so self-inflicted only.
- **Bare `arca exec` sweep consumes rate-limit/grant budget for every releasable secret** —
  fail-closed but a surprise-exhaustion vector; `--only A,A` double-counts.

---

## Done well (verified — keep as invariants)

- **No shell in the exec path**; secrets never in argv (values come from TTY/stdin only); env-name
  validation (incl. `LD_*`/`DYLD_*` prefixes, case-insensitive reserved list) re-checked at every
  injection site, including MCP handles — a poisoned store can't smuggle `LD_PRELOAD` into a child.
- **Terminal-anchored control plane**: loosening operations (`grant`, `agent allow`,
  `handle create`, `recipients add`, policy downgrades) require a human on the controlling
  terminal with a bounded timeout and **no env bypass** (regression-tested); tightening paths stay
  headless so incident response is never gated. Policy-downgrade detection compares *effective*
  rates/expiries, not flag spellings.
- **Grant design**: TTL mandatory; use-count derived from the tamper-evident log rather than a
  mutable counter; issuance prompt shows full scope.
- **Handles**: 96-bit CSPRNG ids; mandatory TTL; minting requires the operator anchor; `--override`
  is explicit, warned, and audited as a distinct op; kill-switch/expiry/rate-limit/canary
  re-checked at use time; audit view masks the hdl→name mapping.
- **Redaction architecture**: hold-back tail for cross-write splits; byte cap downstream of
  redaction; longest-match-first; MCP *refuses* un-redactably short values instead of warning.
- **Audit log**: parameterized queries; `BEGIN IMMEDIATE` head-read+append; genesis anchor;
  per-event Ed25519 session signatures; store-generation binding; fail-closed *before* disclosure.
- **`internal/atomicfile`**: textbook — chmod-before-write, fsync, rename, parent-dir fsync with
  an accurate error. **`lock.go`**: token + rename-steal closes both classic stale-lock races.
- **Sync Phase A/B**: no backend call under the store lock; byte-exact CAS on store and cursor;
  immutable `If-None-Match` revision objects; read-after-write confirmation detecting backends
  that silently ignore conditional headers.
- **Recipient pin** correctly distinguishes "accept exactly these keys" from "accept the store's
  current set"; recipient broadening on pull is a hard refusal; `recipients rm` auto-reencrypts.
- **Crypto hygiene**: correct age API usage; `crypto/rand` everywhere; no custom primitives;
  error messages name secrets but never echo values; untrusted strings sanitized before terminal.
- **Tests mirror the threat model** — the invariants are enforced by tests, not just comments.

## Suggested fix order

1. ~~**M1** — sanitize prompts~~ **Fixed** (Unreleased): `approve` / `approverWho` / `requireOperator` / `grantScope` now sanitize every attacker-influenced fragment before writing to `/dev/tty`.
2. ~~**H2 + M5 + M6** — MCP strict-mode trio~~ **Fixed** (Unreleased).
   → [remediation plan](2026-08-remediation-plan-H1-H2.md)
3. ~~**M3** — atomic grant/rate check-and-record~~ **Fixed** (Unreleased): use events count their rate and grant-uses caps inside the same `BEGIN IMMEDIATE` as the append.
4. ~~**M7** — scrub backend credentials from child environments~~ **Fixed** (Unreleased): inherited `ARCA_SYNC_*` / `AWS_*` credential vars are stripped from `exec` and MCP children; an explicit `--only` injection still wins.
5. ~~**H1** — operator store signatures~~ **Fixed** (Unreleased): push signs; pull verifies against a locally pinned key; escrow segments are signed and verified when a pin exists.
   → [remediation plan](2026-08-remediation-plan-H1-H2.md)
6. ~~**M2, M8, M9** — escrow authentication, unknown-field policy, reencrypt prompt~~ **Fixed** (Unreleased), except escrow *signing* (H1 follow-up).
7. Low/Info hygiene batch — **Fixed** (Unreleased): L1–L5, L7–L10, L12–L14 in code; L6/L11 documented; Info items for MCP accounting/stdin/UTF-8, insecure=1, stripped-metadata Head, and --only double-count fixed. Remaining Info items are documented boundaries.
