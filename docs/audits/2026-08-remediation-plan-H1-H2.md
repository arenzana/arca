# Remediation plan — H1 (store signatures) and H2 (MCP audit_log strict filtering)

Source: [2026-08-17 security audit](2026-08-17-security-audit.md). This plan covers the two High
findings. H2 is a small, self-contained change; H1 is an architectural addition with a migration
story. They are independent and can ship in either order; H2 first is recommended (smaller,
higher immediacy). M5 and M6 are folded into the H2 change because they touch the same handler
and its three sibling handlers.

---

## H2 — MCP `audit_log` must enforce strict-mode exposure (plus M5, M6)

### Problem

`mcpAuditLog` (mcp.go:432–462) returns cleartext secret names, timestamps, ops, actors, and
sessions for **every** secret the operator has ever touched, with no `agentDenied()` check. Under
`--strict` this silently defeats deny-by-default for metadata: an agent that sees zero secrets
via `list_secrets` can enumerate the hidden store, or probe a specific name's existence and
history via the `name` filter.

Adjacent defects in the same patch area:

- **M5** — `show_secret` / `read_secret` / `run_with_secrets` (mcp.go:191–196, 212–217, 261–266)
  check `sec == nil` ("no such secret") *before* `agentDenied(...)` ("not exposed"), giving a
  clean existence oracle over the hidden namespace.
- **M6** — `audit_log`'s `limit` (mcp.go:433–436) is `int(float64)` with only a `v > 0` gate;
  out-of-range conversion yields a negative on amd64 → SQLite `LIMIT -1` → unbounded full-log
  dump.

### Design

1. **Filter, don't refuse.** Under `--strict`, `audit_log` keeps working but returns only events
   for exposed secrets. Refusing the tool outright would break legitimate debugging of *allowed*
   secrets; filtering preserves function without disclosure. (Non-strict mode is unchanged.)
2. **Filter rule.** Load the store once per call (the other MCP handlers already do this).
   For each event:
   - `hdl_`-caller events: keep the existing SEC-09 masking (name → handle id) and return them —
     the caller already holds the handle. (A handle implies the operator exposed *something*.)
   - Events with an empty `Name` (non-secret ops): keep — they carry no secret metadata.
   - Otherwise: keep only if `store.Secrets[name].AgentExposed` (lookup via the existing store;
     a name absent from the store — e.g. an `rm`'d secret — is **not** exposed → drop).
3. **`name` filter:** under `--strict`, if the requested `name` is empty, exposed, or a `hdl_`
   id, proceed; otherwise return the *same* generic "not exposed to agents" error string used by
   the other tools — never "no such secret" — so the filter can't be used as an oracle.
4. **M5 fix:** in `show_secret`, `read_secret`, `run_with_secrets`, evaluate the strict-mode
   decision before the nil check. Concretely: look up the secret, then
   `if agentDenied(sec != nil && sec.AgentExposed)` → generic "not exposed" error; only then the
   nil check. (The refusal echoes the probed name, so responses differ only in the agent's own
   input — what must not differ is anything about store state.) Under non-strict the messages
   stay distinguishable (no oracle concern — the agent can list everything anyway).
5. **M6 fix:** clamp `limit` to `[1, 500]` *as a float* before conversion
   (`if v > 500 { v = 500 }`), matching the CLI's sane-page behavior.

### Files touched

- `mcp.go` — `mcpAuditLog` (filter + clamp), the three handlers (check order).
- `agent.go` — no change expected (`agentDenied` signature already takes a bool).
- `mcplimits_test.go` / `mcp_test.go` — new tests (below); existing tests must not change
  behavior in non-strict mode.

### Tests

- Strict server, two secrets (one exposed, one not), both with audit history:
  `audit_log {}` returns only the exposed secret's events; the hidden name appears nowhere in the
  serialized result (assert on the JSON bytes, not just the parsed views).
- `audit_log {name: "<hidden>"}` and `audit_log {name: "<nonexistent>"}` return the same generic
  refusal under strict (the message echoes the probe, so compare with the probed name normalized
  out).
- `hdl_`-caller events for an exposed-secret handle still appear, masked.
- M5: `show_secret`/`read_secret`/`run_with_secrets` return the same generic refusal (modulo the
  echoed probe name) for a hidden secret and a nonexistent secret under strict.
- M6: `limit: 1e18` and `limit: -5` both resolve to the clamp; a large-limit call returns at most
  500 events.
- Non-strict: behavior unchanged (regression).

### Docs

- `docs/MCP.md`: one paragraph — under `--strict`, `audit_log` is scoped to exposed secrets.
- `docs/THREAT-MODEL.md`: amend the strict-mode description to cover audit metadata.
- `CHANGELOG.md`: entry under Unreleased (`fix:` — this is a security-relevant bug fix).

---

## H1 — Operator signature over the synced store

### Problem

Every pull-side check (rollback floor, generation cross-check, recipient-broadening refusal) keys
on values **inside** the age envelope, and age is unauthenticated. Recipient public keys are
cleartext in the git-committed store. A malicious backend that knows the recipients can fabricate
a store (policies stripped, rotated-out secrets resurrected, generation = HWM+1), seal it, and
have every machine adopt it silently. Today the model reduces to "untrusted backend that has
never seen a recipient list."

### Design

Add a **store signing key**: an Ed25519 keypair, generated and held by the operator, distinct
from the per-session audit signers (those are unanchored and session-scoped; this one is
operator-anchored and store-scoped). Push signs; pull verifies against a **locally pinned**
public key. The signature lives in S3 object user-metadata, so the envelope format does not
change and older clients keep working during migration.

#### Key and pin

- New file `internal/storesign/` (keeps `main` package slim, mirrors `internal/audit`):
  - `Generate()` / `Load(path)` — 32-byte seed at `storeStateDir()/store-signing.key`, written
    via `atomicfile.Write(..., 0o600)` (fixes the L3 pattern from the start).
  - `Sign(priv, payload)` / `Verify(pub, payload, sig)` over the **exact payload bytes** that are
    sealed (the canonical store JSON as written — sign `snap.raw`, verify the decrypted envelope
    payload byte-for-byte, so no canonicalization ambiguity exists).
- **Pin** at `storeStateDir()/store-signer.pin` containing the expected signer public key,
  written via atomicfile, modeled directly on `recipientpin.go`:
  - First push on a machine with no key: generate, then require the terminal-anchored operator
    confirmation (`requireOperator`) that prints the full public key — same pattern as
    `recipients add`.
  - First pull on a machine with no pin (new machine joining a fleet): **refuse** with an
    actionable message naming `arca signer pin <pubkey>`, which prints the key and requires the
    operator anchor. No Trust-On-First-Use from the network — the whole point is that the network
    is hostile; the operator copies the pubkey out-of-band (`arca signer show` on the signing
    machine).
  - A pin mismatch on pull is a **hard refusal, not overrideable by `--force`** (L8 makes this
    worse, not better — a flag that admits a teammate's key must not also admit an unsigned or
    mis-signed store). Signer rotation is an explicit command, not a force.

#### Wire format

- On push (sync.go:~794, `sealEnvelope` call site): sign `snap.raw`; put
  `Arca-Signature: base64(sig)` and `Arca-Signer: base64(pubkey)` into the head object's
  user-metadata alongside the existing `Arca-Generation` (s3.go:136), and onto the revision
  object's metadata as well (rev objects are immutable — their signature is permanent evidence).
- On pull (sync.go:~838, after `openEnvelope` succeeds, before `writeLocalStore`):
  1. If no local pin exists → legacy behavior *with a loud stderr warning* (migration window; see
     below), unless the head carries a signature, in which case refuse and direct the operator to
     `arca signer pin`.
  2. If a pin exists: require both metadata fields; missing (backend strips metadata), malformed,
     `Arca-Signer` ≠ pinned key, or verification failure → **refuse the pull**, no store write,
     no cursor advance. This subsumes the "backend strips metadata wedges sync" Info finding by
     making the failure explicit and correct.
- `Arca-Signer` in metadata lets the verifier detect key *rotation* (signed by a different key)
  vs *forgery* (invalid sig) and say so in the refusal message.

#### Commands

- `arca signer show` — print the local signing public key (headless-safe; public material).
- `arca signer pin <pubkey>` — terminal-anchored; prints the key being pinned.
- `arca signer rotate` — terminal-anchored; generates a new key, re-signs the current store, and
  pushes (head + new rev). Other machines then need `arca signer pin <new-pubkey>`; the pull
  refusal message should say exactly that. Rotating *also* re-pins locally.
- All three go through the existing agent-refusal + operator-anchor path
  (`requireOperator`), like `recipients`.

#### Escrow (in scope, minimal)

Escrow segments (M2) have the same "encrypted but unauthenticated" shape. Signing each segment
with the store key at escrow time and verifying in `fetchEscrowedSegments` when a pin exists is a
small increment once the key infrastructure lands — include it, but behind the same pin gate, and
keep M2's other fixes (anchor secrecy, LastID sanity check) as separate follow-ups.

### Migration

Existing deployments have unsigned heads and no pins. Staged enforcement:

1. **Version N:** pull accepts unsigned stores but prints a one-time-per-upgrade stderr notice:
   "store is unsigned; run `arca signer show` on your signing machine and `arca signer pin` here."
   Push signs automatically once a key exists (generating one on first anchored push).
2. Once a pin exists on a machine, enforcement on that machine is absolute (hard refusals above).
3. A future version may flip the no-pin default to refuse; the notice copy should say so.

### Threat-model deltas (what this does and doesn't buy)

- **Buys:** the backend can no longer fabricate or splice store content, strip policies, or
  resurrect rotated secrets. Replaying a *genuinely signed older* store is still caught by the
  existing generation floor. Deletion/wedging remains possible (availability, already known).
- **Doesn't buy:** protection against a same-UID attacker who reads `store-signing.key` — already
  out of scope (they own the age identity too). Multi-operator approval is out of scope (single
  signer; a future threshold scheme would replace the pin, not this format).

### Files touched

- `internal/storesign/` — new (key load/generate/sign/verify, pin read/write).
- `sync.go` — sign at push, verify at pull, refusal messages.
- `internal/remote/s3.go` — `Arca-Signature`/`Arca-Signer` metadata on head + rev puts, and
  surface them from `Head`.
- `internal/remote/remote.go` — extend the `Rev` struct for the two metadata fields.
- New `cmd_signer.go` — the three subcommands; register in `main.go`.
- `escrow.go` — sign segments at escrow, verify in fetch (pin-gated).
- Docs: `docs/SYNC.md` (replace the "honest-but-curious today" caveat with the signature model +
  rotation runbook), `docs/THREAT-MODEL.md` (T-sync section), `docs/COMMANDS.md`, `SECURITY.md`
  (one line), `CHANGELOG.md`.

### Tests

- Pull refuses: unsigned head with pin present; bad signature; `Arca-Signer` ≠ pin; metadata
  stripped. Assert no store write and no cursor advance in each case.
- Pull accepts: correctly signed head; legacy unsigned head with no pin (warning path).
- Push: metadata present and verifies against the local key; rev object carries the same sig.
- Rotation: `signer rotate` → old-pinned machine refuses with the rotation message; after
  re-pin, pull succeeds.
- Round-trip: two-machine sync e2e (extend `e2e/`) with a forged-store attempt by the test's
  fake backend → refused.
- Escrow: segment signed at push, verifies on `--remote`; tampered segment refused when pinned.
- Pin file: written 0600 via atomicfile; corrupt pin → refuse, never auto-heal.

### Suggested sequencing within H1

1. `internal/storesign` + pin plumbing + `cmd_signer.go` (no sync behavior change yet).
2. Push-side signing (metadata only; pulls ignore it) — shippable alone.
3. Pull-side verification + migration notices.
4. Escrow segment signing.
5. Docs + CHANGELOG + e2e.
