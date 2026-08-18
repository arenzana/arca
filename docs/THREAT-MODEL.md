# Threat model & security assessment

This document records the security assessment performed on arca: the assets it
protects, who might attack them, the threats considered most likely and
impactful, and how each is addressed. It is a living document — it is revisited
when the design changes or a new class of risk is identified.

For the system's actors and components, see [ARCHITECTURE.md](ARCHITECTURE.md);
for the operational reporting policy, see [SECURITY.md](../SECURITY.md).

## Method

The assessment combined a structured review of each trust boundary in the
architecture with a focused audit of the code paths that handle secret values,
enforce policy, and write the audit log. Findings were triaged by likelihood and
impact, remediated, and covered by tests. CI re-checks the same surface on every
change through `go vet`, `staticcheck`, `gosec` (medium severity and up),
`govulncheck`, and CodeQL.

## Assets

1. **Secret values** — the cleartext of stored secrets. Highest-value asset.
2. **The age identity** — the private key that decrypts the store.
3. **Audit integrity** — the trustworthiness of the access log.
4. **The release artifacts** — what users download and run.

## Trust boundaries

- Operator ⇄ arca (full trust; the operator owns the machine).
- AI agent ⇄ arca policy and audit (the agent is *cooperating* but must not be
  able to weaken controls — the boundary arca is built to defend).
- arca ⇄ subprocess (`exec` / `run_with_secrets`).
- Project ⇄ release pipeline and dependencies (supply chain).

Out of scope: a hostile local user with the operator's privileges (they can
bypass arca entirely), and host compromise (malware, a key-logger, memory
scraping). arca raises the bar for an agent, not for an attacker who already owns
the machine.

**The out-of-scope line and the in-scope adversary overlap, and that must be
stated plainly.** The agent arca is built to constrain is typically a coding
assistant with a shell tool — which is a local process running as the operator.
It is therefore *already* the excluded party, and the exclusion is doing more
work than a casual reader will assume. The honest formulation is not "agents are
in scope, local users are out" but:

> arca constrains an agent that acts **through the arca interface**. It does not
> constrain an agent with arbitrary filesystem read, which takes the age identity
> directly and decrypts the store without invoking arca — no policy consulted, no
> audit event, no canary. Every control in this document is void against that
> agent.

This is not a defect to be fixed; it is unfixable in-process without moving the
key out of the operator's reach (TPM, hardware token, remote signer). It is
recorded here because it determines whether the rest of the model is meaningful
or decorative. arca is worth deploying under the honest framing — as a control
on the sanctioned path, and as detection and attribution for everything that
uses it — provided the deployment either restricts the agent's read access to
the identity path or accepts this knowingly.

## Threats considered and how they are addressed

### T1 — Secret value leaks through a side channel
- **Value on the command line** → leaks via shell history and `ps`. *Addressed:* values are only read from a TTY (no echo) or piped stdin, never an argv argument.
- **Value written to disk in cleartext** → recoverable later. *Addressed:* values are age-encrypted at rest; the store is written atomically (unique temp file + chmod + fsync + rename + fsync of the parent directory, one helper shared by every state writer); files are `0600`. The chmod is explicit rather than inherited from the temp file's creation mode, because a write that reuses an existing file keeps that file's mode — which is how a `0600` store could quietly become `0644` after a crash left a temp file behind.
- **Value echoed into an agent's context** → ends up in model logs/transcripts. *Addressed:* `exec` / `run_with_secrets` let a command *use* a secret while arca returns only the command's output; `arca exec` additionally **redacts injected values from the command's captured output** (replacing them with `«arca:NAME»` and auditing the catch), so an accidental `echo $SECRET` is intercepted rather than trusted not to happen. This is defense in depth, not a guarantee: it matches the literal value, so a command that encodes/splits/hashes the secret before printing can still emit it. `--no-print` refuses `get`/`env`/`inject` disclosure entirely.

### T2 — An AI agent weakens the controls that govern it
An agent trying to self-approve a gated read, disable fail-closed auditing, or
suppress its own access record. *Addressed:* the strongest control,
`--require-approval`, no longer trusts the environment at all — it requires an
interactive confirmation on the controlling terminal every time, and an agent has
no terminal (there is no `ARCA_APPROVAL=allow` bypass; only `deny`, which can only
*refuse*). For unattended-but-authorized use, the operator issues a scoped `grant`
or `handle` interactively. The other two knobs, `ARCA_STRICT_AUDIT=0` and
`get --no-log`, are anchored the same way: they are honored only for a non-agent
caller **with a controlling terminal**. Env-var-based agent detection alone would
be advisory (an agent controls its own environment and can scrub the markers),
but it cannot open `/dev/tty` / `CONIN$` when no human terminal exists — so a
headless caller stays fail-closed and always leaves a read record.

A third knob, **`$ARCA_AUDIT`**, was unanchored until it was closed: it selects
*which* DB the fail-closed write goes to, so redirecting it to a scratch file
neutralized the audit log, the rate limit (the log is the counter) and the canary
registry at once, with no knob visibly turned off. It is now handled differently
from the other two — a detected agent whose `$ARCA_AUDIT` resolves to anything
other than the store's own DB has its **command refused**, with no
controlling-terminal hatch. The hatch is deliberately absent here: an agent
running under a pty *does* have a terminal, so extending it would hand the bypass
straight back, and unlike the other two knobs there is no legitimate agent use to
preserve. An operator's redirect (no agent marker) is unaffected, terminal or not.

*Residual:* on Windows, a console-attached agent process does have `CONIN$`; the
terminal anchor there is weaker than on Unix (same trade-off as approval). And
detection remains the trigger for the `$ARCA_AUDIT` refusal, so an agent that
scrubs its own markers evades it — the standing limit of env-based detection
stated above, not new to this control; what the fix removes is the case where
an agent did *not* have to hide to go unaudited.

### T11 — An agent edits the policy instead of defeating it — ✅ ADDRESSED
T2's terminal anchor is applied to the commands that *release* a value. It was not
applied to the commands that *change the rules*, so `arca grant`, `arca agent allow`,
`arca enable`, `arca recipients add`, `arca reencrypt` and `arca handle create` all
succeeded for a detected agent with no controlling terminal.

The consequence was that the strongest per-secret controls were self-servable in one
extra step. An agent refused by `--require-grant` runs `arca grant NAME --ttl 1h
--uses 99` and retries successfully. An agent invisible under a `--strict` MCP
server runs `arca agent allow NAME` and becomes visible. The documented workflow
in T2 — "for unattended-but-authorized use, the operator issues a scoped `grant`
or `handle`" — assumes the operator issues it; nothing enforced that.

*Addressed.* `requireOperator()` (`operator.go`) now anchors all six: a detected
agent is refused outright, and every other caller must answer a yes/no question on
`/dev/tty` (`CONIN$` on Windows) naming the scope being widened. It is deliberately
an interactive **prompt**, not a `hasControllingTTY()` predicate — an agent launched
from the operator's own shell inherits that terminal, so the predicate form returns
true for the primary adversary and buys nothing.

Anchored: the loosening direction only. `agent deny`, `disable`, `recipients rm` and
`handle revoke` stay headless, because a caller that can only narrow its own access
is not an escalation path, and `recipients rm` is emergency revocation — a prompt on
the incident-response path costs speed exactly when speed matters.

There is **no** environment bypass, deliberately: that would reproduce the
`ARCA_APPROVAL=allow` mistake T2 exists to record, and an agent controls its own
environment. `TestControlPlaneHasNoEnvBypass` enforces the absence. The cost is
that genuinely non-interactive use (CI issuing a grant, a provisioning script adding
a teammate's key) is now refused rather than silently allowed. If such a consumer
appears, the fix is an operator-minted admin capability — created interactively,
scoped, expiring, and never written to the state dir — not a variable.

*Residuals:* on Windows a console-attached process has `CONIN$`, so the anchor is
weaker there than on Unix (the same trade-off T2 documents). And an agent sharing
the operator's controlling terminal can attempt to answer its own prompt — on macOS
`TIOCSTI` is unprivileged for the controlling terminal. This converts a *silent*
self-authorization into a *visible* one rather than making it impossible; the
guarantee needs the age identity out of the agent's reach (AR-1).

### T12 — Recipient injection: exfiltration that never enters an access path — ✅ ADDRESSED
The widest case of T11, called out separately because its blast radius and its
audit behaviour are both different in kind.

`arca recipients add <attacker key>` followed by `arca reencrypt` re-wraps every
stored value to an additional age key. The holder of that key then decrypts the
store directly, offline, permanently, and on every machine the store syncs to.
Because the path never calls `gate()`, it is unaffected by *all* per-secret
policy: `--no-print`, `--require-approval`, `--require-grant`, expiry, disable and
rate limits are all irrelevant to it. No read event is recorded, and a canary in
the same store is re-wrapped to the attacker's key **silently** — the decoy is
exfiltrated without tripping.

Auditing was also incomplete here: `recipients add` wrote no audit event at all.
`reencrypt` writes one (`op=reencrypt`, `name=*`) which does not name the
key that was added, so the log showed that a re-wrap happened but not that the
recipient set grew or to whom. `arca log --verify` still reported a clean chain —
correctly, since the chain is honest about everything it was told, and it was
never told.

*Addressed.* Three separable fixes were identified; all three are done:

1. ✅ **Audit `recipients add`** (SEC-44). Each added key is recorded individually as
   `op=recipients-add` with the key in the `name` field, and a relabel as
   `op=recipients-label` — labels are how an operator recognizes a key during review,
   so renaming an unfamiliar key to something trusted-looking defeats that check.
2. ✅ **Apply the T11 anchor to the recipient commands.** Both halves are anchored:
   `recipients add` stages the key, `reencrypt` is what re-wraps every value to it, so
   anchoring only the add would leave the payload step open to an agent racing a
   legitimate pending change. The `recipients add` prompt shows the key itself, because
   *which* key is the decision — it is the last chance to notice an unfamiliar one
   before `reencrypt` makes it total.
3. ✅ **Pin the recipient set in local state.** The first two fixes both act on the
   machine where the key is added. Neither covers the case where it is added on
   *another* machine and pulled in by sync: the store simply arrives carrying a
   recipient nobody here was ever shown. `recipients.pin` (state dir, never synced,
   `0600`) records the set this machine has accepted. A recipient present in the store
   but absent from the pin is reported on every load and raises `doctor`'s readership
   check to HIGH, naming the key — previously that check reported a count at LOW, which
   is a fact rather than a finding, because there was no baseline to compare against.

   The pin deliberately does **not** behave like `store.gen`. That high-water mark
   advances by itself on seeing a higher number, because its job is to catch a
   generation going *backwards*; a recipient set going *forwards* is the attack, so the
   pin only moves on an anchored operator action. Two consequences follow, and both are
   load-bearing rather than incidental:

   - **The pin is edited, never rewritten from the store.** `recipients add` accepts
     only the keys the operator was just shown, and `recipients rm` drops only the keys
     it removed. Re-pinning from the store in either path would turn a decision about
     one key into acceptance of every key present. This matters most for `rm`, which is
     deliberately *not* anchored on the grounds that removal only restricts: if it
     re-pinned, removing any key at all would silently accept an injected one, which is
     an unanchored path to silencing exactly this warning.
   - **Loading never accepts.** The warning repeats until an operator runs
     `arca recipients pin`, which is itself anchored and audited (`op=recipients-pin`),
     and which lists the unaccepted keys in its prompt. A warning that silenced itself
     would report each injected key once, which is not meaningfully different from not
     reporting it.

   The residual is trust-on-first-use: the baseline is established silently on first
   load, so a key injected *before* that is baked in and never reported. Warning on
   every store that predates the check would train operators to ignore the one warning
   that matters, and `store.gen` makes the same trade by starting at 0.

*Detection:* the load-time warning and `doctor` are the primary path. `arca
who-can-read` / `arca exposure` show the current recipient set, and the audit log
names added keys on the machine where they were added. See `GUIDES/` for the
response runbook if an unrecognized key is found.

### T13 — Clearing a policy bit on the write path is not anchored — ✅ ADDRESSED
T11 anchors the six commands that *widen* access. It did not anchor the two that
*write a value*, and those could clear a policy bit on the way past:
`arca set NAME --require-approval=false` (likewise `--no-print=false`,
`--require-grant=false`, `--rate ""`) and the same flags on `arca generate`.
`sec.NoPrint` / `RequireApproval` / `RequireGrant` / `RateLimit` are written from
exactly two places, `set` (`main.go`) and `generate` (`generate.go`); `rotate`,
`edit` and `annotate` do not touch policy.

**This entry previously called those four "the complete set". They are not.** The
same `Flags().Changed(...)` block writes a fifth: `--canary=false` calls
`unmarkCanary(name)`, and `set`/`generate` are the **only** path in the CLI that
disarms a decoy — `arca canary` plants and lists, and has no unmark subcommand. So
the field that turns a tripwire off was both unanchored and unlisted. Ranked with
the other four rather than above them, because it removes a *detection* control
rather than escalating read capability, but it is the one a reader of the old entry
would have implemented a fix without.

**Why this is ranked below the six, rather than folded into T11.** The anchor exists
to stop *silent escalation of read capability*. This is not that. In both commands
the value write is unconditional and comes first (`sec.Value = armored`, before the
`Flags().Changed(...)` block), so clearing the bit costs the secret: the caller must
supply a replacement value, and an agent that needed `--require-approval` cleared is
by definition one that could not read the old value to put back. The outcome is
**destroy-and-downgrade** — audited as `op=set` / `op=generate`, immediately visible
to every legitimate consumer, and recoverable from `sync` or `escrow` — where T11's
paths were silent, permanent, and left the value in place. Controls are ranked by the
failure they prevent; this one prevents a lesser failure.

*Addressed.* `requirePolicyOperator()` (`operator.go`) anchors both commands, with a
predicate deliberately narrower than the six: it fires only when (the target already
exists) **and** (this invocation leaves it less protected than it is now). Creating a
secret with a loose policy is a choice, not a downgrade, and tightening never needs a
terminal. The narrowness is the point — an unconditional prompt on every first `set`
is noise the operator learns to answer `y` to, which would cost the other six anchors
their meaning.

Two details that are load-bearing rather than incidental:

- **The rate limit is compared, not pattern-matched.** Anchoring only the `--rate ""`
  spelling this entry originally named would be theatre: a caller refused that writes
  `--rate 1000000/1s` and holds the same capability. Clearing is treated as the
  limiting case of raising. The window defaulting is shared with `checkRateLimit()`
  through one helper, so the anchor guards the limit that is actually enforced.
- **The guard runs before the value is read.** The value write is unconditional and
  precedes the policy block, so a refusal arriving after it would leave the caller
  having destroyed the secret it was refused permission to downgrade — an anchor that
  only adds damage. Pinned by a test that reads the value back after a refusal, and by
  a second one that checks the decoy registry is untouched.

*Residual — detection of the caller is not the control here, but the terminal is.* An
agent that scrubs its environment markers is still refused, because it cannot open a
controlling terminal that does not exist; the marker check only produces the readable
error. That is T11's standing property, unchanged.

*Expiry — now addressed.* This entry previously stopped short of `--ttl` /
`--expires-at`, which overwrote `ExpiresAt` unconditionally: `arca set NAME --ttl 30d`
extended a secret that would have expired tomorrow, with no anchor. Three things were
filed as blocking it, and each is resolved:

- **"Extend versus shorten" needed its own rule across a relative TTL and an absolute
  date.** It did not, once both are resolved to an instant *before* being compared.
  `policy.ResolveExpiry` does that, after which the question is one time comparison and
  the two spellings stop being two rules. The ordering that makes it decidable: no
  expiry at all is the *least* protected state, and an earlier expiry is tighter than a
  later one. Extending or clearing is a downgrade; shortening, or setting one where
  there was none, is not.
- **No clearing path.** There is one now: a flag given *empty* clears the expiry,
  matching `--rate ""`. That is also what obliges the predicate to treat clearing as the
  widest relaxation rather than an absent value, since "never expires" is now reachable.
- **The helper was shared with a third command.** `rotate` was the one that could move
  an expiry with no anchor of any kind; it now anchors through the same predicate.

Presence and value are handled separately throughout, so a flag that is absent still
leaves an existing expiry alone. Without that, every re-set would silently drop the
expiry it was not asked to touch, and the anchor would fire on ordinary traffic — the
failure mode that teaches an operator to answer `y` without reading.

*Interaction with the empty-value guard.* Before the guard on `set`/`rotate` refused
an empty stdin read, this was materially worse: `arca set NAME --require-approval=false
</dev/null` cleared the policy bit **and** stored empty over the real value and exited
0 — silent destruction, because the store keeps only the current value. With the guard
in place the destructive half is refused outright, which is what leaves this at
destroy-and-downgrade. `generate` was never in that shape: it reads no stdin and always
substitutes a fresh random value.

### T3 — Shell / environment injection via crafted secret names
A hand-edited or synced store containing a name like `x=...; rm -rf` could break
out of `eval "$(arca env)"`, or a name like `LD_PRELOAD`/`PATH` could hijack the
child process when injected by `exec`. *Addressed:* names are validated against
`^[A-Za-z_][A-Za-z0-9_]*$` on write, **and** rejected if they collide with a
reserved environment variable (`PATH`, `LD_*`, `DYLD_*`, `IFS`, `BASH_ENV`,
`PROMPT_COMMAND`, the language-runtime hooks, …). Both checks are re-applied at
every injection site (`env`, `exec`, `run_with_secrets`, `handle`), so an
already-poisoned store is refused there too — a reserved or malformed name is
never emitted or exported.

### T4 — Audit log is bypassed, rewritten, or made unreliable
*Addressed (within scope):* auditing is fail-closed by default — a read aborts
before disclosure if the access cannot be recorded; an agent cannot turn this
off. The log is also **tamper-evident**: each event is hash-chained into the
previous one (`hashᵢ = SHA-256(hashᵢ₋₁ ‖ canonical(eventᵢ))`) and signed with the
recording session's Ed25519 key, so editing, deleting, or reordering past events
breaks the chain or a signature and is caught by `arca log --verify`. `--verify`
also refuses three ways a DB-writer could try to fake a clean result rather than
report them as benign: a "legacy downgrade" that NULLs every hash so the chain
loop skips the rows (a born-chained DB is marked in `PRAGMA user_version`, so a
legacy row appearing later fails); deletion of the `audit_head` truncation anchor
(a missing head on a chained DB fails); and signature stripping (unsigned chained
rows are counted, and `--verify --require-signed` fails on any). *Residual /
documented limitation:* it is tamper-*evident*, not tamper-proof — arca runs as
the user, so by default the session signing key is reachable by the machine
owner, who can add new fake entries going forward *and* could also reset
`user_version` and re-sign a rewritten chain (full non-repudiation needs the key
in a TPM / hardware token / remote signer, and truncation needs an external
anchor beyond the in-DB head). Identity *input* remains advisory: the agent
name/`ARCA_ACTOR` come from the environment, so the log binds each event to a
session key but records the *claimed* human/agent identity.

### T5 — Malformed or hostile store input
A corrupted, oversized, or version-mismatched store file. *Addressed:* `Load`
enforces a size cap, checks the format version, rejects nil entries, and runs
explicit migrations; reads of untrusted-path inputs are bounded (16 MiB) and
annotated where `gosec` flags them.

### T9 — Store rollback / replay
The store is git-synced, so an attacker (or a sync conflict) could restore an
older copy — resurrecting a rotated or deleted secret — with no signal.
*Addressed:* every write that lands bumps a monotonic `generation`. On load arca
compares it to a local high-water mark and warns if it regressed (fast,
per-operation).
Additionally, every audit event records the generation it observed, **bound
into the event's hash and signature** — so `log --verify` detects a rollback
from the tamper-evident log itself: it fails when the store's generation is
behind the log's audited maximum, or when the log records a generation going
backwards (operations continuing against a restored older copy). For the one
rewrite no in-DB check can see — the store and the audit DB rolled back
*together* to a consistent older state — `log --verify` emits an **anchor
token** (chained-event count + head hash) to store off the machine (password
manager, git note, another host); a later `--verify --anchor <token>` fails
unless the log still extends that head. *Residual:* a rollback of exactly one
write (to the copy current at the last audited operation) is below the
generation check's resolution, and the anchor only protects history up to the
moment it was minted — its value depends on minting and checking regularly.

The counter advances only after the bytes have landed. Bumping it first — which
arca did through 0.8.0 — meant a `set` that failed anywhere in the write still
recorded the advanced generation into that command's signed audit event, and the
next process, loading the real lower generation, produced exactly the
"operations continuing against a restored older copy" pattern above with no
attacker involved. A false positive is not a cheap bug on this control: its
entire value is that the operator does not learn to discount it.

### T10 — Removing a recipient is mistaken for revocation
`recipients rm` drops a key from the set, but the removed holder can still decrypt
any ciphertext they already had — backups, clones, and every prior version of the
git-synced store. *Addressed (honesty + narrow the window):* `recipients rm` now
re-encrypts the current store to the remaining keys automatically (so the working
store stops depending on the removed key) and prints an explicit warning that this
is not revocation of prior access, listing the secrets to rotate. *Residual (by
nature):* true revocation of a value is impossible without rotating it — the fix
guides that (`arca rotate NAME` + revoke at the issuer), it cannot undo a read.

### T6 — Concurrent writers corrupt the store
Two arca processes mutating the store at once. *Addressed:* an `O_EXCL` lockfile
guards mutations. The lock carries a per-acquisition token, so release removes it
only if the process still owns it and a stale lock is reclaimed by winning an
atomic rename (not a blind unlink) — a process can neither delete a successor's
lock nor have two processes both reclaim the same one. A holder heartbeats the
lock's mtime while held, so a live-but-slow writer (e.g. `edit` across an
`$EDITOR` session) is not mistaken for a crash and stolen; only a stopped process
ages out.

### T8 — A store reader identifies which secrets are decoys
Canaries (honeytokens) only work if an attacker can't tell them from real
secrets. *Addressed:* the "this is a decoy" designation is kept in a **local
registry** under the state dir, never in the git-synced store — so someone who
obtains the store file (the exfiltration a canary exists to catch) sees only
ordinary-looking entries. The decoy's value is an ordinary age ciphertext. This
defends the *exfiltration* boundary; a same-UID local user who can read the state
dir is out of scope by design (they own the machine). Trade-off: because the
registry is local, a canary is armed per-machine.

### T7 — Supply-chain compromise of a release
A tampered binary, a malicious dependency, or a poisoned build. *Addressed:*
reproducible builds (`CGO_ENABLED=0`, `-trimpath`, stripped); keyless **cosign**
signatures over `checksums.txt`; SLSA build-provenance attestation; CycloneDX
SBOM; `govulncheck` and `go mod verify` in CI and before release; SHA-pinned,
least-privilege GitHub Actions with `harden-runner`. Dependencies are kept
minimal (see [CONTRIBUTING.md](../CONTRIBUTING.md#dependencies)).

## Residual risks (accepted)

- A hostile local user or compromised host can read secrets — out of scope by
  design. **This includes an AI agent with unrestricted filesystem read**, which
  is the same class of party arca otherwise constrains; see the trust-boundary
  section above for why this is stated rather than mitigated.
- Audit attribution is self-reported, not cryptographically verified.
- A subprocess invoked with a secret can itself disclose that secret; choosing
  the command is the operator's responsibility.
- Sync backend credentials, when persisted with `sync init --store-credentials`,
  are stored in cleartext at `0600` in the state directory — the same bootstrap
  class as the age identity, and reachable by the same party as the first item.

These are documented rather than mitigated because they fall outside the single
trust boundary arca is designed to enforce.

## Open findings (not yet addressed)

Recorded here so this document does not read as an all-clear. A threat model that
describes intended behaviour rather than current behaviour is worse than none.

As of the 2026-08-17 external-style audit — full report with severities, file:line
references, and fix order in [audits/2026-08-17-security-audit.md](audits/2026-08-17-security-audit.md)
— the following are open:

| Finding | Summary | Status |
|---|---|---|
| ~~H1~~ | ~~Pulled stores have no writer-authentication~~ | **Fixed** (Unreleased): push signs the store bytes; pull verifies against a locally pinned operator key. `--force` cannot override a pin mismatch. Unsigned heads are accepted only on machines with no pin (migration window). Escrow segments are signed with the same key and verified on fetch when a pin exists. |
| ~~H2~~ | ~~MCP `audit_log` bypasses `--strict`~~ | **Fixed** (Unreleased): `audit_log` is scoped to exposed secrets under `--strict`, its `name` filter returns the generic refusal for hidden/nonexistent names, and `limit` is clamped. M5 (existence oracles in `show`/`read`/`run_with_secrets`) and M6 (`limit` overflow) fixed in the same change. |
| ~~M1~~ | ~~Prompt terminal-escape injection~~ | **Fixed** (Unreleased): `approve`, `approverWho`, `requireOperator`, and `grantScope` now pass every attacker-influenced fragment through `sanitize()` before writing to `/dev/tty`. |
| ~~M3~~ | ~~Grant / rate-limit check-then-record TOCTOU~~ | **Fixed** (Unreleased): use events (`read`/`exec`/`env`/`inject`) count their rate and grant-uses caps inside the same `BEGIN IMMEDIATE` as the append. Concurrent writers against a `--uses 1` grant or a `--rate 1` secret can no longer all observe `used=0`. |
| ~~M7~~ | ~~Sync credentials inherited by children~~ | **Fixed** (Unreleased): `exec` and MCP strip inherited `ARCA_SYNC_ACCESS_KEY` / `ARCA_SYNC_SECRET_KEY` / `AWS_*` from the child environment. An explicit `--only` injection of those names still wins. |
| ~~M2~~ | ~~Unauthenticated escrow segments~~ | **Fixed** (Unreleased): each segment's rows are rehashed against the claimed chain; a `LastID` past the local log is refused; `--verify` no longer prints the anchor on stdout (`--print-anchor` is opt-in). Escrow segments are also signed with the store key (H1). |
| ~~M4~~ | ~~Spoofable grant `--agent`~~ | **Fixed** (Unreleased): the claim that the agent check is "firm" is dropped. `--agent` is documented as advisory (env sniffing); uses and expiry stay firm. |
| ~~M8~~ | ~~Unknown-field policy stripping~~ | **Fixed** (Unreleased): `Decode`/`Save` preserve unknown JSON fields on the store and on each secret. |
| ~~M9~~ | ~~Unenumerated `reencrypt` prompt~~ | **Fixed** (Unreleased): the confirmation lists every recipient and the drift warning is part of the prompt, before the operator answers. |
| ~~L1, L3, L5, L7, L9~~ | ~~WAL perms; corrupt session seed regen; HOME/SHELL/XDG reserved; approve timeout; lexical escrow sort~~ | **Fixed** (Unreleased). |
| ~~L2, L4, L6, L8, L10–L14~~ | ~~State-dir create-only perms; env-shadowing; redaction evasion class; --force bundling; import hardening; session-binding docs; adoption lock; reset-escrow orphaning; seed zeroization~~ | **Fixed** (Unreleased): L2/L4/L8/L10/L12/L13/L14 in code; L6/L11 documented. |
| Info | MCP exec accounting, stdin bound, UTF-8 read_secret, insecure=1 notice, stripped-metadata Head error, --only double-count. | **Fixed** (Unreleased). Remaining Info items (caller argv, handle use-count, symlink semantics, edit temp-file) are documented boundaries, not defects. |

Earlier open findings (the T12 recipient-pin residual and the T13 expiry residual) remain
addressed as described in their sections above.
