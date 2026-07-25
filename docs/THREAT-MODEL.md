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
- **Value written to disk in cleartext** → recoverable later. *Addressed:* values are age-encrypted at rest; the store is written atomically (temp + fsync + rename); files are `0600`.
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
headless caller stays fail-closed and always leaves a read record. *Residual:*
on Windows, a console-attached agent process does have `CONIN$`; the terminal
anchor there is weaker than on Unix (same trade-off as approval).

### T11 — An agent edits the policy instead of defeating it — ⚠ OPEN
T2's terminal anchor is applied to the commands that *release* a value. It is not
applied to the commands that *change the rules*. `arca grant`, `arca agent allow`,
`arca enable`, `arca recipients add`, and `arca reencrypt` all succeed today for a
detected agent with no controlling terminal.

The consequence is that the strongest per-secret controls are self-servable in one
extra step. An agent refused by `--require-grant` runs `arca grant NAME --ttl 1h
--uses 99` and retries successfully. An agent invisible under a `--strict` MCP
server runs `arca agent allow NAME` and becomes visible. The documented workflow
in T2 — "for unattended-but-authorized use, the operator issues a scoped `grant`
or `handle`" — assumes the operator issues it; nothing enforces that.

*Not addressed.* The intended fix is to route control-plane mutations through the
same anchor `approve()` already uses (detected agent or no controlling terminal →
refuse). The trade-off is real and unresolved: it breaks legitimate
non-interactive use such as CI issuing a grant or a provisioning script adding a
teammate's key. It must **not** be re-opened with an environment variable — that
reproduces the `ARCA_APPROVAL=allow` mistake T2 exists to record. The intended
escape hatch is an operator-minted admin capability (the shape `handle` already
uses): created interactively once, scoped, and expiring.

### T12 — Recipient injection: exfiltration that never enters an access path — ⚠ OPEN
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

Auditing is also incomplete here: `recipients add` writes no audit event at all
today. `reencrypt` writes one (`op=reencrypt`, `name=*`) which does not name the
key that was added, so the log shows that a re-wrap happened but not that the
recipient set grew or to whom. `arca log --verify` still reports a clean chain —
correctly, since the chain is honest about everything it was told, and it was
never told.

*Not addressed.* Three separable fixes: (1) audit `recipients add`, recording the
added key — cheap and independent of the rest; (2) apply the T11 anchor to the
recipient commands; (3) pin the recipient set in local state (the pattern
`storeGenPath()` already uses for rollback) so a change is surfaced on load and
raised by `doctor`, which currently reports decryption blast radius at LOW and as
a static count with no baseline to compare against.

*Detection in the meantime:* `arca who-can-read` / `arca exposure` show the
current recipient set. Review it directly; the audit log will not show this
change. See `GUIDES/` for the response runbook if an unrecognized key is found.

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
*Addressed:* every write bumps a monotonic `generation`. On load arca compares
it to a local high-water mark and warns if it regressed (fast, per-operation).
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

| ID | Summary | Severity |
|----|---------|----------|
| T11 | Control-plane mutations are not terminal-anchored; an agent can edit the policy that governs it | High |
| T12 | Recipient injection exfiltrates every secret outside any access path; `recipients add` is unaudited | High |
| — | `sync` performs no store locking, so a concurrent pull can silently revert a mutation — including a `rotate` or `recipients rm` performed as incident remediation. It also forks the `generation` counter that T9's rollback detection and the signed audit events depend on | High |
| — | The MCP `run_with_secrets` path buffers command output unbounded with no timeout. Beyond denial of service, the process heap holds injected values in cleartext, so an agent-driven OOM produces a core dump containing them where core dumps are enabled | High |

The last two were identified during backend review; they are recorded here
because their consequences land on trust boundaries this document owns.
