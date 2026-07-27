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

### T12 — Recipient injection: exfiltration that never enters an access path — ◐ PARTIALLY ADDRESSED
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

*Partially addressed.* Three separable fixes were identified; two are done:

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
3. ⚠ **Pin the recipient set in local state** — still open. The pattern
   `storeGenPath()` already uses for rollback would surface a change on load and let
   `doctor` raise it; `doctor` currently reports decryption blast radius at LOW and as
   a static count with no baseline to compare against. Without this, a recipient added
   on *another* machine and synced in is still not flagged on load.

*Detection for the remaining gap:* `arca who-can-read` / `arca exposure` show the
current recipient set, and the audit log now names added keys on the machine where
they were added. Review both. See `GUIDES/` for the response runbook if an
unrecognized key is found.

### T13 — Clearing a policy bit on the write path is not anchored — ⚠ OPEN (residual of T11)
T11 anchors the six commands that *widen* access. It does not anchor the two that
*write a value*, and those can clear a policy bit on the way past:
`arca set NAME --require-approval=false` (likewise `--no-print=false`,
`--require-grant=false`, `--rate ""`) and the same flags on `arca generate`. Those
are the complete set — `sec.NoPrint` / `RequireApproval` / `RequireGrant` /
`RateLimit` are written from exactly two places, `set` (`main.go`) and `generate`
(`generate.go`); `rotate`, `edit` and `annotate` do not touch policy.

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

*Not addressed, deliberately.* The fix is a different predicate from the six: those
are unconditional `requireOperator()` calls, whereas this must fire only when
(the target already exists) **and** (a policy bit is moving 1→0) — otherwise every
first-time `set` prompts and the anchor becomes noise the operator learns to answer
`y` to. That earns its own change and its own tests rather than riding along with
T11.

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

### T7 — Supply-chain compromise of a release — ◐ PARTIALLY ADDRESSED
A tampered binary, a malicious dependency, or a poisoned build. *Addressed:*
reproducible builds (`CGO_ENABLED=0`, `-trimpath`, stripped); keyless **cosign**
signatures over `checksums.txt`; SLSA build-provenance attestation; CycloneDX
SBOM; `govulncheck` and `go mod verify` in CI and before release; SHA-pinned,
least-privilege GitHub Actions with `harden-runner`. Dependencies are kept
minimal (see [CONTRIBUTING.md](../CONTRIBUTING.md#dependencies)).

*Residual:* every control listed above is **downstream of the trigger**. They
establish the *integrity of the pipeline* — that the published artifact is the
artifact built from the tagged source. None of them establishes the *authority of
the release decision* — that the tagged source was ever meant to ship. cosign
signs, and the provenance attests, whatever was tagged, just as faithfully. Who
may start a release is T14.

### T14 — Anyone who can push a tag can publish a signed release — ◐ PARTIALLY ADDRESSED

> **Current status (2026-07-27).** The primary control is **in place**: a
> `refs/tags/v*` ruleset (creation + update + deletion, **empty bypass list**) makes
> creating or moving a release tag a repository-settings action on a channel a git
> credential does not have — closing the hostile-tag path this entry is about.
> Cutting a release is now *disable the rule → push → re-enable* (the "empty bypass
> list" shape analysed below). The complementary **environment gate is NOT yet in
> place**: the `environment: release` change lives on the unmerged
> `fix/release-environment-gate` branch and the `release` environment has not been
> created, so the defence-in-depth described immediately below is a design, not a
> deployed control. The rest of this section is the analysis behind both decisions.

`release.yml` fires on `push: tags: ['v*']`, and the release job holds
`contents: write`, `id-token: write` (cosign keyless signing), `attestations:
write`, and the `HOMEBREW_TAP_TOKEN` / `SCOOP_GITHUB_TOKEN` used to update the
Homebrew tap and Scoop bucket. So the credential that publishes arca to every
install channel is *any* credential that can create a `v*` tag.

**Branch protection does not bound this.** `main` requires status checks, but a
tag push consults no branch rule, so the tagged commit need never have been on
`main`, reviewed, or merged. The two are orthogonal: the branch gate is real and
it is simply not on this path.

**Nor do the in-workflow checks.** A `push` event runs the workflow *from the
pushed ref*, so a hostile tag carries its own copy of `release.yml`: the `verify
before release` step (`go vet` / `go test` / `govulncheck`), `harden-runner`, and
the cask-checksum guard all delete with the tree that carries them. `harden-runner`
is on `egress-policy: audit`, which records exfiltration rather than blocking it.
This is the shape T11 rejected for env vars and config files, one layer out: a
control the constrained party can edit is not a control.

*Designed, not yet deployed (see status above):* the intended complement is to gate
the release job on a protected GitHub **environment** (`environment: release`) whose
protection rule requires a reviewer, with the tap and scoop tokens moved to
environment secrets on it. Two different mechanisms are at work there and they fail
in different ways, so they are worth separating:

- The **required-reviewer rule** lives in repository settings, outside any tree, so
  a hostile tag cannot carry an edited copy of *the rule*. Subject to *Condition on
  the gate* below, it means publishing takes a human approval.
- The **secret scoping**: a job that does not declare the environment never receives
  that environment's secrets. This is the half that holds even when the workflow file
  itself has been rewritten, and per the residual below it is the load-bearing half.

*Residual — the protection rule lives in repository settings; the workflow key
alone gates nothing.* `environment: release` in `release.yml` only *names* an
environment. If that environment does not exist, GitHub creates it implicitly with
no protection rules, and the job runs unguarded while the workflow file reads as
gated — strictly worse than no key at all, because it invites the reader to stop
checking. This document cannot assert the gate is in place; only the repository
settings can. Verify with:

```sh
gh api repos/arenzana/arca/environments/release \
  --jq '{name, rules: [.protection_rules[].type]}'   # expect "required_reviewers"
```

*Residual — the rule is out of tree, but the opt-in is not.* `environment: release`
is a job-level key in `release.yml`, and a `push` event runs the workflow from the
pushed ref. So the attacker's cheapest move is not to defeat the approval rule; it
is to **delete the key that opts into it**, which costs them nothing they wanted:

| | keeps `environment:` | deletes it |
|---|---|---|
| approval | required; a git-transport credential cannot approve → blocked | not required |
| `GITHUB_TOKEN` | as declared here | their own `permissions:` block takes `contents: write` |
| tap / scoop tokens | withheld until approval | **unreachable — environment-scoped** |
| outcome | blocked | **signed, attested Release of their code; no tap push** |

The repository's default-permissions setting does not bound the middle row. GitHub
documents that "anyone with write access to a repository can modify the permissions
granted to the `GITHUB_TOKEN`, adding or removing access as required, by editing the
`permissions` key in the workflow file" — the repository default is a starting point
the workflow may raise, not a ceiling. (The documented case where the `permissions`
key *cannot* grant write is a workflow triggered from a **forked** repository, which
a tag push in this repository is not.)

So the honest statement is that **the secret scoping, not the approval rule, is what
survives a hostile tag.** The gate closes the automated Homebrew/Scoop push; it
leaves a cosign-signed, SLSA-attested GitHub Release of attacker-controlled code
standing. Someone running `brew upgrade` is protected because the tap does not move;
someone downloading from the Releases page — or any tooling resolving "latest
release" — is not. Closing that path means restricting the tag itself, below.

*Condition on the gate.* "A credential that can create a tag cannot approve the
run it starts" is a property of the *credential*, not of the environment. It
holds for a git-transport credential — an SSH key or a deploy key speaks git and
cannot call the REST API at all. It does not hold for an API credential: GitHub
documents *Review pending deployments for a workflow run* as reachable by a
classic personal access token with `repo` scope, so a `repo`-scoped PAT could
create the tag and approve its own deployment, collapsing this control back into
the credential. `can_admins_bypass` also defaults to true on a new environment.
So any credential used for automated pushes must be checked against the approval
endpoint and the bypass setting, not only against `contents`.

*Addressed — the tag ref is now restricted, for creation and for movement.* A
hostile tag was the one path the environment gate cannot close (per the residual
above it does not stop a signed Release), so restricting the tag ref is what stops
that tag *existing*. That control is now live: a ruleset covers `refs/tags/v*` with
all three rules and an empty bypass list, so neither creating a `v*` tag nor
re-pointing one is reachable by a git credential. The ruleset comes in two shapes
with very different costs; the deployed one is the first ("empty bypass list")
below. Both need the same three rules:

    target: tag    pattern: refs/tags/v*    enforcement: active
    rules: restrict creations + restrict updates + restrict deletions

**All three, not only creations.** GitHub's *New tag ruleset* form selects
*Restrict deletions* by default and leaves creations and updates unselected, so
ticking the one rule this finding is usually named by lands on creations plus
deletions with updates open — which pays the full friction while leaving the
movement path below intact.

*Why `update` is load-bearing.* Immutable releases is enabled on this repository,
and GitHub documents that "once an immutable release is published, its associated
Git tag is locked to a specific commit, cannot be changed, and cannot be deleted
while the release exists." That locks the tag at **publish**, not at push, and
`.goreleaser.yaml` creates the release as a draft which the workflow publishes in
its second-to-last step. So a release run that ends before that step leaves a `v*`
tag whose release is unpublished and therefore still movable. The window is not
hypothetical here: of 17 `release.yml` runs, two ended before the publish step —
`v0.2.0` on a blocked syft download, `v0.5.0` on a failed provenance attestation —
and `v0.2.0` was re-pointed to a different commit while its window was open, with
the workflow firing again on the new commit. Separately, `v0.1.0` predates the
setting and its release is `immutable: false`, so that tag is movable today with no
window needed.

- **Empty bypass list — available today.** Cutting a release then becomes: disable
  the rule, push the tag, re-enable it. That is a UI/API action, on a channel a git
  credential does not have, so it holds even while every push uses the operator's
  own key. The cost is recurring friction on every release, in a repository where
  releases are cut by hand.
- **The automation identity excluded from bypass.** Much lower friction, but it
  needs an identity to exclude: a bypass list cannot distinguish the operator at a
  terminal from an agent holding a copy of the operator's key, so this shape becomes
  available only once agent pushes use a separate credential *and* the copies of the
  operator's key are gone. Adding the separate credential does not by itself remove
  anything.

Choosing between them is a cost decision rather than a security one — the first is
strictly stronger today and strictly more annoying.

*Recovering from a failed release run* splits into two cases under either shape, and
the run's own step list says which: **did the goreleaser step run?**

- **It did not.** Nothing was built, no release object exists, and nothing was pushed
  to the Homebrew tap or the Scoop bucket. The tag is inert — re-point or delete it
  freely, which under the ruleset costs one more disable/re-enable cycle. Cutting the
  next patch number instead costs no cycle at all, and is usually right, because a run
  that died this early normally died on something the tagged tree has to fix anyway.
- **It succeeded.** A draft release exists *and the tap and bucket were already pushed
  inside that same step.* **Publish the draft; do not re-point the tag.** Re-pointing
  leaves the tap advertising a cask whose checksums came from a build no longer at the
  tag — by hand, the divergence that shipped a broken `v0.6.1`. Publishing needs no
  ruleset change, and it closes the window instead of reopening it.

Until one is in place, **a tag with no corresponding approved deployment is the signal
to look for**, and it is worth checking over any period the pushing credential was
reachable by something other than the operator.

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
| T14 (residual) | The primary control is in place — the `refs/tags/v*` ruleset (empty bypass) blocks tag creation and movement by any git credential. The complementary defence-in-depth is not yet deployed: the `environment: release` gate — scoping the tap/scoop tokens so a workflow that drops the environment key cannot reach them — lives on an unmerged branch, and the `release` environment is not created (a named-but-uncreated environment is auto-created *unprotected*, so the workflow key must not merge before the environment exists). Until then a release is protected by the ruleset alone, not additionally by token scoping | Medium |
| T12 (residual) | The recipient set is not pinned in local state, so a recipient added on another machine and synced in is not surfaced on load; `doctor` reports blast radius as a static count with no baseline | Medium |
| T13 (residual) | `set` / `generate` extend an expiry (`--ttl`, `--expires-at`) on an existing secret with no anchor: `applyExpiry()` overwrites `ExpiresAt` unconditionally and has no clearing path. Not folded into the policy predicate that closed T13's five relaxation flags — the helper is shared with a third command and "extend versus shorten" needs its own rule across a relative TTL and an absolute date. Neither reveals a value nor widens who may read one, and the expiry is visible in `arca show` | Low |
