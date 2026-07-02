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

## Threats considered and how they are addressed

### T1 — Secret value leaks through a side channel
- **Value on the command line** → leaks via shell history and `ps`. *Addressed:* values are only read from a TTY (no echo) or piped stdin, never an argv argument.
- **Value written to disk in cleartext** → recoverable later. *Addressed:* values are age-encrypted at rest; the store is written atomically (temp + fsync + rename); files are `0600`.
- **Value echoed into an agent's context** → ends up in model logs/transcripts. *Addressed:* `exec` / `run_with_secrets` let a command *use* a secret while arca returns only the command's output; `arca exec` additionally **redacts injected values from the command's captured output** (replacing them with `«arca:NAME»` and auditing the catch), so an accidental `echo $SECRET` is intercepted rather than trusted not to happen. This is defense in depth, not a guarantee: it matches the literal value, so a command that encodes/splits/hashes the secret before printing can still emit it. `--no-print` refuses `get`/`env`/`inject` disclosure entirely.

### T2 — An AI agent weakens the controls that govern it
A detected agent trying to self-approve a gated read, disable fail-closed
auditing, or suppress its own access record. *Addressed:* agent-aware policy —
`ARCA_APPROVAL=allow`, `ARCA_STRICT_AUDIT=0`, and `get --no-log` are honored only
for a non-agent caller. An agent cannot re-enable them. This is the project's
central invariant and is covered by dedicated tests.

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
breaks the chain or a signature and is caught by `arca log --verify`. *Residual /
documented limitation:* it is tamper-*evident*, not tamper-proof — arca runs as
the user, so by default the session signing key is reachable by the machine
owner, who can add new fake entries going forward (full non-repudiation needs the
key in a TPM / hardware token / remote signer). Identity *input* remains
advisory: the agent name/`ARCA_ACTOR` come from the environment, so the log binds
each event to a session key but records the *claimed* human/agent identity. Tail
truncation is detectable only against the recorded head or an external anchor.

### T5 — Malformed or hostile store input
A corrupted, oversized, or version-mismatched store file. *Addressed:* `Load`
enforces a size cap, checks the format version, rejects nil entries, and runs
explicit migrations; reads of untrusted-path inputs are bounded (16 MiB) and
annotated where `gosec` flags them.

### T6 — Concurrent writers corrupt the store
Two arca processes mutating the store at once. *Addressed:* an `O_EXCL` lockfile
guards mutations, with stale-lock stealing after a timeout.

### T7 — Supply-chain compromise of a release
A tampered binary, a malicious dependency, or a poisoned build. *Addressed:*
reproducible builds (`CGO_ENABLED=0`, `-trimpath`, stripped); keyless **cosign**
signatures over `checksums.txt`; SLSA build-provenance attestation; CycloneDX
SBOM; `govulncheck` and `go mod verify` in CI and before release; SHA-pinned,
least-privilege GitHub Actions with `harden-runner`. Dependencies are kept
minimal (see [CONTRIBUTING.md](../CONTRIBUTING.md#dependencies)).

## Residual risks (accepted)

- A hostile local user or compromised host can read secrets — out of scope by design.
- Audit attribution is self-reported, not cryptographically verified.
- A subprocess invoked with a secret can itself disclose that secret; choosing
  the command is the operator's responsibility.

These are documented rather than mitigated because they fall outside the single
trust boundary arca is designed to enforce.
