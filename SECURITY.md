# Security Policy

## Reporting a vulnerability

Please report security issues **privately**:

- GitHub Security Advisories: <https://github.com/arenzana/arca/security/advisories/new>, or
- email <isma@arenzana.org>.

Do **not** open public issues for vulnerabilities. We aim to acknowledge within 72 hours.

## How arca handles secrets

- Secret values are **age-encrypted at rest**; no cleartext is ever written to disk.
- Values are read from a TTY (no echo) or piped stdin — **never** passed as command-line
  arguments (which would leak via shell history / `ps`).
- Store and audit files are created `0600`; store writes are atomic (temp + rename).
- The audit log records access **metadata only** (op, name, time, actor, agent, session, caller) — never values.
- Auditing is **fail-closed by default**: if an access cannot be recorded the operation is
  aborted (reads abort before disclosing the value). A non-agent caller may opt into
  best-effort auditing with `ARCA_STRICT_AUDIT=0`; a **detected AI agent cannot weaken this**.

## Trust model & boundaries

The system's actors and components are described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
and the full security assessment — assets, threats, and how each is addressed — in
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

arca runs with the invoking user's privileges; it raises the bar for a *cooperating* AI agent,
not a hostile local user (who could bypass arca entirely). Specifically:

- **Per-secret policy is agent-aware.** A detected agent cannot self-approve a
  `--require-approval` secret via `ARCA_APPROVAL=allow`, cannot disable fail-closed auditing
  (`ARCA_STRICT_AUDIT=0`), and cannot suppress its own read record (`get --no-log`). These
  overrides are honored only for a non-agent caller.
- **`--require-grant` is a guardrail, not a sandbox.** A grant scopes a secret to a command
  pattern, a use count, and a time window. The use count (drawn from the tamper-evident audit
  log), the expiry, and the agent restriction are firm. The **command match is argv-based**, so it
  enforces *intent* but can be sidestepped by an agent that controls argv — renaming a binary or
  wrapping it in `sh -c`. Treat it as expressing and auditing "this secret is for this job," not as
  a containment boundary; every grant, revoke, and use is recorded.
- **`--rate` is a throttle, not a quota guarantee.** It caps uses per rolling window from the
  audit log and records each refusal, which stops a runaway agent hammering a secret and surfaces
  the burst. It is heuristic: a patient caller can stay under the cap by spreading use out, and the
  window is best-effort (it trusts the audit timestamps).
- **Capability handles reduce discovery, not misuse.** An `hdl_…` lets an agent *use* a secret via
  MCP `run_with_handle` without its name or value, and without listing the store — so a leaked
  handle exposes only that one scoped, expiring capability, not the whole store. It does not stop
  the agent from using the handle for its sanctioned purpose; the command run under it has the
  value in its environment (its output is redacted, but the command itself could still transform
  and emit it). Treat a handle like a scoped bearer token: revocable, expiring, and audited.
- **`--no-print` blocks *disclosure*, not *use*.** It refuses `get`/`env`/`inject`, but `exec`
  / MCP `run_with_secrets` deliberately let a command **use** the secret. If the command prints
  an injected value, `arca exec` **redacts it from the captured output** (replacing it with
  `«arca:NAME»` and auditing the catch), so a leak into an agent's context is caught at the
  boundary rather than relied on not to happen. Redaction is best-effort defense in depth — it
  matches the literal value, so a command that transforms the secret (encodes, splits, hashes it)
  before printing can still emit it; `--redact` controls the behavior. The value itself is never
  returned by arca; the command's output is.
- **Secret names** are restricted to `[A-Za-z_][A-Za-z0-9_]*` on write, and invalid names in a
  hand-edited / synced store are skipped by `env`/`exec`, to prevent shell-injection via
  `eval "$(arca env)"` or env-variable hijacking.
- **The audit log is tamper-evident.** Each event is hash-chained into the previous one and
  signed with the recording session's Ed25519 key, so editing, deleting, or reordering past
  events is detectable — run `arca log --verify`. This is tamper-*evident*, not tamper-proof:
  arca runs as the user, so by default the session key is reachable by the machine owner, who
  could still add new fake entries going forward (full non-repudiation needs the key in a TPM /
  hardware token / remote signer). What the chain prevents is silent rewriting of *history*. See
  [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
- **Identity *input* is still advisory.** The agent name/version/session and `ARCA_ACTOR` are
  read from the environment, so the log records the *claimed* identity; signing binds each event
  to a session key but doesn't independently verify that the environment's claim was truthful.

## Supply-chain integrity

- **Reproducible builds:** `CGO_ENABLED=0`, `-trimpath`, stripped (`-buildid=`), pinned
  module timestamps (GoReleaser `mod_timestamp`).
- **Signed releases:** release archives ship with SHA-256 `checksums.txt`, signed with
  **cosign** (keyless / Sigstore) — `checksums.txt.sigstore.json` (bundle: signature,
  certificate, and Rekor transparency-log proof; releases up to v0.6.3 shipped
  `checksums.txt.sig` + `checksums.txt.pem` instead).
- **SBOM:** a CycloneDX SBOM is generated for the module (CI) and per archive (release).
- **Build provenance:** each release artifact carries a SLSA **build-provenance attestation**
  (`actions/attest-build-provenance`).
- **Vulnerability scanning:** `govulncheck` runs in CI; dependency updates via Dependabot.
- **Module integrity:** `go mod verify` runs in CI and before each release.

### Verifying a release

```sh
# checksum signature (keyless cosign; needs cosign >= 2.x for bundle support)
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp 'https://github.com/arenzana/arca/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# then verify the archive against the (now-trusted) checksums
sha256sum -c checksums.txt --ignore-missing

# build provenance
gh attestation verify arca_<ver>_<os>_<arch>.tar.gz --repo arenzana/arca
```
