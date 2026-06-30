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
- **`--no-print` blocks *disclosure*, not *use*.** It refuses `get`/`env`/`inject`, but `exec`
  / MCP `run_with_secrets` deliberately let a command **use** the secret. The command you run
  could still print it — choose commands that consume the secret without echoing it. The value
  itself is never returned by arca; the command's output is.
- **Secret names** are restricted to `[A-Za-z_][A-Za-z0-9_]*` on write, and invalid names in a
  hand-edited / synced store are skipped by `env`/`exec`, to prevent shell-injection via
  `eval "$(arca env)"` or env-variable hijacking.
- **Audit attribution is advisory.** The agent name/version/session and `ARCA_ACTOR` are read
  from the environment, so the log records the *claimed* identity, not a cryptographically
  verified one. `ARCA_AUDIT` likewise trusts the configured path; audit integrity assumes a
  trusted `ARCA_AUDIT` / `ARCA_STRICT_AUDIT` environment.

## Supply-chain integrity

- **Reproducible builds:** `CGO_ENABLED=0`, `-trimpath`, stripped (`-buildid=`), pinned
  module timestamps (GoReleaser `mod_timestamp`).
- **Signed releases:** release archives ship with SHA-256 `checksums.txt`, signed with
  **cosign** (keyless / Sigstore) — `checksums.txt.sig` + `checksums.txt.pem`.
- **SBOM:** a CycloneDX SBOM is generated for the module (CI) and per archive (release).
- **Build provenance:** each release artifact carries a SLSA **build-provenance attestation**
  (`actions/attest-build-provenance`).
- **Vulnerability scanning:** `govulncheck` runs in CI; dependency updates via Dependabot.
- **Module integrity:** `go mod verify` runs in CI and before each release.

### Verifying a release

```sh
# checksum signature (keyless cosign)
cosign verify-blob checksums.txt \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/arenzana/arca/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# then verify the archive against the (now-trusted) checksums
sha256sum -c checksums.txt --ignore-missing

# build provenance
gh attestation verify arca_<ver>_<os>_<arch>.tar.gz --repo arenzana/arca
```
