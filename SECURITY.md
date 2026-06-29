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
  aborted (reads abort before disclosing the value). Override with `ARCA_STRICT_AUDIT=0`.

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
