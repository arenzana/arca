# Maintainers

This file records who maintains arca, what each role is responsible for, and who
holds access to the project's sensitive resources.

## Current maintainers

| Name | GitHub | Role |
|------|--------|------|
| Ismael Arenzana | [@arenzana](https://github.com/arenzana) | Lead maintainer |

arca is currently maintained by a single person. New maintainers are added by an
existing maintainer once they have a sustained record of reviewed contributions;
the addition is recorded in this file by a pull request.

## Roles and responsibilities

**Lead maintainer**

- Reviews and merges pull requests; no change reaches `main` except through a PR
  with green required checks (branch protection is enforced for everyone,
  including admins).
- Triages issues and private vulnerability reports, and coordinates disclosure
  (see [SECURITY.md](SECURITY.md)).
- Cuts releases: tags a version, runs the signed release pipeline, and reviews
  the published artifacts.
- Owns the project's secrets and infrastructure access listed below.

**Contributors**

- Anyone opening a pull request. Contributors are responsible for signing off
  their commits (DCO), adding tests for new behavior, and keeping the change
  within the scope described in [CONTRIBUTING.md](CONTRIBUTING.md). They do not
  have merge rights or access to the sensitive resources below.

## Access to sensitive resources

The following resources are restricted to the lead maintainer:

| Resource | Purpose |
|----------|---------|
| `arenzana/arca` admin | Repository settings, branch protection, required checks. |
| Repository Actions secrets | `HOMEBREW_TAP_TOKEN`, `SCOOP_GITHUB_TOKEN`, `SCORECARD_TOKEN` — used by the release and scorecard pipelines. |
| `arenzana/homebrew-tap`, `arenzana/scoop-bucket` | Distribution repositories, written to automatically by the release pipeline. |
| Release signing | Releases are signed with keyless **cosign** (Sigstore) using the workflow's OIDC identity — there is no long-lived signing key to hold. |
| GitHub Pages | The project website (`docs/`) is published from the default branch by the Pages workflow. |

Secrets are never stored in the repository in cleartext; they live as encrypted
GitHub Actions secrets and are referenced only by name in workflows.
