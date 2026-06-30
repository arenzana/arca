# Stability policy

From v1.0 onward, arca follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). This
document spells out which surfaces that covers, so you know what you can depend on and what may
change between releases.

## Versioning

- **MAJOR** (`x.0.0`) — a backward-incompatible change to a stable surface listed below.
- **MINOR** (`1.x.0`) — new, backward-compatible features.
- **PATCH** (`1.0.x`) — backward-compatible bug and security fixes.

## Stable surfaces

These do not change incompatibly without a major-version bump:

- **Commands and flags.** Existing subcommands, their arguments, and their flags keep their
  meaning and defaults. New commands and flags may be added in a minor release.
- **Exit codes.** `0` on success, non-zero on failure; `exec` propagates the child's exit code.
- **Store schema.** The on-disk store stays a single JSON document — per-value age ciphertext
  plus cleartext metadata — carrying a `version` field. A 1.x release always reads a store
  written by an earlier 1.x, migrating it forward on load.
- **References.** The `arca://NAME` syntax and how `inject` resolves it.
- **Configuration.** The `ARCA_STORE`, `ARCA_AUDIT`, `ARCA_IDENTITY`, `ARCA_ACTOR`,
  `ARCA_APPROVAL`, and `ARCA_STRICT_AUDIT` environment variables, plus the XDG/default paths.
- **Policy semantics.** `--no-print`, `--require-approval`, TTL/expiry, fail-closed auditing,
  and the agent-aware restrictions on those overrides behave as documented.
- **`--json` output.** The JSON shapes from `ls`, `show`, `log`, and `stale`. Fields may be
  added; existing fields keep their name and meaning.
- **MCP tools.** The names `list_secrets`, `show_secret`, `run_with_secrets`, `read_secret`,
  `audit_log`, and their documented inputs and outputs.

## Not covered

These may change in any release — do not build automation on them:

- **Human-readable output** — the wording, column layout, and spacing of non-`--json` output.
  Parse `--json`, not the table text.
- **Log and error message wording.**
- **Internal Go packages** (`internal/…`) and any unexported API. arca is a CLI, not a library.
- **The audit database file layout** beyond "a local SQLite log." Read it with `arca log`
  (or `--json`), not by querying the table directly.

## Deprecation

A stable surface that must change is first **deprecated**: it keeps working and emits a warning
for at least one minor release before removal in the next major. Deprecations are recorded in
[CHANGELOG.md](CHANGELOG.md).

## Supported platforms

Linux, macOS, and Windows on amd64 and arm64. Released binaries are static (CGO-free),
reproducible, cosign-signed, and carry SLSA build provenance — see [SECURITY.md](SECURITY.md).

## Security exception

A security fix may, in rare cases, change documented behavior within a minor or patch release
when that is the only way to close a vulnerability. Any such change is called out in the
changelog and the corresponding security advisory.
