# Changelog

All notable changes to arca are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches 1.0.

## [Unreleased]

### Added
- `STABILITY.md` — the v1.0 SemVer policy: which surfaces (commands, exit codes, store schema,
  `arca://` references, `ARCA_*` config, `--json` output, MCP tools) are stable, and what isn't.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and issue/PR templates.
- `MAINTAINERS.md` — maintainers, roles, and who holds access to sensitive resources.
- `docs/ARCHITECTURE.md` — design documentation (actors, components, and the agent-aware
  policy invariant) and `docs/THREAT-MODEL.md` — the documented security assessment.
- Developer Certificate of Origin: a `Signed-off-by` trailer is now required on every commit
  and enforced by a `dco` CI check; `CONTRIBUTING.md` documents `git commit -s`.
- `CONTRIBUTING.md` now documents how dependencies are selected, obtained, and tracked.

## [0.3.0] - 2026-06-30

### Added
- `generate NAME` creates a secret with a cryptographically-random value (`--length`,
  `--charset alnum|hex|full|<custom>`, `--show`), so a password/token is never typed.
- `edit NAME` opens a secret's value in `$EDITOR` and re-encrypts it on save (the plaintext
  touches a `0600` temp file, scrubbed and removed afterward).
- `rename OLD NEW` (alias `mv`) renames a secret while preserving its metadata and history.
- Homebrew install via a tap: `brew install arenzana/tap/arca` (the cask is published to
  `arenzana/homebrew-tap` on each release).
- Scoop install on Windows (the manifest is published to `arenzana/scoop-bucket` on release).
- `go install` builds now report the module version (from build info) instead of `dev`.
- Windows support for the approval prompt: `--require-approval` now reads from the Windows
  console (`CONIN$`/`CONOUT$`) instead of `/dev/tty`, which does not exist on Windows.
- Store-level locking: every mutation (`set`/`rotate`/`rm`/`import`/`reencrypt`/`recipients`)
  takes an exclusive lock around its read-modify-write, so concurrent writers can no longer lose
  an update. A lock left by a crashed process (older than 30s) is reclaimed automatically.
- Schema-migration framework: an older store is upgraded to the current schema on load, so a
  future incompatible change can ship a migration rather than break existing stores. A store
  with no version field is treated as the v1 baseline.

### Changed
- CI now runs the unit and end-to-end suites on Linux, macOS, and Windows (previously Linux
  only; release targets were cross-compiled but never tested).

## [0.2.0] - 2026-06-30

### Added
- TTL / ephemeral secrets: `set --ttl 30m|12h|7d|2w` or `--expires-at`; an expired secret is
  refused on every access path and surfaced by `stale`.
- JSON output: `--json` on `ls`, `show`, `log`, and `stale`.
- Shell completion with dynamic secret-name and tag suggestions.
- Multi-recipient / teams: `recipients add`/`rm` plus `reencrypt` to re-wrap the whole store to
  the current age recipient set.
- MCP server (`arca mcp`): lets an agent use secrets through audited tools without the value
  entering the model context.

### Security
- Secret-name validation blocks shell injection via `eval "$(arca env)"` and `LD_PRELOAD`-style
  environment hijacking.
- Agent-aware policy: a detected AI agent cannot self-approve a `--require-approval` secret,
  suppress its own read record, or weaken fail-closed auditing.
- Store hardening: reject null, oversized, or newer-versioned store files; bounded stdin reads;
  the private key is created with `O_EXCL`; the store is fsynced before the atomic rename.
- Release pipeline runs `vet`/`test`/`govulncheck` before building; the cosign certificate is
  published alongside the signature; build provenance covers `checksums.txt`.
- CI gained a `gosec` + `staticcheck` lint job, and CodeQL now scans the workflows themselves.

## [0.1.0] - 2026-06-29

### Added
- Initial release: age-encrypted per-value secrets with cleartext metadata in a single JSON
  store, and a local SQLite audit log of every access attributed to the calling AI agent.
- Commands: `init`, `set`, `get`, `rotate`, `ls`, `show`, `stale`, `rm`, `import`, `inject`,
  `exec`, `env`, `log`.
- Per-secret policy: `--no-print` (exec-only) and `--require-approval` (human gate).
- `arca://NAME` references resolved by `inject`; least-privilege `exec --only`.
- Fail-closed auditing by default; agent name/version/session auto-detection.
- Supply chain: reproducible static builds, cosign keyless signatures, SLSA build-provenance,
  CycloneDX SBOM, govulncheck, CodeQL, OpenSSF Scorecard, SHA-pinned actions.

[Unreleased]: https://github.com/arenzana/arca/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/arenzana/arca/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/arenzana/arca/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/arenzana/arca/releases/tag/v0.1.0
