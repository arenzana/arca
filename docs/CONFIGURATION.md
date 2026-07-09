# Configuration & storage

[← README](../README.md) · related: [Commands](COMMANDS.md) · [Architecture](ARCHITECTURE.md)

## Environment (ops)

All paths are overridable so the store can live in your dotfiles while the audit log stays local.

| Variable | Purpose | Default |
|---|---|---|
| `ARCA_STORE` | JSON store path (sync this) | `~/.config/arca/store.json` |
| `ARCA_AUDIT` | SQLite audit DB (do **not** sync) | `~/.local/state/arca/audit.db` |
| `ARCA_IDENTITY` | age private key | `$SOPS_AGE_KEY_FILE`, else `~/.config/arca/identity.txt` |
| `ARCA_STRICT_AUDIT` | fail-closed auditing | enabled; a human at a controlling terminal may set `0`/`false`/`off`/`no` for best-effort (ignored for a detected agent or a headless caller) |
| `ARCA_ACTOR` | explicit actor label in the audit | — (OS user / agent auto-detected) |
| `AI_AGENT` | let any agent self-identify: `name` or `name_version_agent` | — |
| `ARCA_AGENT_MARKERS` | register custom agent markers: comma-separated `name=ENVVAR` | — |
| `ARCA_APPROVAL` | `deny` refuses a `--require-approval` release (fail-safe); anything else is ignored — approval always needs an interactive terminal (no `allow` bypass) | — |
| `ARCA_SYNC_URL` | sync backend (`s3://bucket/prefix?endpoint=…`), overrides `arca sync init` | — |
| `ARCA_SYNC_ACCESS_KEY` / `ARCA_SYNC_SECRET_KEY` | sync credentials (fall back to `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`) | — |
| `ARCA_SYNC_AUTO` | force automatic sync on (`1`) or off (`0`), overriding `arca sync auto` | per `sync.json` |
| `XDG_CONFIG_HOME` / `XDG_STATE_HOME` | base dirs | `~/.config` / `~/.local/state` |

Local operational state (session signing keys, grants, handles, the canary registry, and the
sync config/cursor `sync.json` / `sync-state.json`) lives under `$XDG_STATE_HOME/arca/`
alongside the audit DB — never synced.

### AI-agent detection

arca attributes each access to the calling AI agent (visible in `arca log`) by looking for the
runtime markers an agent injects into the commands it launches. Built in: **Claude Code**
(`CLAUDECODE`), **Cursor** (`CURSOR_TRACE_ID`), **Gemini CLI** (`GEMINI_CLI`), and **OpenAI Codex**
(`CODEX_SANDBOX`). For anything else — opencode, Kimi, Aider, Copilot CLI, Amazon Q, … — either:

- have the agent (or a shell wrapper) export **`AI_AGENT=name`** (or `name_version_agent`), or
- register a marker: **`ARCA_AGENT_MARKERS="opencode=OPENCODE,kimi=KIMI_CODE_HOME"`** — each
  `name=ENVVAR` says "if `ENVVAR` is set, the caller is `name`."

Detection keys only on such runtime markers, never on API-key variables (`OPENAI_API_KEY`, …), which
non-agent scripts also set. It is **advisory**: an agent controls its own environment, so this drives
audit attribution and output redaction, not the human-approval gate (which needs a real terminal —
see the [threat model](../docs/THREAT-MODEL.md)).

**Typical deployment:** point `ARCA_STORE` at a (private) dotfiles repo to version the store;
leave the audit DB local and gitignored. The age private key is your single decrypt root — back
it up (e.g. to a password manager). On a new machine: restore the key, `git clone`, done.

**`make` targets:** `build` (reproducible), `test`, `cover`, `vet`, `vuln` (govulncheck),
`sbom` (CycloneDX), `verify`.

## Storage model

```jsonc
// store.json  (git-syncable; 0600)
{
  "version": 1,
  "recipients": ["age1…"],                  // re-encrypted to on every set
  "secrets": {
    "GITHUB_TOKEN": {
      "value": "-----BEGIN AGE ENCRYPTED FILE-----\n…",  // armored age ciphertext
      "created_at": "…", "updated_at": "…",
      "tags": ["github","ci"], "description": "…",
      "rotate_after": "2026-12-01",
      "no_print": false,                     // exec-only when true
      "require_approval": false,             // requires human approval when true
      "canary": false,                       // decoy: any use trips a signed alert
      "require_grant": false,                // usable only via a matching grant
      "rate_limit": 0, "rate_window": "",    // e.g. 10 / "1h"
      "meta": { }                            // open-ended extensibility bag
    }
  }
}
```

Read tracking (`last_read`, counts, full history with agent/session) lives in the **audit DB**,
not here — so reads never dirty git. See [Architecture](ARCHITECTURE.md) for the two-store design
and [the tamper-evident audit note](../SECURITY.md#trust-model--boundaries) for how the log is
hash-chained and signed.
