# Configuration & storage

[← README](../README.md) · related: [Commands](COMMANDS.md) · [Architecture](ARCHITECTURE.md)

## Environment (ops)

All paths are overridable so the store can live in your dotfiles while the audit log stays local.

| Variable | Purpose | Default |
|---|---|---|
| `ARCA_STORE` | JSON store path (sync this) | `~/.config/arca/store.json` |
| `ARCA_AUDIT` | SQLite audit DB (do **not** sync) | `~/.local/state/arca/stores/<store-key>/audit.db` |
| `ARCA_IDENTITY` | age private key | `$SOPS_AGE_KEY_FILE`, else `~/.config/arca/identity.txt` |
| `ARCA_STRICT_AUDIT` | fail-closed auditing | enabled; a human at a controlling terminal may set `0`/`false`/`off`/`no` for best-effort (ignored for a detected agent or a headless caller) |
| `ARCA_ACTOR` | explicit actor label in the audit | — (OS user / agent auto-detected) |
| `AI_AGENT` | let any agent self-identify: `name` or `name_version_agent` | — |
| `ARCA_AGENT_MARKERS` | register custom agent markers: comma-separated `name=ENVVAR` | — |
| `ARCA_APPROVAL` | `deny` refuses a `--require-approval` release (fail-safe); anything else is ignored — approval always needs an interactive terminal (no `allow` bypass) | — |
| `ARCA_AGENT_STRICT` | deny-by-default MCP exposure (same as `arca mcp --strict`): agents see only `arca agent allow`-ed secrets | off (all secrets exposed, with a startup warning) |
| `ARCA_MCP_MAX_OUTPUT` | bytes of a command's output the MCP exec tools capture, per stream; **clamped** to 4 KiB–16 MiB | 1 MiB |
| `ARCA_MCP_TIMEOUT` | wall-clock deadline for a command run by the MCP exec tools (`90s`, `2m`, or bare seconds); **clamped** to 1s–600s | 120s |
| `ARCA_SYNC_URL` | sync backend (`s3://bucket/prefix?endpoint=…`), overrides `arca sync init` | — |
| `ARCA_SYNC_ACCESS_KEY` / `ARCA_SYNC_SECRET_KEY` | sync credentials (fall back to `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`) | — |
| `ARCA_SYNC_AUTO` | force automatic sync on (`1`) or off (`0`), overriding `arca sync auto` | per `sync.json` |
| `XDG_CONFIG_HOME` / `XDG_STATE_HOME` | base dirs | `~/.config` / `~/.local/state` |

### Local state is per store

Local operational state (session signing keys, grants, handles, the canary registry, the rollback
high-water mark `store.gen`, the escrow cursor, and the sync config/cursor `sync.json` /
`sync-state.json`) lives alongside the audit DB under

```
$XDG_STATE_HOME/arca/stores/<store-key>/
```

— never synced. `<store-key>` is derived from the absolute path of the store the command is running
against, so **two stores on one machine keep separate state**. That matters if you run the
documented personal/work split: before 0.8.1 all of this was shared, so a `sync` against your work
store reconciled it against your personal store's backend and replaced its contents, and the
second store's legitimately lower generation tripped the rollback warning against the first
store's high-water mark.

Two spellings of one store still key to two dirs if you symlink the store *file* itself, or if its
parent directory doesn't exist yet when the key is first computed — symlinks are resolved on the
directory, never the file. A split is the safe direction: the store's state looks fresh and
`arca doctor` names the dirs so you can merge them.

Two entries are deliberately **not** per store:

- **`$XDG_STATE_HOME/arca/machine-id`** identifies this *machine* to escrow. Keying it per store
  would fork one machine into several escrow identities, each with its own segment sequence.
- **`$ARCA_AUDIT`**, when you set it. The default audit DB is per store, because two stores sharing
  one DB interleave their hash chains and `arca log --verify` on either reads the other's events as
  its own. Setting `ARCA_AUDIT` explicitly is how you opt into one shared log anyway.

  **One restriction:** if arca detects an AI agent and `$ARCA_AUDIT` points anywhere other than the
  store's own audit DB, the command is refused. An agent controls its own environment, so an
  honoured redirect would hand it an unread log *and* a fresh rate-limit window on every secret —
  the audit log is what the rate limit counts. Here there is no controlling-terminal hatch of the
  kind `ARCA_STRICT_AUDIT=0` and `get --no-log` use: an agent running under a pty has a terminal,
  and a hatch here would return the bypass. (`exec`'s forced redaction is anchored the same way —
  detection alone, no terminal test.) Nothing changes for an operator, headless or not. If a
  human's shell exports an agent marker (`AI_AGENT`, `CLAUDECODE`, …), unset it for that command;
  the refusal names the expected path.

**Upgrading:** the first arca command after the upgrade moves the existing flat state into the
per-store directory for whichever store it is running against, once. Nothing is copied and nothing
is deleted. If you have a second store, it starts with empty state — that is the fix working, and
`arca doctor` reports which store adopted the shared state so the empty grants list is explained
rather than mysterious. If it is really the same store under a new path, move the directory
`arca doctor` names to the one it reports for the current store.

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
