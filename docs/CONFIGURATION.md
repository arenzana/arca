# Configuration & storage

[← README](../README.md) · related: [Commands](COMMANDS.md) · [Architecture](ARCHITECTURE.md)

## Environment (ops)

All paths are overridable so the store can live in your dotfiles while the audit log stays local.

| Variable | Purpose | Default |
|---|---|---|
| `ARCA_STORE` | JSON store path (sync this) | `~/.config/arca/store.json` |
| `ARCA_AUDIT` | SQLite audit DB (do **not** sync) | `~/.local/state/arca/audit.db` |
| `ARCA_IDENTITY` | age private key | `$SOPS_AGE_KEY_FILE`, else `~/.config/arca/identity.txt` |
| `ARCA_STRICT_AUDIT` | fail-closed auditing | enabled; set `0`/`false`/`off`/`no` for best-effort |
| `ARCA_ACTOR` | explicit actor label in the audit | — (OS user / agent auto-detected) |
| `ARCA_APPROVAL` | short-circuit the approval prompt | — (`allow`/`deny`; else interactive `/dev/tty`) |
| `XDG_CONFIG_HOME` / `XDG_STATE_HOME` | base dirs | `~/.config` / `~/.local/state` |

Local operational state (session signing keys, grants, handles, the canary registry) lives under
`$XDG_STATE_HOME/arca/` alongside the audit DB — never synced.

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
