<p align="center">
  <img src="assets/arca-light.png" alt="arca logo" width="160">
</p>

# arca

> *arca* (Latin): a strongbox or chest for keeping valuables under lock.

A small CLI secret store built on [age](https://github.com/FiloSottile/age): **cleartext metadata,
per-value encryption, and a local audit log**. The store is a single JSON file (diff-friendly,
git-syncable); each value is an individually age-encrypted blob, so `ls`/`show`/`log` work without
the key and `get` only ever decrypts the one secret you asked for. Access is recorded in a local
SQLite log, so you can answer *when was this read, and by what?*

No daemon, no account, no proprietary backend — just age + your existing identity.

## Why

- **JSON store** → readable, `jq`-able, merges and diffs in git; unchanged secrets keep
  byte-identical ciphertext, so history shows exactly what changed.
- **Per-value encryption** → query metadata and list secrets without decrypting anything.
- **SQLite audit (separate, local)** → reads never churn the synced store; rich access queries.
- **age identity reuse** → defaults to your `$SOPS_AGE_KEY_FILE`.

## Install

```sh
go install github.com/arenzana/arca@latest
```

## Quickstart

```sh
arca init                          # reuses $SOPS_AGE_KEY_FILE, or generates an identity
printf '%s' "$TOKEN" | arca set GITHUB_TOKEN --tag github,ci --desc "classic PAT"
arca ls --reads                    # metadata + last-read/count (no decryption)
arca get GITHUB_TOKEN              # decrypts just this one; logs the read
arca exec -- terraform apply       # inject secrets as env into a subprocess (audited)
arca rotate GITHUB_TOKEN --rotate-after 2026-12-01   # replace value; set next rotation
arca stale                         # secrets past their rotate-after date
arca log GITHUB_TOKEN              # who/what read it, and when
```

Migrate an existing sops dotenv:

```sh
sops -d ~/.dotfiles/secrets/secrets.env | arca import
```

## Storage model

```jsonc
// store.json  (git-syncable; 0600)
{
  "version": 1,
  "recipients": ["age1…"],
  "secrets": {
    "GITHUB_TOKEN": {
      "value": "-----BEGIN AGE ENCRYPTED FILE-----\n…",  // armored age ciphertext
      "created_at": "…", "updated_at": "…",
      "tags": ["github","ci"], "description": "…",
      "rotate_after": "2026-12-01",
      "meta": { }                                          // open-ended bag
    }
  }
}
```

Read tracking (`last_read`, counts, history) lives in the **audit DB**, not the store — so reads
don't dirty git.

## Paths

| What | Env override | Default |
|---|---|---|
| store (sync this) | `ARCA_STORE` | `~/.config/arca/store.json` |
| audit db (local) | `ARCA_AUDIT` | `~/.local/state/arca/audit.db` |
| age identity | `ARCA_IDENTITY` | `$SOPS_AGE_KEY_FILE` or `~/.config/arca/identity.txt` |

Point `ARCA_STORE` at your dotfiles to version the store; leave the audit DB local and gitignored.

## Security notes

- Secret values are read from a TTY (no echo) or piped stdin — **never** passed as CLI args.
- Store and audit files are written `0600`, store writes are atomic (temp + rename).
- Metadata (names, tags, descriptions) is **cleartext** by design, so the store reveals *which*
  secrets exist (same tradeoff as a sops dotenv) — that's what makes decrypt-free listing possible.
- `arca env` is a convenience bulk-dump and **bypasses per-read auditing**; prefer `exec`/`get`
  for anything you want tracked.
- The age private key is your single decrypt root — back it up (e.g. to a password manager).

## Supply chain & releases

Built as security software: **reproducible** builds (`CGO_ENABLED=0`, `-trimpath`, pinned
timestamps), **cosign**-signed checksums, a **CycloneDX SBOM**, and **SLSA build-provenance**
attestations on every release. CI runs `go vet`, `go test -race`, `go mod verify`, and
`govulncheck`. See [SECURITY.md](SECURITY.md) for verification steps.

## Designed for AI agents

arca is a file-based secrets broker you can safely put in front of an AI agent:

- **Use without revealing.** `arca exec -- <cmd>` injects secrets into a subprocess's environment —
  the command uses the value, but it never prints into the agent's context or transcript.
- **Attributed audit.** Set `ARCA_ACTOR` (e.g. the agent/session name) and every access is logged
  with it, so `arca log` answers *which agent touched which secret, and when*.
- **Least privilege.** `--only` injects just the secrets a task needs, not the whole store.
- **Metadata without secrets.** `ls` / `show` let an agent discover what exists (names, tags,
  descriptions) and reason about it without ever decrypting a value.

More agent controls — per-secret access policies, human approval gates, JSON output, and an MCP
server — are on the roadmap.

## License

MIT

