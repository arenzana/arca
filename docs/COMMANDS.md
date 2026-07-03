# Command reference

[← README](../README.md) · related: [Policies](POLICIES.md) · [Importing](IMPORTING.md) · [MCP](MCP.md) · [Configuration](CONFIGURATION.md)

| Command | Purpose | Key flags |
|---|---|---|
| `init` | Create the store (reuse or generate an age key) | `--force` |
| `set NAME` | Add/update a secret (value from TTY or stdin) | `--tag --desc --rotate-after --ttl --expires-at --meta k=v --no-print --require-approval --canary --require-grant --rate N/D` |
| `generate NAME` | Create a secret with a random value | `-l/--length --charset --tag --desc --ttl --no-print --show --canary --require-grant --rate N/D` |
| `get NAME` | Decrypt and print one secret (records a read) | `-n` (newline), `--no-log` |
| `rotate NAME` | Replace value, keep `created_at`, log a rotation | `--rotate-after --ttl --expires-at` |
| `ls` | List secrets + metadata (no decryption) | `--tag`, `--reads`, `--json` |
| `show NAME` | Show one secret's metadata (no value) | `--json` |
| `stale` | Secrets overdue/soon for rotation, or expired/expiring | `--within N`, `--missing`, `--json` |
| `rm NAME` | Remove a secret | — |
| `disable NAME` | Suspend a secret — refused on every access path — without deleting it or changing its value (a distinct kill switch, independent of expiry) | — |
| `enable NAME` | Re-enable a disabled secret (keeps any real expiry) | — |
| `edit NAME` | Edit a secret's value in `$EDITOR` (re-encrypted) | — |
| `rename OLD NEW` | Rename a secret, preserving metadata/history (alias `mv`) | `--force` |
| `annotate NAME` | Edit a secret's tags/description/metadata **without** changing its value (works on `--no-print` secrets) | `--tag --add-tag --rm-tag --desc --meta k=v --rm-meta` |
| `recipients` | List age recipients; `add`/`rm` subcommands manage the set | — |
| `reencrypt` | Re-encrypt every secret to the current recipient set | — |
| `import` | Bulk-load secrets from stdin (dotenv lines, or a JSON object) — see [Importing](IMPORTING.md) | `--json`, `--dry-run`, `--overwrite`, `--prefix P`, `--tag t` |
| `inject` | Resolve `arca://NAME` references on stdin → stdout | — |
| `exec -- CMD` | Run CMD with secrets injected as env (audited); injected values are redacted from its output | `--only a,b`, `--redact auto\|on\|off`, `--reveal` |
| `env` | Emit `export …` for `eval "$(arca env)"` | `--no-export` |
| `log [NAME]` | Access history (agent/session/actor); `--verify` checks the log's integrity | `--limit N`, `--json`, `--verify`, `--require-signed` |
| `canary [NAME]` | Plant a decoy secret (any use trips a signed alert), or list canaries and their trips | `--template`, `--list`, `--tag`, `--desc` |
| `grant SECRET` | Authorize a `--require-grant` secret for a command, a number of uses, and a window | `--command`, `--uses`, `--ttl`, `--agent` |
| `grants` | List active grants and their remaining uses | — |
| `revoke SECRET` | Remove the active grant for a secret | — |
| `handle create SECRET` | Mint an opaque capability handle an agent can use (via MCP) without the secret's name/value — operator-only (refused for a detected agent) | `--ttl`, `--command`, `--as`, `--override` |
| `handle ls` / `handle revoke ID` | List or revoke handles | — |
| `mcp` | Run an MCP server exposing arca to AI agents (stdio) — see [MCP](MCP.md) | — |
| `version` | Print version, commit, build date, and toolchain (`arca --version` prints just the version) | `--json` |
| `completion SHELL` | Shell completion script (bash/zsh/fish/powershell) | — |

Values are always read from a TTY (no echo) or piped stdin — **never** passed as arguments.

The per-secret policy flags (`--no-print`, `--require-approval`, `--canary`, `--require-grant`,
`--rate`) are documented in [Policies](POLICIES.md).

## Disabling a secret (fast, reversible kill switch)

`disable NAME` is the quickest way to take a secret out of service without losing it: the value and
all metadata stay in the store, but every access path — `get`, `exec`, `inject`, `env`, and the MCP
tools — refuses it until you `enable` it again. It's a dedicated flag, independent of expiry, so a
disabled secret shows as `DISABLED` in `show` / `[disabled]` in `ls`, the audit log records the
`disable`/`enable` intent, and — unlike before 0.6.3 — enabling it **keeps any real expiry** the
secret was carrying (disable/enable no longer touch `expires_at`).

```bash
arca disable GITHUB_TOKEN     # suspend it everywhere, keep the value + any expiry
arca enable  GITHUB_TOKEN     # bring it back (a real expiry, if any, is preserved)
```

> Upgrade note: secrets disabled by an arca **before 0.6.3** were suspended by stamping `expires_at`
> to now, so they read as `EXPIRED` (not `DISABLED`); clear that with `rotate` / `set --expires-at`.

**This is a *local* kill switch, not revocation.** Disabling stops *arca* from handing the value out;
it does nothing to a copy that already leaked. On a suspected compromise, **revoke the token at its
issuer first** (GitHub, AWS, …), then `disable` or `rotate` it here.

Note: `env` skips any secret it can't release — disabled/expired and `--require-grant` — instead of
failing, so one suspended secret never blanks out `eval "$(arca env)"`.
