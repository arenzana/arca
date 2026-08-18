# Command reference

[← README](../README.md) · related: [Policies](POLICIES.md) · [Importing](IMPORTING.md) · [MCP](MCP.md) · [Configuration](CONFIGURATION.md)

| Command | Purpose | Key flags |
|---|---|---|
| `init` | Create the store (reuse or generate an age key) | `--force` |
| `set NAME` | Add/update a secret (value from TTY or stdin) | `--tag --desc --rotate-after --ttl --expires-at --meta k=v --no-print --require-approval --canary --require-grant --rate N/D --allow-empty` |
| `generate NAME` | Create a secret with a random value | `-l/--length --charset --tag --desc --ttl --no-print --show --canary --require-grant --rate N/D` |
| `get NAME` | Decrypt and print one secret (records a read) | `-n` (newline), `--no-log` |
| `rotate NAME` | Replace value, keep `created_at`, log a rotation | `--rotate-after --ttl --expires-at --allow-empty` |
| `ls` | List secrets + metadata (no decryption) | `--tag`, `--no-rotation`, `--reads`, `--json` |
| `show NAME` | Show one secret's metadata (no value) | `--json` |
| `stale` | Secrets overdue/soon for rotation, or expired/expiring | `--within N`, `--json` |
| `rm NAME` | Remove a secret | — |
| `disable NAME` | Suspend a secret — refused on every access path — without deleting it or changing its value (a distinct kill switch, independent of expiry) | — |
| `enable NAME` | Re-enable a disabled secret (keeps any real expiry) | — |
| `edit NAME` | Edit a secret's value in `$EDITOR` (re-encrypted) | — |
| `rename OLD NEW` | Rename a secret, preserving metadata/history (alias `mv`) | `--force` |
| `annotate NAME` | Edit a secret's tags/description/metadata **without** changing its value (works on `--no-print` secrets) | `--tag --add-tag --rm-tag --desc --meta k=v --rm-meta` |
| `recipients` | List age recipients (with labels); `add`/`rm`/`pin` subcommands manage the set | `add --label name@machine` |
| `who-can-read [NAME]` | Show which recipients can decrypt the store (or one secret); flags high-privilege names | — |
| `exposure` | List secrets by blast radius (recipients that can decrypt each); flags master/admin-looking names | `--sensitive` |
| `doctor` | Security & health check of your setup, ranked by severity with a remedy per finding | `--json`, `--fix` |
| `reencrypt` | Re-encrypt every secret to the current recipient set | — |
| `import` | Bulk-load secrets from stdin (dotenv lines, or a JSON object) — see [Importing](IMPORTING.md) | `--json`, `--dry-run`, `--overwrite`, `--allow-empty`, `--prefix P`, `--tag t` |
| `inject` | Resolve `arca://NAME` references on stdin → stdout | — |
| `exec -- CMD` | Run CMD with secrets injected as env (audited); injected values are redacted from its output | `--only a,b`, `--redact auto\|on\|off`, `--reveal` |
| `env` | Emit `export …` for `eval "$(arca env)"` | `--no-export` |
| `sync` | Replicate the store through an S3-compatible backend (see [SYNC.md](SYNC.md)); envelope-encrypted, CAS-safe | `--pull`, `--push`, `--force`, `--admit-recipients`; `sync init URL`, `sync status`, `sync auto on\|off`, `sync reset-escrow` |
| `signer show` | Print this machine's store-signing public key (headless-safe; generates the key on first use) | — |
| `signer pin PUBKEY` | Accept a store-signing public key as this machine's expected signer — terminal-anchored | — |
| `signer rotate` | Generate a new store-signing key and pin it here — terminal-anchored; other machines then need `signer pin` | — |
| `log [NAME]` | Access history (agent/session/actor); `--verify` checks the log's integrity | `--limit N`, `--json`, `--verify`, `--require-signed`, `--anchor TOKEN`, `--remote`, `--print-anchor` |
| `canary [NAME]` | Plant a decoy secret (any use trips a signed alert), or list canaries and their trips | `--template`, `--list`, `--tag`, `--desc` |
| `grant SECRET` | Authorize a `--require-grant` secret for a command, a number of uses, and a window. `--agent` is advisory (env sniffing), not a containment boundary | `--command`, `--uses`, `--ttl`, `--agent` |
| `grants` | List active grants and their remaining uses | — |
| `revoke SECRET` | Remove the active grant for a secret | — |
| `handle create SECRET` | Mint an opaque capability handle an agent can use (via MCP) without the secret's name/value — operator-only (refused for a detected agent), and refused for a disabled secret | `--ttl`, `--command`, `--as`, `--override` |
| `handle ls` / `handle revoke ID` | List or revoke handles | — |
| `mcp` | Run an MCP server exposing arca to AI agents (stdio) — see [MCP](MCP.md) | `--strict` (deny-by-default agent exposure) |
| `agent allow/deny/ls NAME` | Manage which secrets a `--strict` MCP server exposes to agents | — |
| `version` | Print version, commit, build date, and toolchain (`arca --version` prints just the version) | `--json` |
| `completion SHELL` | Shell completion script (bash/zsh/fish/powershell) | — |

Values are always read from a TTY (no echo) or piped stdin — **never** passed as arguments.

An **empty read is refused** on every write path (`set`, `rotate`, and `import --overwrite`). The
case this exists for is a pipe whose producer failed:

```bash
vault-cli read prod/key | arca set PRODKEY    # producer fails, prints nothing…
```

Without the guard, stdin closes empty, arca reports success, and the stored value is gone — the
store keeps only the current value, so there is no undo. Pass `--allow-empty` when you genuinely
mean to store nothing. Whitespace is a value, not an absence: a single space is stored, while
`""`, a bare newline, and CRLF are refused.

The per-secret policy flags (`--no-print`, `--require-approval`, `--canary`, `--require-grant`,
`--rate`) are documented in [Policies](POLICIES.md).

## Disabling a secret (fast, reversible kill switch)

`disable NAME` is the quickest way to take a secret out of service without losing it: the value and
all metadata stay in the store, but every access path — `get`, `exec`, `inject`, `env`, and the MCP
tools, **including a capability handle minted before you disabled it** — refuses it until you
`enable` it again. Handles are made inert rather than revoked, so undoing a false alarm restores the
pre-incident state exactly instead of forcing you to re-issue every handle you had handed out. It's a dedicated flag, independent of expiry, so a
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

## Accepting a recipient set (`recipients pin`)

arca records the recipient set each machine has been shown, in `recipients.pin` under that
machine's state dir. The file never syncs: it is this machine's memory of what it expects, and a
baseline that travelled with the store would be controlled by whoever controls the store.

Adding a recipient here is already guarded by an operator prompt. A recipient added on **another**
machine and pulled in by sync is not, so the store can arrive carrying a key nobody here was ever
shown. When that happens arca warns on every load and `doctor` raises its readership check to HIGH
and names the key. Review it with `arca who-can-read`, then either:

- `arca recipients pin` to accept the current set as expected (prompts on the terminal, listing the
  keys that are not yet accepted, and records `op=recipients-pin` in the audit log), or
- `arca recipients rm KEY` to drop it.

The warning repeats until you do one or the other. Loading the store never accepts a key by itself,
because a warning that silenced itself would report an injected key exactly once.

The baseline is established silently the first time a store is loaded, so a key that was already
present at that point is accepted without comment. Reviewing `arca who-can-read` once, on a store
that predates this check, is the way to close that gap.

## Removing a recipient (`recipients rm`)

`recipients rm KEY` drops an age recipient (e.g. an ex-teammate's key) and **re-encrypts every secret
to the remaining keys in the same step**, so the *current* store immediately stops being decryptable
by the removed key. Use `--no-reencrypt` to defer the re-wrap to a later `arca reencrypt`.

**Re-encryption is not revocation of what was already read.** The removed key can still decrypt any
copy it already had — local clones, backups, and **every prior version of the store in git history**.
`recipients rm` prints this warning and lists the secrets to rotate. To *truly* deny the removed
holder a secret, **rotate its value** (`arca rotate NAME`) so the old ciphertext decrypts to a dead
value — and, as always, revoke the underlying credential at its issuer.
