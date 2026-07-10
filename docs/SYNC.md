# Syncing the store between machines

The store is one file, and it has always been fine to sync it however you like (a git
repo, a dotfiles manager). `arca sync` replaces "however you like" with a first-class
answer: replication through any **S3-compatible backend** (Cloudflare R2, MinIO,
Garage, AWS S3) that is **untrusted by construction** and safe against lost updates.

```sh
arca sync init "s3://my-bucket/arca?endpoint=minio.example.net:9000"   # once per machine
export ARCA_SYNC_ACCESS_KEY=… ARCA_SYNC_SECRET_KEY=…                   # backend credentials

arca sync            # reconcile: pull if the remote is ahead, push if local is ahead
arca sync status     # local vs remote generation, last sync
arca sync auto on    # opportunistic sync: push after writes, periodic pull
```

## What the backend sees

Nothing. The uploaded envelope is the whole store wrapped in **one more age layer to
the store's own recipients** — on top of the per-value encryption the store already
has. Names, tags, descriptions, policy, even the JSON shape are invisible to the
backend; it stores bytes and learns only size and timing. Any machine holding a
recipient identity can open the envelope, which is exactly the multi-machine model:

```sh
# on a new machine: identity file + backend URL is all it takes
arca sync init "s3://my-bucket/arca?endpoint=…"
arca sync        # bootstraps the local store from the remote
```

## Safety model

- **Lost updates are impossible.** Every push is a conditional write (CAS): an
  immutable revision object per generation (`If-None-Match: *`) plus a head flip
  gated on the last-seen ETag (`If-Match`). Two machines racing produce one winner
  and one loud error — never a silent overwrite. AWS S3, R2, and MinIO enforce
  these conditions server-side (proven against a real MinIO in CI).
- **Conflicts are reported, never merged.** If both sides advanced, `arca sync`
  explains the divergence and stops. `arca sync --pull` adopts the remote (explicitly
  discarding local divergence); there is no auto-merge of a secrets store.
- **Rollback / replay / recipient-broadening are refused on pull.** The rollback floor is the
  durable high-water mark, checked before the local store is touched; a backend serving an
  envelope older than the head it advertises, or a store that *adds* a recipient not already
  local, is refused (use `--force` to adopt a legitimately-broader store, e.g. a teammate's new
  key). Immutable `store/revs/<generation>.age` objects are the forensic trail.
- **The escrowed audit trail is truncation-checked.** `log --verify --remote` refuses if the
  backend has fewer segments than this machine escrowed. **Caveat — authenticity:** age gives the
  backend *confidentiality* (it sees only ciphertext), not *authentication*. A backend that both
  knows the recipients and serves a strictly-newer forged store can still substitute content;
  the complete defense is an operator signature over the store, planned. Treat the backend as
  honest-but-curious today; the refusals above close the replay/rollback class.
- **Offline is a normal state.** The local file remains the source of truth for every
  read and exec; sync never sits in an access path. Automatic mode runs strictly
  *after* a command's real work and any failure is a warning, never an error.

## Automatic sync

`arca sync auto on` (or `ARCA_SYNC_AUTO=1`) makes every command opportunistic: a
command that mutated the store pushes the change afterwards, and any command
reconciles when the last sync is older than 15 minutes. Network work is bounded by a
10-second timeout and can never fail the command it rides on. The MCP server process
does not auto-sync (it is long-running; run `arca sync` or rely on the CLI's habits).

## The audit trail follows (Option B escrow)

Every sync also ships the increment of this machine's **audit log** as an append-only,
age-encrypted segment (`audit/<machine-id>/<seq>.age`, create-only). The local SQLite
log remains the operational, fail-closed witness — escrow adds an off-machine copy a
local tamperer cannot retract:

```sh
arca log --verify --remote   # the local chain must extend its escrowed history
```

A rewritten or truncated local log diverges from its own escrowed prefix and fails the
check; segments themselves are continuity-chained (each carries its predecessor's
anchor), so segments removed or replaced on the backend are detected client-side.
Escrow is best-effort: a failure warns and retries on the next sync, and it never
blocks a secret access. What it deliberately does **not** provide is fleet-wide
*enforcement* (rate limits across machines) — that requires a trusted arbiter, which
the dumb backend is not.

## Configuration

| What | How |
|---|---|
| Backend URL | `ARCA_SYNC_URL`, or pinned via `arca sync init URL` (state dir, `0600`) |
| Credentials | `ARCA_SYNC_ACCESS_KEY` / `ARCA_SYNC_SECRET_KEY` (fall back to `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`), or persisted once via `sync init URL --store-credentials` (state dir, `0600`) — env wins when both exist |
| Automatic mode | `arca sync auto on\|off`, overridable by `ARCA_SYNC_AUTO=1/0` |

URL parameters: `endpoint` (S3-compatible host), `region`, `insecure=1` (plain HTTP,
local dev only), `pathstyle=1` (default whenever `endpoint` is set). Credentials never
go in the URL.

Sync credentials live *outside* the store on purpose: a new machine needs them before
it has a store. `--store-credentials` keeps them next to the audit DB with `0600` —
the same protection class as the age identity file, and what makes automatic sync
work without any shell environment. A neat bootstrap that keeps the canonical copy in
arca itself:

```sh
arca exec --only ARCA_SYNC_ACCESS_KEY,ARCA_SYNC_SECRET_KEY -- \
  arca sync init "s3://arca?endpoint=…" --store-credentials --auto
```
