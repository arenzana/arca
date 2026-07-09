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
- **Rollback detection extends to the network (SEC-14).** A remote head that went
  *backwards* (a restored bucket, a tampering backend) is refused on sync. Immutable
  `store/revs/<generation>.age` objects replace git history as the forensic trail.
- **Offline is a normal state.** The local file remains the source of truth for every
  read and exec; sync never sits in an access path. Automatic mode runs strictly
  *after* a command's real work and any failure is a warning, never an error.

## Automatic sync

`arca sync auto on` (or `ARCA_SYNC_AUTO=1`) makes every command opportunistic: a
command that mutated the store pushes the change afterwards, and any command
reconciles when the last sync is older than 15 minutes. Network work is bounded by a
10-second timeout and can never fail the command it rides on. The MCP server process
does not auto-sync (it is long-running; run `arca sync` or rely on the CLI's habits).

## Configuration

| What | How |
|---|---|
| Backend URL | `ARCA_SYNC_URL`, or pinned via `arca sync init URL` (state dir, `0600`) |
| Credentials | `ARCA_SYNC_ACCESS_KEY` / `ARCA_SYNC_SECRET_KEY` (fall back to `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`) |
| Automatic mode | `arca sync auto on\|off`, overridable by `ARCA_SYNC_AUTO=1/0` |

URL parameters: `endpoint` (S3-compatible host), `region`, `insecure=1` (plain HTTP,
local dev only), `pathstyle=1` (default whenever `endpoint` is set). Credentials never
go in the URL.

Sync credentials live *outside* the store on purpose: a new machine needs them before
it has a store. Protect them like the age identity file.
