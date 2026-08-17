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
backend; it stores bytes and learns only size and timing. Only a machine holding one of
the store's recipient identities can open the envelope — which is exactly the
multi-machine model.

Age is confidentiality, not authentication. Each push also signs the store bytes
with an operator-held Ed25519 key (`arca signer show`) and writes `Arca-Signature`
/ `Arca-Signer` on the object. A pull verifies that signature against a **locally
pinned** public key (`arca signer pin`). A backend that knows the (public)
recipients can no longer fabricate a policy-stripped store that every machine
will adopt. `--force` cannot override a pin mismatch; rotation is
`arca signer rotate` on the signing machine, then `arca signer pin <new>` on the
others. A machine with no pin still accepts an unsigned head (migration window,
with a warning) but will refuse a signed head until the key is pinned
out-of-band.

## Adding a machine to the fleet

Each machine has its **own** age identity (there is no shared key). The store is
encrypted to every machine's recipient key, so joining a new machine is two moves — mint
its key and add it as a recipient — before it can pull. (A store pulled from the backend
that *adds* a recipient your local store doesn't have is refused, so a new machine can't
simply "adopt" the fleet store; it has to be granted access from a machine already in it.)

```sh
# 1. On the NEW machine — install arca, generate its identity, note the recipient key,
#    and drop the empty starter store so the first sync bootstraps cleanly.
arca init                                  # prints:  recipients: age1newmachine…
rm ~/.config/arca/store.json               # keep the identity, discard the fresh store

# 2. On a machine ALREADY in the fleet — grant the new key and push.
arca recipients add age1newmachine…
arca reencrypt                             # re-wrap every secret to the new key too
arca sync                                  # push the updated store

# 3. Back on the NEW machine — point it at the backend and pull.
arca sync init "s3://my-bucket/arca?endpoint=…" --store-credentials --auto
arca sync                                  # bootstraps the local store from the remote
```

Step 3's `--store-credentials` persists the backend keys next to the identity (0600) so
automatic sync needs no shell environment; `--auto` turns on opportunistic sync. To pass
credentials to a remote host without putting them on a command line, feed them over stdin:

```sh
printf '%s\n%s\n' "$ACCESS_KEY" "$SECRET_KEY" | ssh host \
  'read -r ak; read -r sk; ARCA_SYNC_ACCESS_KEY=$ak ARCA_SYNC_SECRET_KEY=$sk \
   arca sync init "s3://my-bucket/arca?endpoint=…" --store-credentials --auto'
```

Removing a machine is the reverse: `recipients rm age1…` + `reencrypt` on any fleet
machine, then rotate any secrets that machine could have read (removing a recipient stops
it decrypting *future* stores, not copies it already holds — see the `recipients rm`
warning).

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
- **A sync cannot lose a concurrent local change.** The CAS above arbitrates between
  *machines*; this one arbitrates between *processes on one machine*. A sync does its network
  work without holding the store lock, then takes the lock and re-checks that the local store
  and the sync cursor are byte-for-byte what they were when it started. If another `arca`
  process wrote in between — the `rm` or `rotate` you ran during an incident while a sync was
  on the network — the sync restarts from a fresh snapshot instead of committing a decision
  made before your change existed. Sustained contention gives up after three attempts with
  "run it again" rather than overwriting anything.
- **Offline is a normal state.** The local file remains the source of truth for every
  read and exec; sync never sits in an access path. Automatic mode runs strictly
  *after* a command's real work and any failure is a warning, never an error. No network
  call is ever made while the store lock is held, so a slow or unreachable backend can never
  delay the `rotate` or `recipients rm` you run during an incident.

## Automatic sync

`arca sync auto on` (or `ARCA_SYNC_AUTO=1`) makes every command opportunistic: a
command that mutated the store pushes the change afterwards, and any command
reconciles when the last sync is older than 15 minutes. Network work is bounded by a
10-second timeout and can never fail the command it rides on. The MCP server process
does not auto-sync (it is long-running; run `arca sync` or rely on the CLI's habits).

Opportunistic sync also refuses to *wait* for the store lock: before it touches the network it
checks whether another `arca` process is mid-write — most often an `arca edit` session with
`$EDITOR` still open — and if so it skips silently, costing not even a round trip. The next
command retries. Explicit `arca sync` waits for the lock as usual, so a long `edit` session
never leaves the next command hanging behind a background sync.

The one exception is a push that has already landed on the remote: recording it locally is no
longer optional at that point, so that single write waits for the lock even in automatic mode.
If it somehow cannot be recorded, the error says so and names the repair (`arca sync --pull`,
which adopts the identical remote and fixes the cursor) rather than leaving a conflict to be
decoded later.

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

### Troubleshooting: `audit escrow failed … already exists (append-only)`

```
arca: warning: audit escrow failed (will retry on the next sync):
remote object audit/<machine-id>/NNNNNN.age already exists (append-only)
```

The local **escrow cursor** (`escrow-state.json` in the state dir) has fallen *behind*
the remote: the next sequence slot it wants to write is already taken. The usual cause
is a state dir that was **restored or rolled back** to an older snapshot (a backup
restore, a synced dotfiles checkout, a machine migration) while the remote kept the
newer segments. Your secrets are unaffected — only the off-machine audit copy is stuck.

- **Same machine, cursor behind (the common case): self-healing.** On the collision arca
  reconciles the cursor to the remote's newest segment for this machine and retries once,
  so an ordinary sync clears it. If you see the warning, run `arca sync` once and it
  should not return.
- **Escrow identity collides with another machine (rare): reset it.** If two machines
  ended up with the *same* `machine-id` (e.g. the whole state dir — including `machine-id`
  — was copied between hosts), the newest remote segment is not part of this machine's
  audit log, and arca refuses to splice two chains. It says so and points here. Recover by
  giving this host a fresh escrow identity:

  ```sh
  arca sync reset-escrow   # rotates machine-id, resets the cursor, re-escrows under a new prefix
  ```

  This touches only the escrow identity and cursor — never the store, the age identity, or
  the local audit log. The previous segments stay on the backend as an orphaned prefix.

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
work without any shell environment. Those env vars are **not** inherited by `arca exec`
or MCP children — a child running `printenv` must not see live backend keys. The one
exception is an explicit `--only` injection of those names from the store, which is
how this bootstrap still works:

```sh
arca exec --only ARCA_SYNC_ACCESS_KEY,ARCA_SYNC_SECRET_KEY -- \
  arca sync init "s3://arca?endpoint=…" --store-credentials --auto
```
