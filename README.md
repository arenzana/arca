<p align="center">
  <img src="assets/arca-light.png" alt="arca logo" width="160">
</p>

# arca

> *arca* (Latin): a strongbox or chest for keeping valuables under lock.

<p align="center">
  <a href="https://github.com/arenzana/arca/actions/workflows/ci.yml"><img src="https://github.com/arenzana/arca/actions/workflows/ci.yml/badge.svg" alt="ci"></a>
  <a href="https://github.com/arenzana/arca/actions/workflows/codeql.yml"><img src="https://github.com/arenzana/arca/actions/workflows/codeql.yml/badge.svg" alt="codeql"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/arenzana/arca"><img src="https://api.scorecard.dev/projects/github.com/arenzana/arca/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://www.bestpractices.dev/projects/13446"><img src="https://www.bestpractices.dev/projects/13446/baseline" alt="OpenSSF Baseline"></a>
  <a href="https://goreportcard.com/report/github.com/arenzana/arca"><img src="https://goreportcard.com/badge/github.com/arenzana/arca" alt="Go Report Card"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT"></a>
</p>

A small, file-based secrets manager built on [age](https://github.com/FiloSottile/age) — designed
to sit **safely in front of AI agents**. Secrets are encrypted per value with cleartext
metadata in a single JSON store; every access is recorded in a local, fail-closed audit log
attributed to the calling agent. No daemon, no account, no proprietary backend.

---

## Contents

- [Why arca](#why-arca)
- [Features](#features)
- [Install](#install)
- [Quickstart](#quickstart)
- [Importing & migrating](#importing--migrating)
- [Recipes](#recipes)
- [The model](#the-model)
- [Command reference](#command-reference)
- [Configuration (ops)](#configuration-ops)
- [Storage model](#storage-model)
- [Designed for AI agents](#designed-for-ai-agents)
- [MCP server](#mcp-server)
- [Security & supply chain](#security--supply-chain)
- [Stability](#stability)
- [License](#license)

---

## Why arca

- **Use secrets without revealing them.** A command can *use* a secret (`exec`) or a config can
  *reference* one (`inject`) while the value never reaches stdout or an agent's context.
- **Every access is accountable.** The audit log records who/what/when — including the
  auto-detected AI agent, version, and session — and is **fail-closed by default**.
- **Per-secret policy.** Mark a secret exec-only (`--no-print`) or require human approval
  (`--require-approval`).
- **Git-friendly.** The store is plain JSON: it diffs, merges, and lives happily in a dotfiles
  repo as the source of truth, with a free created/modified history from `git log`.
- **Inspectable & dependency-light.** Stdlib + age + cobra; pure-Go SQLite for the audit log.
  No cgo, reproducible builds, signed releases.

---

## Features

| Area | What you get |
|---|---|
| **Encryption** | Per-value age (X25519) ciphertext, ASCII-armored; reuses your existing `$SOPS_AGE_KEY_FILE` |
| **Store** | Single JSON doc; cleartext metadata (tags, description, timestamps, policy), encrypted values |
| **Metadata & query** | `ls`/`show` list and filter **without decrypting**; `--reads` joins usage from the audit log |
| **Rotation** | `rotate` (keeps `created_at`), `--rotate-after` dates, `stale` to find overdue/missing policies |
| **Expiry (TTL)** | `--ttl 30m\|12h\|7d\|2w` or `--expires-at`; expired secrets are **refused on every access path** and surfaced by `stale` |
| **Audit** | Local SQLite log of every access; agent **name/version/session** attribution; **fail-closed** by default; **hash-chained + per-session signed** so tampering is detectable (`log --verify`) |
| **AI-safety policies** | `--no-print` (exec-only), `--require-approval` (human approval), least-privilege `exec --only` |
| **Canary secrets** | Plant realistic decoys (`canary --template stripe`); any use trips a loud, signed audit alert — leak detection, not just prevention |
| **JIT grants** | `--require-grant` secrets are usable only via a `grant` scoped to a command, a use count, and a time window — bind a secret to *what* an agent does, not just whether it can see it |
| **References** | `arca://NAME` resolved at render time by `inject` — agents manipulate references, not secrets |
| **Teams** | Encrypt each value to multiple age recipients; `recipients add/rm` + `reencrypt` re-wrap the whole store |
| **JSON output** | `--json` on `ls`/`show`/`log`/`stale` for agents and scripts |
| **Completion** | `completion bash\|zsh\|fish` with dynamic secret-name + tag suggestions |
| **Migration** | `import` a dotenv **or JSON** stream (audited); `set NAME < file` for blobs; `env` for shell `eval` |
| **Supply chain** | Reproducible builds, SBOM, cosign-signed + SLSA-provenanced releases, govulncheck, CodeQL |

---

## Install

**Homebrew** (macOS / Linux):

```sh
brew install arenzana/tap/arca
```

**Scoop** (Windows):

```powershell
scoop bucket add arenzana https://github.com/arenzana/scoop-bucket
scoop install arca
```

**`go install`:**

```sh
go install github.com/arenzana/arca@latest
```

**Pre-built binaries** for linux/macOS/windows (amd64 + arm64) are attached to each
[release](https://github.com/arenzana/arca/releases), cosign-signed with SLSA provenance — see
[SECURITY.md](SECURITY.md) to verify. Or build from source: `git clone … && cd arca && make build`.

---

## Quickstart

```sh
arca init                                  # reuses $SOPS_AGE_KEY_FILE, or generates an identity
printf '%s' "$TOKEN" | arca set GITHUB_TOKEN --tag github,ci --desc "classic PAT"

arca ls --reads                            # metadata + last-read/count (no decryption)
arca get GITHUB_TOKEN                       # decrypt just this one; records a read

arca exec -- terraform apply                # inject secrets as env (value never hits stdout)
echo 'token = "arca://GITHUB_TOKEN"' | arca inject > config.toml   # resolve references

arca set DB_PASSWORD --no-print             # exec-only: get/env/inject refuse to reveal it
arca set ROOT_KEY --require-approval         # human must approve each release
arca set TMP_TOKEN --ttl 1h                  # ephemeral: refused everywhere after it expires

arca rotate GITHUB_TOKEN --rotate-after 2026-12-01
arca stale                                  # secrets past their rotate-after date, or expired
arca log GITHUB_TOKEN                        # who/what accessed it, and when

arca ls --json | jq '.[].name'              # structured output for agents/scripts

arca recipients add age1teammate...         # share with a teammate's key
arca reencrypt                              # re-wrap every secret to the new recipient set
```

---

## Importing & migrating

arca takes values on **stdin**, so anything that can emit secrets pipes straight in. There are
three ingest shapes:

| Shape | Command | Use it for |
|-------|---------|-----------|
| dotenv lines | `arca import` | `KEY=value` streams (`.env`, sops, `printenv`) |
| JSON object | `arca import --json` | `{"KEY":"value"}` — what most secret stores emit |
| a single value | `arca set NAME < file` | one secret, including multi-line blobs (PEM keys, a service-account JSON) |

`import` validates every name (`[A-Za-z_][A-Za-z0-9_]*`) and **skips** anything else, and each
imported secret is recorded in the audit log like any other write. With `--json`, string values
pass through verbatim (a JSON-escaped multi-line key round-trips), numbers and booleans are
stringified, and `null`/nested values are skipped.

By default `import` **skips a name that already exists** (so a re-run never silently clobbers a
secret); pass `--overwrite` to replace them. A few flags shape the load:

| Flag | Effect |
|------|--------|
| `--dry-run` | Print what would be imported (new vs overwrite vs skip) and write nothing |
| `--overwrite` | Replace existing secrets instead of skipping them |
| `--prefix P` | Prepend `P` to every imported name (e.g. `--prefix STRIPE_`) |
| `--tag t` | Attach tags to every imported secret (repeatable or comma-separated) |

```sh
# dotenv — a plain file, or decrypted from sops
arca import < .env
sops -d ~/.dotfiles/secrets/secrets.env | arca import

# JSON — straight from a cloud secret store, no jq gymnastics
aws secretsmanager get-secret-value --secret-id prod/app --query SecretString --output text \
  | arca import --json
gcloud secrets versions access latest --secret=prod-app | arca import --json
vault kv get -format=json secret/prod/app | jq '.data.data' | arca import --json
op item get prod-app --format json | jq '[.fields[]|select(.value)|{(.label):.value}]|add' \
  | arca import --json

# any KEY=value source via dotenv
pass show prod/env | arca import
printenv | grep '^APP_' | arca import

# preview first, then namespace + tag a load
arca import --json --dry-run < secrets.json
arca import --prefix STRIPE_ --tag billing,prod < stripe.env
arca import --overwrite < refreshed.env          # replace existing (default skips them)

# one secret, multi-line, as a single value (not dotenv)
arca set TLS_KEY < server.key
arca set GCP_SA_JSON < service-account.json
```

> A non-JSON source whose values span lines (a raw PEM, a certificate) doesn't fit dotenv —
> import it as one named secret with `set NAME < file`, or wrap it in a JSON object and use
> `--json`.

---

## Recipes

**Use a secret in a command — never on stdout**

```sh
arca exec -- terraform apply
arca exec --only AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY -- terraform apply   # least privilege
```

If the command itself prints an injected secret, arca **redacts it from the output** before it
reaches whoever is reading — replacing the value with `«arca:NAME»` and recording the catch in the
audit log. Redaction is automatic when output is captured (piped to an agent or a log) and steps
aside for an interactive terminal; `--redact on|off` forces it, and `--reveal` shows a partial
mask of long values instead of the name.

```sh
$ arca exec --only PASSWORD -- sh -c 'echo connecting with $PASSWORD'
connecting with «arca:PASSWORD»          # the value never reaches the agent's context
```

**Plant a canary to catch an agent that grabs everything**

```sh
arca canary AWS_PROD_KEY --template aws    # a realistic decoy; using it should never happen
# ... later, if anything reads it ...
#   ⚠  CANARY TRIPPED: "AWS_PROD_KEY" was accessed by malicious-agent (session …)
arca canary --list                         # which canaries exist, and which have been tripped
```

**Grant a secret just-in-time, scoped to a command**

```sh
arca set DEPLOY_KEY --require-grant                       # now unusable until granted
arca grant DEPLOY_KEY --command 'terraform *' --uses 3 --ttl 15m
arca exec --only DEPLOY_KEY -- terraform apply           # allowed (use 1 of 3)
arca exec --only DEPLOY_KEY -- sh -c 'curl …'            # denied: command doesn't match
arca grants                                              # secret, command, uses, expiry
```

**Render a config from a template** (the value only lands in the rendered file):

```sh
echo 'database_url = "arca://DATABASE_URL"' > app.toml.tmpl
echo 'api_key      = "arca://STRIPE_KEY"'  >> app.toml.tmpl
arca inject < app.toml.tmpl > app.toml
```

**Generate, then rotate on a schedule:**

```sh
arca generate DB_PASSWORD --length 40 --no-print      # random value, exec-only
arca rotate   DB_PASSWORD --rotate-after 2026-12-01    # new value + next rotation date
arca stale --within 30                                 # what's due (or expired) in 30 days
```

**Short-lived tokens:**

```sh
arca generate CI_DEPLOY_TOKEN --ttl 1h                 # refused on every path after an hour
```

**Exec-only and human-approved secrets:**

```sh
arca set PROD_DB_PASSWORD --no-print                   # get/env/inject refuse to print it
arca set ROOT_SIGNING_KEY --require-approval           # a human confirms each release on the TTY
```

**Share with a teammate** (add their age public key, re-wrap the store):

```sh
arca recipients add age1teammate...
arca reencrypt
```

**Load into a shell or write a dotenv:**

```sh
eval "$(arca env)"                                     # export every non-no-print secret
arca env --no-export > .env
```

**Use from an AI agent (MCP):**

```sh
claude mcp add arca -- arca mcp
# the agent calls run_with_secrets to USE a secret without seeing it, and read_secret
# (policy-gated, audited) only when the value must enter its context.
```

**Audit — who touched what:**

```sh
arca log                       # recent access across all secrets
arca log PROD_DB_PASSWORD      # one secret, with agent / session / actor
arca ls --reads                # last-read time + count per secret
```

**Keep the store in a dotfiles repo** (the JSON diffs cleanly; the audit DB stays local):

```sh
export ARCA_STORE=~/.dotfiles/arca/store.json
```

**Script against JSON output:**

```sh
arca ls --json | jq -r '.[] | select(.expired) | .name'    # expired secrets
arca log --json | jq '.[] | {op, name, agent, time}'
```

---

## The model

arca is three pieces with deliberately different jobs:

```
 ┌──────────────────────────┐        ┌───────────────────────────┐
 │ store.json (git-synced)  │        │ audit.db  (local, SQLite) │
 │ cleartext metadata +     │        │ append-only access log    │
 │ per-value age ciphertext │        │ op, name, time, AGENT,    │
 │ (changes only on set/    │        │ version, session, actor   │
 │  rotate/rm)              │        │ (read tracking lives here)│
 └──────────────────────────┘        └───────────────────────────┘
             ▲  encrypt/decrypt with the age identity (≈ your sops key)
```

- **The store** is the source of truth and is meant to be **git-synced**. Reads never touch it, so
  it only changes on real mutations — clean history, no churn.
- **The audit log** is **local and never synced**. Keeping read-tracking here is what lets the
  store stay quiet and lets `log`/`show --reads` answer "who accessed this?".
- **Per-value encryption** means `get`/`inject`/`exec` decrypt only the one secret asked for, and
  unchanged secrets keep byte-identical ciphertext (clean diffs).

### Access shapes (and what each exposes)

| Command | Exposes the value to… | Blocked for `--no-print`? | Audited |
|---|---|---|---|
| `get` / `env` | **stdout** (the caller/agent sees it) | yes | yes |
| `inject` | **stdout**, but only inside a rendered template | yes | yes (per ref) |
| `exec` | a **subprocess's environment** only — never stdout | no (this is the sanctioned path) | yes (per secret) |

> Rule of thumb for agents: let a command **use** a secret with `exec`, or a config **reference**
> one with `inject`; reach for `get` only when a human needs the raw value.

### Fail-closed auditing

By default, if an access cannot be recorded, the operation is **aborted** — and for reads it
aborts *before* the value is revealed, so a secret an agent accesses is never disclosed without a
trail. Set `ARCA_STRICT_AUDIT=0` to fall back to best-effort (swallow audit errors).

### Agent attribution

Each event is tagged with the calling AI agent, auto-detected from the environment:

- **Claude Code** — name, session (`CLAUDE_CODE_SESSION_ID`), version (from the exec path)
- **Cursor** — via `CURSOR_TRACE_ID`
- **Generic** — `AI_AGENT=name_version_agent`
- plus an explicit `ARCA_ACTOR` label you can set yourself.

---

## Command reference

| Command | Purpose | Key flags |
|---|---|---|
| `init` | Create the store (reuse or generate an age key) | `--force` |
| `set NAME` | Add/update a secret (value from TTY or stdin) | `--tag --desc --rotate-after --ttl --expires-at --meta k=v --no-print --require-approval` |
| `generate NAME` | Create a secret with a random value | `-l/--length --charset --tag --desc --ttl --no-print --show` |
| `get NAME` | Decrypt and print one secret (records a read) | `-n` (newline), `--no-log` |
| `rotate NAME` | Replace value, keep `created_at`, log a rotation | `--rotate-after --ttl --expires-at` |
| `ls` | List secrets + metadata (no decryption) | `--tag`, `--reads`, `--json` |
| `show NAME` | Show one secret's metadata (no value) | `--json` |
| `stale` | Secrets overdue/soon for rotation, or expired/expiring | `--within N`, `--missing`, `--json` |
| `rm NAME` | Remove a secret | — |
| `edit NAME` | Edit a secret's value in `$EDITOR` (re-encrypted) | — |
| `rename OLD NEW` | Rename a secret, preserving metadata/history (alias `mv`) | `--force` |
| `recipients` | List age recipients; `add`/`rm` subcommands manage the set | — |
| `reencrypt` | Re-encrypt every secret to the current recipient set | — |
| `import` | Bulk-load secrets from stdin (dotenv lines, or a JSON object) | `--json`, `--dry-run`, `--overwrite`, `--prefix P`, `--tag t` |
| `inject` | Resolve `arca://NAME` references on stdin → stdout | — |
| `exec -- CMD` | Run CMD with secrets injected as env (audited); injected values are redacted from its output | `--only a,b`, `--redact auto\|on\|off`, `--reveal` |
| `env` | Emit `export …` for `eval "$(arca env)"` | `--no-export` |
| `log [NAME]` | Access history (agent/session/actor); `--verify` checks the log's integrity | `--limit N`, `--json`, `--verify` |
| `canary [NAME]` | Plant a decoy secret (any use trips a signed alert), or list canaries and their trips | `--template`, `--list`, `--tag`, `--desc` |
| `grant SECRET` | Authorize a `--require-grant` secret for a command, a number of uses, and a window | `--command`, `--uses`, `--ttl`, `--agent` |
| `grants` | List active grants and their remaining uses | — |
| `revoke SECRET` | Remove the active grant for a secret | — |
| `mcp` | Run an MCP server exposing arca to AI agents (stdio) | — |
| `completion SHELL` | Shell completion script (bash/zsh/fish/powershell) | — |

Values are always read from a TTY (no echo) or piped stdin — **never** passed as arguments.

---

## Configuration (ops)

All paths are overridable so the store can live in your dotfiles while the audit log stays local.

| Variable | Purpose | Default |
|---|---|---|
| `ARCA_STORE` | JSON store path (sync this) | `~/.config/arca/store.json` |
| `ARCA_AUDIT` | SQLite audit DB (do **not** sync) | `~/.local/state/arca/audit.db` |
| `ARCA_IDENTITY` | age private key | `$SOPS_AGE_KEY_FILE`, else `~/.config/arca/identity.txt` |
| `ARCA_STRICT_AUDIT` | fail-closed auditing | enabled; set `0`/`false`/`off`/`no` for best-effort |
| `ARCA_ACTOR` | explicit actor label in the audit | — (agent auto-detected) |
| `ARCA_APPROVAL` | short-circuit the approval prompt | — (`allow`/`deny`; else interactive `/dev/tty`) |
| `XDG_CONFIG_HOME` / `XDG_STATE_HOME` | base dirs | `~/.config` / `~/.local/state` |

**Typical deployment:** point `ARCA_STORE` at a (private) dotfiles repo to version the store;
leave the audit DB local and gitignored. The age private key is your single decrypt root — back
it up (e.g. to a password manager). On a new machine: restore the key, `git clone`, done.

**`make` targets:** `build` (reproducible), `test`, `cover`, `vet`, `vuln` (govulncheck),
`sbom` (CycloneDX), `verify`.

---

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
      "meta": { }                            // open-ended extensibility bag
    }
  }
}
```

Read tracking (`last_read`, counts, full history with agent/session) lives in the **audit DB**,
not here — so reads never dirty git.

---

## Designed for AI agents

arca is a file-based secrets broker you can safely put in front of an AI agent:

- **Use without revealing.** `arca exec -- <cmd>` injects secrets into a subprocess's environment —
  the command uses the value, but it never prints into the agent's context or transcript.
- **References, not values.** Put `arca://NAME` in a config/template and `arca inject` resolves it
  at render time, so an agent manipulates references rather than raw secrets.
- **`--no-print` (exec-only) secrets.** `get`, `env`, and `inject` refuse to reveal them — only
  `exec` can inject them into a subprocess.
- **`--require-approval` gates.** A human confirms each release on the terminal; an agent can
  request but cannot self-approve (no terminal ⇒ denied).
- **Attributed audit.** Every access is logged with the calling **agent, version, and session**,
  plus an explicit `ARCA_ACTOR` override — `arca log` answers *which agent touched what, and when*.
- **Fail-closed auditing.** If an access can't be recorded the operation is aborted — and for
  reads, aborted *before* disclosing the value.
- **Least privilege.** `exec --only a,b` injects just the secrets a task needs.

---

## MCP server

`arca mcp` runs a [Model Context Protocol](https://modelcontextprotocol.io) server over stdio, so
an agent accesses secrets through controlled, **audited tools** instead of raw shell — the same
`--no-print` / `--require-approval` / fail-closed-audit policies apply.

| Tool | What it does |
|---|---|
| `list_secrets` | Names + metadata (tags, policy, last read) — **never values** |
| `show_secret` | Metadata for one secret |
| `run_with_secrets` | Run a command with named secrets injected as env; returns the command's **output**, not the values |
| `read_secret` | Reveal a value (refused for `--no-print`, requires `--require-approval` confirmation, audited) — the escape hatch |
| `audit_log` | Recent access events |

The intended flow is *use, don't reveal*: an agent calls `run_with_secrets` so a command can use a
secret, reserving `read_secret` for when the value genuinely must enter the model context.

Register it with Claude Code:

```sh
claude mcp add arca -- arca mcp
```

---

## Security & supply chain

Built as security software: **reproducible** builds (`CGO_ENABLED=0`, `-trimpath`, pinned
timestamps), **cosign**-signed checksums, a **CycloneDX SBOM**, and **SLSA build-provenance**
attestations on every release. CI runs `go vet`, `go test -race` (~92% coverage, enforced),
`go mod verify`, `govulncheck`, **CodeQL**, **OpenSSF Scorecard**, dependency review, and
**SHA-pinned** actions under a hardened runner. See [SECURITY.md](SECURITY.md) for the disclosure
policy and release-verification steps.

---

## Stability

From v1.0, arca follows [Semantic Versioning](https://semver.org). [STABILITY.md](STABILITY.md)
defines exactly which surfaces are covered — commands/flags, exit codes, the store schema,
`arca://` references, the `ARCA_*` configuration, `--json` output, and the MCP tools — and what
may change (human-readable text, internal packages). Parse `--json`, not the table output.

---

## License

MIT
