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
- [Documentation](#documentation)
- [Recipes](#recipes)
- [The model](#the-model)
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
| **Rate limiting** | `set --rate 10/1h` caps how often a secret may be used in a rolling window; the throttle is recorded, so a runaway agent hammering a secret is stopped and surfaced |
| **Capability handles** | `handle create` mints an opaque `hdl_…` token; over MCP an agent uses it (`run_with_handle`) without ever learning the secret's name or value, or being able to enumerate the store |
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

**RPM / DEB** (RHEL/Rocky/Fedora, Debian/Ubuntu) — download from the
[latest release](https://github.com/arenzana/arca/releases/latest) and:

```sh
sudo dnf install ./arca_<version>_linux_<arch>.rpm    # or: sudo dpkg -i arca_….deb
```

Packages are listed in `checksums.txt`, so the release's cosign bundle covers them
(see [SECURITY.md](SECURITY.md)).

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

## Documentation

The README is the overview; the detail lives in [`docs/`](docs/):

- **[Commands](docs/COMMANDS.md)** — the full command reference.
- **[Policies](docs/POLICIES.md)** — the per-secret controls: `--no-print`, `--require-approval`,
  output redaction, canaries, JIT grants (`--require-grant`), rate limiting, and capability handles.
- **[AI agents & MCP](docs/MCP.md)** — the MCP server, its tools, and the agent-safety model.
- **[Importing & migrating](docs/IMPORTING.md)** — pipe from sops, `.env`, JSON, AWS, Vault, 1Password, …
- **[Configuration & storage](docs/CONFIGURATION.md)** — `ARCA_*` env vars, paths, and the store schema.
- **[Architecture](docs/ARCHITECTURE.md)** · **[Threat model](docs/THREAT-MODEL.md)** — how it's built and what it defends against.

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

**Rate-limit a secret an agent might hammer**

```sh
arca set SIGNING_KEY --rate 5/1h        # at most 5 uses per rolling hour
arca get SIGNING_KEY                     # ... the 6th within the hour is refused and recorded
```

**Hand an agent a secret it can't name, read, or enumerate**

```sh
# operator mints an opaque, command-scoped, expiring handle
arca handle create DB_PASSWORD --as PGPASSWORD --command 'psql *' --ttl 1h
#   hdl_3fd698a47ed0c05e21c41d30
# the agent, over MCP, runs a command via the handle — never seeing the name or value:
#   run_with_handle(handle="hdl_…", command="psql", args=["-c","select 1"])
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
trail. A human at a controlling terminal may set `ARCA_STRICT_AUDIT=0` to fall back to
best-effort (swallow audit errors); a detected agent or a headless caller cannot.

### Agent attribution

Each event is tagged with the calling AI agent, auto-detected from the environment:

- **Claude Code** — name, session (`CLAUDE_CODE_SESSION_ID`), version (from the exec path)
- **Cursor** — via `CURSOR_TRACE_ID`
- **Generic** — `AI_AGENT=name_version_agent`
- plus an explicit `ARCA_ACTOR` label you can set yourself.

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
