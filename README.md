<p align="center">
  <img src="assets/arca-light.png" alt="arca logo" width="160">
</p>

# arca

> *arca* (Latin): a strongbox or chest for keeping valuables under lock.

<p align="center">
  <a href="https://github.com/arenzana/arca/actions/workflows/ci.yml"><img src="https://github.com/arenzana/arca/actions/workflows/ci.yml/badge.svg" alt="ci"></a>
  <a href="https://github.com/arenzana/arca/actions/workflows/codeql.yml"><img src="https://github.com/arenzana/arca/actions/workflows/codeql.yml/badge.svg" alt="codeql"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/arenzana/arca"><img src="https://api.scorecard.dev/projects/github.com/arenzana/arca/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://goreportcard.com/report/github.com/arenzana/arca"><img src="https://goreportcard.com/badge/github.com/arenzana/arca" alt="Go Report Card"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT"></a>
</p>

A small, file-based secrets manager built on [age](https://github.com/FiloSottile/age) — designed
to sit **safely in front of AI agents**. Secrets are encrypted per value with rich, cleartext
metadata in a single JSON store; every access is recorded in a local, fail-closed audit log
attributed to the calling agent. No daemon, no account, no proprietary backend.

---

## Contents

- [Why arca](#why-arca)
- [Features](#features)
- [Install](#install)
- [Quickstart](#quickstart)
- [The model](#the-model)
- [Command reference](#command-reference)
- [Configuration (ops)](#configuration-ops)
- [Storage model](#storage-model)
- [Designed for AI agents](#designed-for-ai-agents)
- [MCP server](#mcp-server)
- [Security & supply chain](#security--supply-chain)
- [License](#license)

---

## Why arca

- **Use secrets without revealing them.** A command can *use* a secret (`exec`) or a config can
  *reference* one (`inject`) while the value never reaches stdout or an agent's context.
- **Every access is accountable.** The audit log records who/what/when — including the
  auto-detected AI agent, version, and session — and is **fail-closed by default**.
- **Per-secret policy.** Mark a secret exec-only (`--no-print`) or gate it behind human approval
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
| **Audit** | Local SQLite log of every access; agent **name/version/session** attribution; **fail-closed** by default |
| **AI-safety policies** | `--no-print` (exec-only), `--require-approval` (human gate), least-privilege `exec --only` |
| **References** | `arca://NAME` resolved at render time by `inject` — agents manipulate references, not secrets |
| **Migration** | `import` from a sops/dotenv stream; `env` for shell `eval` |
| **Supply chain** | Reproducible builds, SBOM, cosign-signed + SLSA-provenanced releases, govulncheck, CodeQL |

---

## Install

```sh
go install github.com/arenzana/arca@latest
```

Or build from source: `git clone … && cd arca && make build` (produces a static, reproducible binary).

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

arca rotate GITHUB_TOKEN --rotate-after 2026-12-01
arca stale                                  # secrets past their rotate-after date
arca log GITHUB_TOKEN                        # who/what accessed it, and when
```

Migrate an existing sops dotenv:

```sh
sops -d ~/.dotfiles/secrets/secrets.env | arca import
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
| `set NAME` | Add/update a secret (value from TTY or stdin) | `--tag --desc --rotate-after --meta k=v --no-print --require-approval` |
| `get NAME` | Decrypt and print one secret (records a read) | `-n` (newline), `--no-log` |
| `rotate NAME` | Replace value, keep `created_at`, log a rotation | `--rotate-after` |
| `ls` | List secrets + metadata (no decryption) | `--tag`, `--reads` |
| `show NAME` | Show one secret's metadata (no value) | — |
| `stale` | Secrets overdue/soon for rotation | `--within N`, `--missing` |
| `rm NAME` | Remove a secret | — |
| `import` | Load `KEY=value` (dotenv) lines from stdin | — |
| `inject` | Resolve `arca://NAME` references on stdin → stdout | — |
| `exec -- CMD` | Run CMD with secrets injected as env (audited) | `--only a,b` |
| `env` | Emit `export …` for `eval "$(arca env)"` | `--no-export` |
| `log [NAME]` | Access history (agent/session/actor) | `--limit N` |
| `mcp` | Run an MCP server exposing arca to AI agents (stdio) | — |

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
      "require_approval": false,             // human gate when true
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
| `read_secret` | Reveal a value (refused for `--no-print`, gated by `--require-approval`, audited) — the escape hatch |
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
attestations on every release. CI runs `go vet`, `go test -race` (~90% coverage, gated),
`go mod verify`, `govulncheck`, **CodeQL**, **OpenSSF Scorecard**, dependency review, and
**SHA-pinned** actions under a hardened runner. See [SECURITY.md](SECURITY.md) for the disclosure
policy and release-verification steps.

---

## License

MIT
