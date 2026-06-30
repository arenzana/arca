# Architecture

This document describes arca's design: the actors that interact with it, the
components they touch, and the actions that flow between them. It complements the
[trust model](../SECURITY.md#trust-model--boundaries) and the
[threat model](THREAT-MODEL.md).

## Purpose

arca is a single-user command-line secrets manager. It keeps secrets
age-encrypted at rest and records every access in a tamper-evident audit log. Its
distinguishing goal is to sit **safely in front of an AI agent**: an agent can be
allowed to *use* a secret (run a command with it) without the secret value
entering the model's context, and an agent cannot quietly weaken the controls
that record what it did.

## Actors

| Actor | Description | How it interacts |
|-------|-------------|------------------|
| **Operator** | The human running arca on their own machine. | Full CLI; can set/rotate/read secrets, approve gated reads, and relax audit/approval policy. |
| **AI agent** | A coding agent (Claude Code, Cursor, a generic `AI_AGENT`) invoking arca on the operator's behalf. | Same CLI and the MCP server, but detected as an agent and held to stricter, non-overridable policy. |
| **Subprocess** | A command launched by `arca exec` / MCP `run_with_secrets`. | Receives selected secrets via its environment; never via the command line. |
| **Release pipeline** | GitHub Actions. | Builds, tests, signs, and publishes releases and the website; never reads operator secrets. |

The operator and the agent are the two trust tiers. arca raises the bar for a
*cooperating* agent; it does **not** defend against a hostile local user, who
could bypass arca entirely (see the trust model).

## Components

| Component | Source | Responsibility |
|-----------|--------|----------------|
| **CLI** | `main.go`, `manage.go`, `recipients.go`, `generate.go`, `completion.go` | Command tree (cobra), identity detection, policy enforcement, value I/O over TTY/stdin/stdout. |
| **MCP server** | `mcp` command | Exposes `list_secrets`, `show_secret`, `read_secret`, `run_with_secrets`, `audit_log` over stdio JSON-RPC for agents. |
| **Store** | `internal/store` | The age-encrypted JSON secret store: load (with size/version/validity checks and migrations), atomic save (fsync + rename), per-secret metadata and expiry. |
| **Crypto** | `internal/crypto` | age (X25519) encrypt/decrypt of secret values; recipient management. |
| **Audit** | `internal/audit` | Append-only SQLite log (WAL) of access metadata — never values. |
| **Lock** | `lock.go` | Cross-process `O_EXCL` lockfile guarding store mutations. |

## Data at rest

| File | Default location | Contents | Mode |
|------|------------------|----------|------|
| Store | `ARCA_STORE` | age-encrypted secret values + metadata (name, tags, timestamps, policy, expiry). | `0600` |
| Audit DB | `ARCA_AUDIT` | Access events: op, name, time, actor, agent, session, caller. **No values.** | `0600` |
| Identity | `ARCA_IDENTITY` / sops key | The age private key that decrypts the store. | `0600` |

## Primary actions

**Write a secret** — `set` / `rotate` / `generate` / `edit`
1. The value is read from a TTY (no echo) or piped stdin — never an argv argument.
2. The name is validated against `^[A-Za-z_][A-Za-z0-9_]*$`.
3. The store is locked, the value is age-encrypted, the store is written atomically, the lock is released.
4. The operation is recorded in the audit log.

**Read a secret** — `get` / `show` / `env` / `inject`
1. Policy is checked: `--no-print` refuses disclosure; `--require-approval` requires operator approval (an agent cannot self-approve).
2. The read is recorded **before** the value is disclosed. If recording fails and auditing is fail-closed (the default, and non-negotiable for an agent), the read aborts and nothing is disclosed.
3. The decrypted value is written to stdout (or substituted into an `inject` template).

**Use a secret without disclosing it** — `exec` / MCP `run_with_secrets`
1. Selected secrets are decrypted and placed in the subprocess environment.
2. The subprocess runs; arca returns the subprocess's output, never the secret value itself.
3. The use is audited. `--no-print` secrets are usable here but still never returned by arca.

**Inspect history** — `log` / MCP `audit_log`
- Reads the audit DB and prints access metadata. An agent cannot suppress its own read record (`get --no-log` is honored only for a non-agent caller).

## Agent-aware policy (the core invariant)

When arca detects that the caller is an AI agent, three operator escape hatches
are disabled and **cannot be re-enabled by the agent**:

- It cannot self-approve a `--require-approval` secret (`ARCA_APPROVAL=allow`).
- It cannot disable fail-closed auditing (`ARCA_STRICT_AUDIT=0`).
- It cannot suppress its own read record (`get --no-log`).

These overrides are honored only for a non-agent (operator) caller. This is the
property that lets an operator hand arca to an agent and still trust the audit
log and the approval gates.

## Trust boundaries

```
  operator ──► arca CLI ──► store (encrypted)  ──► disk (0600)
                  │     └──► audit (metadata)   ──► disk (0600)
                  │
  AI agent ─► arca CLI / MCP ─(agent-aware policy)─► same store & audit
                  │
                  └──► exec / run_with_secrets ──► subprocess (env, not argv)
```

The boundary that matters is between the **agent** and the **policy/audit
controls**: everything an agent does crosses it, and the agent cannot move the
boundary. See [THREAT-MODEL.md](THREAT-MODEL.md) for the assessed threats and how
each is addressed.
