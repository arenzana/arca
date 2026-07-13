# AI agents & the MCP server

[← README](../README.md) · related: [Policies](POLICIES.md) · [Commands](COMMANDS.md) · [Threat model](THREAT-MODEL.md)

## Designed for AI agents

arca is a file-based secrets broker you can safely put in front of an AI agent:

- **Use without revealing.** `arca exec -- <cmd>` injects secrets into a subprocess's environment —
  the command uses the value, but it never prints into the agent's context or transcript. If the
  command prints one anyway, arca **redacts** it from the captured output (see [Policies](POLICIES.md#output-redaction)).
- **References, not values.** Put `arca://NAME` in a config/template and `arca inject` resolves it
  at render time, so an agent manipulates references rather than raw secrets.
- **`--no-print` (exec-only) secrets.** `get`, `env`, and `inject` refuse to reveal them — only
  `exec` can inject them into a subprocess.
- **`--require-approval` gates.** A human confirms each release on the terminal; an agent can
  request but cannot self-approve (no terminal ⇒ denied).
- **Command-scoped grants and opaque handles.** Bind a secret to *what* an agent does, or hand it a
  capability it can't name, read, or enumerate — see [Policies](POLICIES.md).
- **Attributed, tamper-evident audit.** Every access is logged with the calling **agent, version,
  and session**; the log is hash-chained and per-session signed (`arca log --verify`).
- **Fail-closed auditing.** If an access can't be recorded the operation is aborted — and for
  reads, aborted *before* disclosing the value. A detected agent cannot weaken this.
- **Least privilege.** `exec --only a,b` injects just the secrets a task needs.

## The MCP server

`arca mcp` runs a [Model Context Protocol](https://modelcontextprotocol.io) server over stdio, so
an agent accesses secrets through controlled, **audited tools** instead of raw shell — the same
`--no-print` / `--require-approval` / rate-limit / fail-closed-audit policies apply.

| Tool | What it does |
|---|---|
| `list_secrets` | Names + metadata (tags, policy, last read) — **never values** |
| `show_secret` | Metadata for one secret |
| `run_with_secrets` | Run a command with named secrets injected as env; returns the command's **output** (redacted), not the values |
| `run_with_handle` | Run a command via an opaque `hdl_…` handle — uses a secret **without its name or value**, enforcing the handle's command scope and expiry. A handle bypasses the grant/approval gates, so it's the operator's pre-authorization: `arca handle create` is operator-only (refused for a detected agent) and needs `--override` to mint one for a `--require-approval`/`--require-grant` secret |
| `read_secret` | Reveal a value (refused for `--no-print`, requires `--require-approval` confirmation, audited) — the escape hatch |
| `audit_log` | Recent access events (a handle-issued event's secret name is masked to the handle id, so it can't map a handle back to the secret it wraps) |

The intended flow is *use, don't reveal*: an agent calls `run_with_secrets` (or `run_with_handle`)
so a command can use a secret, reserving `read_secret` for when the value genuinely must enter the
model context.

## Deny-by-default agent exposure (`--strict`)

By default the MCP tools operate over **every** secret in the store — a wide default. Run the server
in strict mode to flip that to an explicit allow-list, so an agent only sees and uses secrets you
have opted in:

```sh
arca agent allow DEPLOY_TOKEN        # expose just what the agent needs
arca agent allow GITHUB_TOKEN
arca agent ls                        # review the allow-list
arca mcp --strict                    # or set ARCA_AGENT_STRICT=1
```

Under `--strict`, `list_secrets` hides anything not allowed, and `show_secret`/`read_secret`/
`run_with_secrets` **refuse** it with a pointer to `arca agent allow NAME`. Revoke with
`arca agent deny NAME`. Without `--strict` the server stays backwards-compatible but prints a loud
warning on startup that every secret is reachable — a future major release makes strict the default.
`arca doctor` also flags a store whose MCP exposure isn't scoped.

Register it with Claude Code (add `--strict` once you've built your allow-list):

```sh
claude mcp add arca -- arca mcp --strict
```
