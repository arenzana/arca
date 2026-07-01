---
name: arca
description: >-
  Use whenever an AI agent needs a secret, API token, credential, or environment variable that is
  managed by arca — reading, using, listing, adding, rotating, or disabling one. Activates on
  requests like "use the GITHUB_TOKEN", "deploy with the prod key", "what secrets are available",
  "add an API token", "disable that leaked key", or any mention of arca, `arca://` references, or a
  secret an agent isn't meant to see in plaintext. Teaches the "use, don't reveal" workflow so the
  value stays out of the model's context.
---

# Using arca (age-encrypted secrets, safe in front of AI agents)

[arca](https://github.com/arenzana/arca) stores secrets as age-encrypted values with cleartext
metadata in one JSON file, and records **every access** in a local, fail-closed audit log
attributed to the calling agent. As an agent you interact with it through its **MCP tools** (or the
CLI). The whole point is that you can *use* a secret without its value ever entering your context.

## Golden rules

1. **Use, don't reveal.** Run a command *with* a secret injected as an env var — never fetch the
   raw value into your context. Prefer `run_with_secrets` (MCP) / `arca exec` (CLI).
2. **Never print, echo, log, or paste a secret value.** Not into a file, a commit, a message, or
   your own reasoning. If you must confirm one exists, check its *presence or length*, never the
   value.
3. **Reveal is a last resort.** `read_secret` / `arca get` returns the plaintext and is refused for
   `--no-print` secrets. Only use it when a human explicitly needs the raw value.
4. **Every access is audited and attributed to you.** Assume anything you touch is logged. Don't
   enumerate or read secrets you weren't asked to.

## Discover what's available (no values)

- MCP: `list_secrets` → names, tags, descriptions, policy, and whether a secret is expired/disabled.
- CLI: `arca ls` (add `--tag X` to filter), `arca show NAME` for one secret's metadata.

Never call a "reveal" tool just to explore — listing metadata is enough to plan.

## Use a secret without seeing it (the normal path)

- **MCP:** `run_with_secrets` — runs a command with named secrets injected as env vars and returns
  the command's (redacted) output, not the values.
- **CLI:** `arca exec --only NAME1,NAME2 -- <command>` — injects only those secrets; if the command
  prints one, arca redacts it from the output before you see it.
- **Config templating:** put `arca://NAME` in a config/template and resolve it with `arca inject`
  (stdin → stdout). The value is substituted at the boundary, not surfaced to you.

Example (CLI): `arca exec --only DATABASE_URL -- psql -c '\dt'`

## Scoped, just-in-time access (when a secret is locked down)

Some secrets are `--require-grant`: unusable until scoped to a specific command, use-count, and
time window. If a use is refused for lack of a grant, ask the human to run
`arca grant SECRET --command '<pattern>' --uses N --ttl 15m` (granting is a human action). Agents
may also be handed an opaque **capability handle** (`hdl_…`) and use it via the MCP
`run_with_handle` tool without ever learning the secret's name or value.

## Add / rotate / disable

- **Add** (human types or pipes the value; you supply metadata): `arca set NAME --tag ... --desc
  "what it is and where it's issued"`. A good `--desc` (issuer + consumers) is what makes a future
  revocation fast — always set it.
- **Rotate** (replace the value, keep history): `arca rotate NAME`.
- **Disable / enable** — a fast, reversible kill switch that suspends a secret on every access path
  without deleting it: `arca disable NAME` / `arca enable NAME`. Use this to quarantine a suspected
  leak. **It is a *local* kill switch, not revocation** — the token must still be revoked at its
  issuer (GitHub, AWS, …); disabling only stops arca from handing the value out.

## Audit

`arca log [NAME]` shows who/what/when accessed a secret; `arca log --verify` checks the log's
hash-chain + signatures. If asked to investigate access, use this — don't reconstruct it by reading
values.

## Do NOT

- Do not put a secret value in a file, commit, PR, message, URL, or your visible output.
- Do not `read_secret` / `arca get` unless a human explicitly needs the raw value.
- Do not disable/rotate/remove a secret unless asked — those are audited, consequential actions.
- Do not treat `disable` as revocation; on a real compromise, tell the human to revoke at the
  issuer first, then `disable` or `rotate` in arca.

See the full command reference and docs at <https://arenzana.github.io/arca/>.
