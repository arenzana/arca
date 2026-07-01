# Per-secret policies & agent controls

[← README](../README.md) · related: [Commands](COMMANDS.md) · [MCP](MCP.md) · [Threat model](THREAT-MODEL.md)

arca's distinguishing feature is a set of per-secret controls for putting a secret **safely in
front of an AI agent** — constraining not just *whether* an agent can see a value, but *how*,
*how often*, and *for what*, and catching misuse when it happens. Each has an honest boundary,
documented in [SECURITY.md](../SECURITY.md#trust-model--boundaries).

## `--no-print` (exec-only)

Refuses `get` / `env` / `inject` for a secret, so its value can never be printed to stdout — only
`exec` (or MCP `run_with_secrets`) can inject it into a subprocess. It blocks *disclosure*, not
*use*.

```sh
arca set PROD_DB_PASSWORD --no-print
arca get PROD_DB_PASSWORD          # refused
arca exec --only PROD_DB_PASSWORD -- psql   # allowed (value in the child's env)
```

## `--require-approval` (human gate)

A human must confirm each release on the terminal. An agent can *request* but cannot self-approve:
with no TTY the request is denied, and a detected agent can't set `ARCA_APPROVAL=allow` to bypass.

```sh
arca set ROOT_SIGNING_KEY --require-approval
```

## Output redaction

When a command run under `exec` (or MCP `run_with_secrets`) prints an injected secret, arca
replaces the value with `«arca:NAME»` in the captured output **before it reaches whoever is
reading** (an agent's context, a log), and records the catch in the audit log. It's on by default
for captured/piped output and steps aside for an interactive terminal; `--redact on|off` forces it,
`--reveal` shows a partial mask of long values.

```sh
$ arca exec --only PASSWORD -- sh -c 'echo connecting with $PASSWORD'
connecting with «arca:PASSWORD»          # the value never reaches the agent's context
```

*Boundary:* it matches the literal value, so a command that transforms the secret (encodes, splits,
hashes it) before printing can still emit it. Defense in depth, not a guarantee.

## Canary secrets (leak detection)

Plant a realistic **decoy** that should never legitimately be used. Any use trips a loud stderr
alert and a distinct, signed `op=canary` audit event — turning the audit log into active leak
detection rather than passive forensics.

```sh
arca canary AWS_PROD_KEY --template aws     # stripe | github | aws | slack | generic
# ... later, if anything uses it ...
#   ⚠  CANARY TRIPPED: "AWS_PROD_KEY" was accessed by malicious-agent (session …)
arca canary --list                          # which canaries exist, and which were tripped
```

*Boundary:* a canary is a tripwire, not a barrier — an attacker who inspects metadata can identify
and avoid one. Its value is catching the common case of an agent that uses what it can read.

## Just-in-time grants (`--require-grant`)

Bind a secret to *what* an agent does. A `--require-grant` secret is unusable until you issue a
`grant` scoped to a **command pattern**, a **use count**, and a **time window**; then it
auto-expires. Use counts come from the tamper-evident audit log, so they can't be rolled back.

```sh
arca set DEPLOY_KEY --require-grant                       # now unusable until granted
arca grant DEPLOY_KEY --command 'terraform *' --uses 3 --ttl 15m [--agent claude-code]
arca exec --only DEPLOY_KEY -- terraform apply           # allowed (use 1 of 3)
arca exec --only DEPLOY_KEY -- sh -c 'curl …'            # denied: command doesn't match
arca grants                                              # secret, command, uses, expiry
arca revoke DEPLOY_KEY                                   # remove the grant
```

*Boundary:* the command match is argv-based — a guardrail expressing intent, not a sandbox (an
agent controls argv and can rename a binary or wrap it in `sh -c`). The uses / expiry / agent
checks are firm; every grant, revoke, and use is recorded.

## Rate limiting (`--rate`)

Cap how often a secret may be *used* (read/exec/env/inject) in a rolling window. Once the cap is
reached the access is refused and the throttle is recorded (`op=ratelimit`) — stopping a runaway
agent hammering a secret and surfacing the burst.

```sh
arca set SIGNING_KEY --rate 5/1h        # at most 5 uses per rolling hour
arca get SIGNING_KEY                     # ... the 6th within the hour is refused and recorded
arca set SIGNING_KEY --rate ""           # clear the limit
```

*Boundary:* a throttle, not a quota — a patient caller can stay under the cap by spreading use out.

## Capability handles

Over MCP, hand an agent an **opaque `hdl_…` token** instead of a secret name. It can *use* the
secret via `run_with_handle` — inject it into a command — without ever learning the secret's name
or value, and without being able to enumerate the store.

```sh
# operator mints a command-scoped, expiring handle (injects the value as $PGPASSWORD):
arca handle create DB_PASSWORD --as PGPASSWORD --command 'psql *' --ttl 1h
#   hdl_3fd698a47ed0c05e21c41d30
arca handle ls                              # operator view: which secret each unlocks
arca handle revoke hdl_…                     # revoke
# the agent, over MCP, runs a command via the handle — never seeing the name or value:
#   run_with_handle(handle="hdl_…", command="psql", args=["-c","select 1"])
```

*Boundary:* a handle reduces *discovery*, not misuse — a scoped, expiring, revocable, audited
bearer token; the command under it still has the value in its environment.

## How they compose

Policies are enforced at a single gate in this order: **canary** trips first (so it fires even on
an access another policy then refuses), then hard **expiry**, then **grant**, then **rate limit**,
then **approval**. A secret can carry several at once — e.g. a canary that's also rate-limited will
alert on every attempt, including the throttled ones.
