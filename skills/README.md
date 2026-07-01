# arca skills

Agent skills that ship with arca. A skill teaches an AI coding agent how to *use* arca correctly —
the "use, don't reveal" workflow, the audited MCP tools, and the lifecycle commands — so an agent
can work with your secrets without their values ever entering its context.

## `arca` — safe secret usage

[`arca/SKILL.md`](arca/SKILL.md) is a [Claude Code](https://docs.claude.com/en/docs/claude-code)
skill. It pairs with the arca **MCP server** (`arca mcp`), which exposes the audited tools the skill
refers to.

### Install (Claude Code)

Copy the skill into your skills directory and register the MCP server:

```bash
# 1. Install the skill (user-level; or drop it in a project's .claude/skills/)
mkdir -p ~/.claude/skills/arca
cp arca/SKILL.md ~/.claude/skills/arca/SKILL.md

# 2. Expose arca to the agent over MCP (audited tools: list_secrets, run_with_secrets, …)
claude mcp add -s user arca -- arca mcp
```

Other agents: point your tool at the same `arca mcp` server and load `arca/SKILL.md` as its
system/skill guidance — the content is not Claude-specific.

The skill is intentionally read-mostly: it steers the agent toward `run_with_secrets` / `arca exec`
(use without revealing) and treats `read_secret` / `arca get` as a last resort. See the full docs at
<https://arenzana.github.io/arca/>.
