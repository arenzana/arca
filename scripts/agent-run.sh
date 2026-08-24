#!/usr/bin/env bash
# Normalizes "run this prompt, return JSON" across agent CLIs.
# Usage: AGENT=claude ./scripts/agent-run.sh docs/review/gates/40-code.md <<< "$CONTEXT"
set -euo pipefail

GATE_FILE="${1:?usage: agent-run.sh <gate-file>}"
AGENT="${AGENT:-claude}"
SCHEMA="$(dirname "$0")/../docs/review/schema/finding.schema.json"

PROMPT="$(sed '1{/^---$/!q;};1,/^---$/d' "$GATE_FILE")"   # strip YAML front matter
CONTEXT="$(cat)"
FULL="${PROMPT}

Return ONLY JSON conforming to this schema:
$(cat "$SCHEMA")

--- CONTEXT ---
${CONTEXT}"

case "$AGENT" in
  claude)   claude -p "$FULL" --output-format json ;;
  opencode) opencode run "$FULL" ;;
  codex)    codex exec "$FULL" ;;
  aider)    aider --message "$FULL" --no-auto-commits ;;
  *)        echo "unknown AGENT=$AGENT" >&2; exit 2 ;;
esac
