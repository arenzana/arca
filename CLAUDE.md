@AGENTS.md

## Claude Code specifics

Everything above is shared with other agents. Only Claude-specific notes belong below.

- The Workflow runner for the review pipeline is `runners/adversarial-pipeline.js`. It reads the
  gate definitions from `docs/review/gates/` rather than embedding prompts; keep it that way so
  the gates stay portable.
- `/code-review` covers the code gate (gate 40) only. It does not replace the plan or test gates.
  Scale its effort with blast radius, per `docs/review/README.md`.
