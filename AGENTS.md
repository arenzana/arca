# Agent instructions

Read by every coding agent that supports the AGENTS.md convention. Claude Code reads it via the
one-line import in `CLAUDE.md`. Keep this file lean: it loads into context at the start of every
session, so link to detail rather than inlining it.

## Language and tooling

- Go is the primary language. Prefer the standard library; justify every dependency.
- Tests are `go test`. Property tests use `rapid`. Mutation testing uses `gremlins`.

## Review pipeline (non-optional above a blast-radius threshold)

Changes pass through adversarial gates before merge. The gates, the blast-radius ladder that
decides which ones run, and the rules that are load-bearing are documented in
`docs/review/README.md`. The gate prompts themselves are `docs/review/gates/*.md` and findings
conform to `docs/review/schema/finding.schema.json`.

Four rules that agents must not work around:

1. **Fresh context per gate.** A gate sees only the artifact named in its front matter `sees:`
   list, never the reasoning of the gate before it.
2. **Design findings supersede the ADR**; they are never patched into the code silently.
3. **Findings are structured**, never prose.
4. **Never auto-apply** a review's output. Applying an unreviewed fix recreates the problem the
   review exists to solve.

## Architecture decisions

Significant decisions are recorded as ADRs in `docs/adr/`, numbered and immutable. To change a
decision, write a new ADR that supersedes the old one; do not edit an accepted ADR. Template at
`docs/adr/0000-template.md`. Acceptance criteria live in the ADR in Given/When/Then form, because
they compile into tests.

Before changing behaviour in a way an ADR describes, read that ADR. The reason a thing is the way
it is usually is not in the code.
