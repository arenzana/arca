export const meta = {
  name: 'adversarial-pipeline',
  description: 'Run the adversarial review gates retrospectively over one commit to measure per-gate yield',
  whenToUse: 'Trial: point at a merged commit to learn what each gate catches and what it costs, before adopting the pipeline prospectively.',
  phases: [
    { title: 'Reconstruct', detail: 'derive requirement and implied ADR from the diff' },
    { title: 'Gates', detail: 'the four gates, each in a fresh context' },
    { title: 'Verify', detail: 'refute-by-default on every finding' },
    { title: 'Synthesis', detail: 'per-gate yield and earliest-catch analysis' },
  ],
}

// The gate definitions live in docs/review/gates/*.md and are provider-agnostic.
// This runner does NOT embed prompts: it hands each agent a pointer and the agent
// reads the file itself. That keeps the gates portable to any agent CLI.
const REPO = (args && args.repo) || '.'
const REF = (args && args.ref) || '646f2ca'

const FINDINGS = {
  type: 'object',
  required: ['findings'],
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        required: ['claim', 'failure_scenario', 'severity', 'gate_level'],
        properties: {
          claim: { type: 'string' },
          failure_scenario: { type: 'string' },
          severity: { enum: ['high', 'medium', 'low'] },
          gate_level: { enum: ['requirement', 'plan', 'test', 'code'] },
          file: { type: 'string' },
          line: { type: 'integer' },
        },
      },
    },
  },
}

const VERDICT = {
  type: 'object',
  required: ['refuted', 'reasoning'],
  properties: {
    refuted: { type: 'boolean' },
    reasoning: { type: 'string' },
  },
}

const base = `Repository: ${REPO} (a Go project, arca: an age-encrypted secrets manager).
Commit under review: ${REF}. Read it with \`git show ${REF}\` and \`git show ${REF} --stat\`.

NOTE ON HISTORY: ${REF} was part of a branch that was later SQUASH-merged into main as 60b77d8,
so ${REF} is not an ancestor of HEAD even though its content is present in the working tree.
\`git show ${REF}\` still works and gives the focused diff; use it as the change under review, and
use the working tree for surrounding context.

This is READ-ONLY analysis: do not modify anything, do not create branches, do not commit.`

phase('Reconstruct')
const recon = await agent(
  `${base}

Reconstruct, from the diff alone, the two artifacts that would have existed had this change gone
through a spec-driven pipeline:

1. THE REQUIREMENT: the wanted outcome in the user's terms, with acceptance criteria in
   Given/When/Then form. Do not describe the implementation.
2. THE IMPLIED ADR: context and forces, the decision taken, alternatives evidently available, and
   consequences (what it makes easy, what it makes hard).

List explicitly what the diff does NOT tell you. Return markdown.`,
  { label: 'reconstruct', phase: 'Reconstruct' },
)

// Each agent() call is a fresh context. That is the mechanism enforcing the
// `sees:` / `must_not_see:` contract declared in each gate's front matter.
const GATES = [
  { key: 'requirement', file: 'docs/review/gates/10-requirement.md' },
  { key: 'plan', file: 'docs/review/gates/20-plan.md' },
  { key: 'test', file: 'docs/review/gates/30-test.md' },
  { key: 'code', file: 'docs/review/gates/40-code.md' },
]

phase('Gates')
const gateResults = await parallel(
  GATES.map((g) => () =>
    agent(
      `${base}

Read \`${g.file}\` in this repository. It defines your role, the question you ask, and what you
may and may not look at (its front matter has \`sees:\` and \`must_not_see:\` lists). Follow it
exactly, including the restrictions.

Reconstructed requirement and ADR for this change:

${recon}

Return findings conforming to the schema. Report only defects you can demonstrate concretely.`,
      { label: `gate:${g.key}`, phase: 'Gates', schema: FINDINGS, effort: 'high' },
    ).then((r) => ({ gate: g.key, findings: (r && r.findings) || [] })),
  ),
)

const all = gateResults.filter(Boolean).flatMap((r) => r.findings.map((f) => ({ ...f, gate: r.gate })))
log(`${all.length} raw findings across ${gateResults.filter(Boolean).length} gates`)

phase('Verify')
const verified = await parallel(
  all.map((f) => () =>
    parallel([
      () => agent(`${base}\n\nTry to REFUTE this claim. Default to refuted=true if uncertain.\n\nCLAIM: ${f.claim}\nSCENARIO: ${f.failure_scenario}`,
        { label: 'refute-a', phase: 'Verify', schema: VERDICT }),
      () => agent(`${base}\n\nYou are the author defending this change against a reviewer's claim. Is the reviewer wrong? Default to refuted=true if uncertain.\n\nCLAIM: ${f.claim}\nSCENARIO: ${f.failure_scenario}`,
        { label: 'refute-b', phase: 'Verify', schema: VERDICT }),
    ]).then((vs) => ({ ...f, survived: vs.filter(Boolean).filter((v) => !v.refuted).length >= 2 })),
  ),
)

const confirmed = verified.filter(Boolean).filter((f) => f.survived)

phase('Synthesis')
const byGate = {}
const byEarliest = {}
for (const f of confirmed) {
  byGate[f.gate] = (byGate[f.gate] || 0) + 1
  byEarliest[f.gate_level] = (byEarliest[f.gate_level] || 0) + 1
}

const report = await agent(
  `Trial report for an adversarial review pipeline run against ${REF} in arca.

CONFIRMED FINDINGS (survived two independent refutation attempts):
${JSON.stringify(confirmed, null, 2)}

RAW: ${all.length}. SURVIVED: ${confirmed.length}.
FOUND BY GATE: ${JSON.stringify(byGate)}
EARLIEST GATE THAT COULD HAVE CAUGHT IT: ${JSON.stringify(byEarliest)}

Answer exactly these, in prose, no padding:
1. Did the upstream gates (requirement, plan, test) find anything the code gate did not? Name them.
2. How many findings were catchable EARLIER than the gate that found them? If zero, the upstream
   gates are not paying for themselves and the pipeline should be cut back. Say so plainly.
3. Which gate had the best yield per unit effort?
4. What would you change in the gate prompts before running this prospectively?
5. One paragraph: adopt for arca or not, and at what blast-radius threshold?`,
  { label: 'trial-report', phase: 'Synthesis', effort: 'high' },
)

return {
  ref: REF,
  raw: all.length,
  confirmed: confirmed.length,
  foundByGate: byGate,
  earliestCatchableAt: byEarliest,
  findings: confirmed,
  report,
}
