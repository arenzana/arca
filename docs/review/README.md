# Adversarial review pipeline

Provider-agnostic. Nothing here depends on a particular agent CLI.

    requirement  ->  [gate 10]  ->  plan/ADR  ->  [gate 20]  ->  tests  ->  [gate 30]  ->  code  ->  [gate 40]
                                        |                                                            |
                                        +---------------- design finding escalates back -------------+

## The two layers

| Layer | Tool | Question | Home |
|---|---|---|---|
| Mechanical | `gremlins`, `go test -fuzz`, `rapid` | are my tests strong? | CI, hard threshold |
| Judgment | any agent CLI + `gates/*.md` | did I test the right thing, what did I not think of? | pre-PR, effort by blast radius |

They are complements. Mutation testing cannot see code that was never written, which is the whole
omission class.

## Blast-radius ladder

| Radius | Gates run |
|---|---|
| scratch, docs, KB | none |
| ordinary change | 40 (code) + mechanical |
| `internal/`, public API | 20, 30, 40 + mechanical |
| auth, crypto, escrow, migrations, data-destructive | all gates, high effort |

## Rules that are load-bearing

1. **Fresh context per gate.** A gate must not see the reasoning of the gate before it, only its
   output artifact. Enforce structurally (separate process/invocation), never by instruction.
2. **Design findings supersede the ADR**, they are not patched into the code. See `docs/adr/`.
3. **Findings are structured** (`schema/finding.schema.json`), never prose. Prose is unauditable.
4. **Never auto-apply** an adversarial review's output. That recreates unreviewed generation one
   level up.
