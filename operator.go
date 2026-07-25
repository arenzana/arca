// Control-plane anchoring (T11/T12). arca's strongest per-secret controls — --require-approval,
// --require-grant, --no-print, the kill switch, deny-by-default MCP exposure — are all enforced on
// the paths that *release* a value, and `approve()` anchors the strongest of them to an interactive
// confirmation on the controlling terminal (SEC-06).
//
// The commands that *change those rules* had no such anchor. An agent refused by --require-grant
// could run `arca grant NAME --ttl 52w --uses 0` and retry; an agent hidden by `mcp --strict` could
// run `arca agent allow NAME`; and widest of all, `arca recipients add <own key>` + `arca reencrypt`
// re-wraps every value to a key the operator does not hold — permanently, on every machine the store
// reaches, without ever entering an access path, so no per-secret policy applies and no canary trips.
// `handle create` is the widest of the self-serve paths, because run_with_handle skips the whole
// gate() ladder rather than satisfying one rung of it; it already refused a *detected* agent, which
// is the advisory half, and now carries the terminal anchor as well.
//
// So the disclosure path was anchored and the control plane was not, which meant every control on
// the disclosure path could be edited away by the party it governs. This file closes that.
//
// Deliberately NOT anchored: the commands that only ever *restrict* — `agent deny`, `disable`,
// `recipients rm`, `handle revoke`. The rule is **anchor the loosening direction only; tightening must always work
// headless.** arca's existing convention is that the environment may refuse but never grant
// (ARCA_APPROVAL=deny is honored, =allow is not), a caller that can only tighten its own constraints
// is not an escalation path, and `recipients rm` is emergency revocation — putting a prompt on the
// incident-response path costs speed exactly when speed is what matters.
package main

import (
	"fmt"
	"strings"
)

// requireOperator refuses a control-plane mutation unless a human confirms it on the controlling
// terminal. `cmd` names the command for the refusal message; `question` is the yes/no question shown
// on the terminal, and should say what is about to change.
//
// It is deliberately an *interactive prompt*, not a `hasControllingTTY()` predicate, and that is the
// load-bearing decision in this file. A TTY-presence check looks like the same anchor approve() uses
// but is not: an agent launched from the operator's own terminal session **inherits that terminal**,
// which is how a coding assistant normally runs. hasControllingTTY() returns true for it, so the
// predicate form would pass for the primary adversary and buy nothing in the setup arca is deployed
// in. Adding `detectIdentity().Agent == ""` does not rescue it either — arca's own threat model says
// env markers are scrubbable, and that is the entire reason the terminal anchor exists.
//
// The prompt is what survives scrubbed-markers-plus-shared-terminal, because the question is
// rendered on the operator's screen and someone has to answer it.
//
// Two checks, in order, because they fail for different reasons and deserve different messages:
//
//  1. A *detected* agent is refused outright, with no prompt. This half is advisory (an agent can
//     scrub the markers) but it produces by far the clearest error for the common, cooperating case,
//     and it means an agent cannot make an unexpected prompt appear on the operator's terminal.
//  2. Everyone else must answer the question on /dev/tty (CONIN$/CONOUT$ on Windows). No terminal is
//     a refusal, so a headless caller — CI, a daemon, an agent with scrubbed markers and no tty — is
//     fail-closed regardless of what the environment claims.
//
// Residuals, stated rather than papered over:
//
//   - On Windows a console-attached process does have CONIN$, so the anchor is weaker there than on
//     Unix — the same trade-off T2 already documents for approval.
//   - An agent that shares the operator's controlling terminal can attempt to answer its own prompt:
//     it can consume a keystroke meant for the shell, and on macOS the TIOCSTI ioctl
//     ("simulate terminal input", sys/ttycom.h:125) is unprivileged for the controlling terminal.
//     So this converts a *silent* self-authorization into a *visible* one — the question still
//     renders on the operator's screen — rather than making it impossible. That is a real
//     improvement over the predicate and not a guarantee; the guarantee needs the key out of the
//     agent's reach (see the AR-1 framing in docs/THREAT-MODEL.md).
func requireOperator(cmd, question string) error {
	if agent := detectIdentity().Agent; agent != "" {
		return fmt.Errorf(
			"`arca %s` changes the controls that govern agents, so it is a human action; "+
				"this caller is detected as %q. Ask the operator to run it at a terminal", cmd, agent)
	}
	in, out, err := openTTY()
	if err != nil {
		return fmt.Errorf(
			"`arca %s` changes the controls that govern agents, so it must be confirmed by a human "+
				"on a terminal, and no controlling terminal is available. Re-run it interactively", cmd)
	}
	defer in.Close()
	if out != in {
		defer out.Close()
	}
	fmt.Fprintf(out, "%s [y/N] ", question)
	var resp string
	_, _ = fmt.Fscanln(in, &resp)
	if strings.EqualFold(strings.TrimSpace(resp), "y") {
		return nil
	}
	return fmt.Errorf("`arca %s` declined at the terminal", cmd)
}

// There is deliberately NO environment bypass, and there must not be one. ARCA_APPROVAL=allow was
// removed for exactly this reason: an agent controls its own environment, so an env-var escape hatch
// hands the bypass straight back to the party being constrained. If a genuinely non-interactive
// consumer ever appears, the answer is an operator-minted capability — created interactively, scoped,
// expiring, and **never written to the state dir**, because a bearer token on local disk is readable
// by the same UID this anchor exists to stop (handles.json is written 0600 to stateDir(), which is
// the shape to avoid). Until such a consumer exists, no bypass is built at all.
// TestControlPlaneHasNoEnvBypass enforces the absence.
