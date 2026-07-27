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
	"time"
)

// operatorTimeout bounds how long requireOperator waits for a human answer on the controlling
// terminal. Without it the prompt was an unbounded Fscanln: a terminal handle that *opens* but
// never delivers input — a Windows console (CONIN$ opens for any console-attached process, human
// or not), or a pty held by a supervisor that never relays keystrokes — blocked the process
// forever (W1). That is an availability failure, not a bypass: the anchor failed *stuck*, and on
// the paths that hold the store lock it wedged the store for every other arca process, because the
// lock heartbeat (lock.go) keeps a hung holder looking alive past staleLockAge. Failing closed on
// a deadline converts the hang into the same refusal a missing terminal already produces.
//
// The value is deliberately small: it bounds CI cost where the refusal is the asserted outcome
// (e2e on Windows runs the anchor checks against a console no human is watching), and a real
// operator who gets cut off can simply re-run — the refusal says so. It is a package var so tests
// can shorten it, same convention as lockTimeout/staleLockAge (lock.go).
var operatorTimeout = 5 * time.Second

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
//     fail-closed regardless of what the environment claims. A terminal that opens but stays silent
//     is the same refusal after operatorTimeout (see above), so a console no human is watching
//     fails closed too instead of hanging.
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
	closeIn := true
	defer func() {
		if closeIn {
			in.Close()
		}
	}()
	if out != in {
		defer out.Close() // no read is ever pending on out; safe unconditionally
	}
	fmt.Fprintf(out, "%s [y/N] ", question)
	// The read carries the operatorTimeout deadline described above. It runs in a goroutine
	// because a blocked Fscanln cannot be interrupted; on expiry the goroutine stays parked on
	// the dead handle until process exit, which for this CLI follows the refusal immediately.
	// The channel is buffered so that parked goroutine never leaks on its send.
	answered := make(chan string, 1)
	go func() {
		var resp string
		_, _ = fmt.Fscanln(in, &resp)
		answered <- resp
	}()
	select {
	case resp := <-answered:
		if strings.EqualFold(strings.TrimSpace(resp), "y") {
			return nil
		}
		// Any non-yes answer — including EOF, which is what a console with no input queued
		// delivers — is a decline. This message must NOT name the timeout: the two refusals
		// mean different things (a human said no vs. nobody was there) and read differently.
		return fmt.Errorf("`arca %s` declined at the terminal", cmd)
	case <-time.After(operatorTimeout):
		// Do NOT close `in`: a goroutine is parked in a synchronous read on it.
		closeIn = false
		return fmt.Errorf("`arca %s` was not confirmed on the terminal within %s — no answer was received, so it was refused. Re-run it interactively to confirm", cmd, operatorTimeout)
	}
}

// There is deliberately NO environment bypass, and there must not be one. ARCA_APPROVAL=allow was
// removed for exactly this reason: an agent controls its own environment, so an env-var escape hatch
// hands the bypass straight back to the party being constrained. If a genuinely non-interactive
// consumer ever appears, the answer is an operator-minted capability — created interactively, scoped,
// expiring, and **never written to the state dir**, because a bearer token on local disk is readable
// by the same UID this anchor exists to stop (handles.json is written 0600 to stateDir(), which is
// the shape to avoid). Until such a consumer exists, no bypass is built at all.
// TestControlPlaneHasNoEnvBypass enforces the absence.
