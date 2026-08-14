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

	"github.com/arenzana/arca/internal/policy"
	"github.com/arenzana/arca/internal/store"
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

// ----------------------------------------------------------------------------
// The write path (T13/R28): `set` and `generate` relaxing an existing policy.
// ----------------------------------------------------------------------------
//
// The six commands above are anchored unconditionally, because every one of them exists only to
// widen access. `set` and `generate` are different: their job is to write a value, and the policy
// flags ride along. Anchoring them unconditionally would put a prompt on every first `set` — and a
// prompt that fires when nothing is being given away is one the operator learns to answer `y` to
// without reading, which costs the anchors above their meaning too.
//
// So the predicate is narrower than the six and has to be exact: fire only when (the secret already
// exists) AND (this invocation leaves it less protected than it is now). Creating a secret with a
// loose policy is a choice, not a downgrade. Tightening is always allowed headless, per the rule in
// the file header.

// policyDowngrade is one field that a `set`/`generate` invocation would relax on a secret that
// already exists. The `from`/`to` strings are what the operator is shown, so they say what the
// stored policy is now and what it would become — not what flag was typed.
type policyDowngrade struct{ flag, from, to string }

func (d policyDowngrade) String() string { return fmt.Sprintf("%s %s → %s", d.flag, d.from, d.to) }

// policyDowngrades reports every way this invocation would leave `cur` less protected. It returns
// nil (no anchor) when cur is nil — a secret that does not exist yet has no policy to downgrade.
//
// `changed` is cmd.Flags().Changed, threaded in rather than taking a *cobra.Command so the predicate
// is testable without building a command. A field is only considered when its flag was actually
// given: without that, the zero value of every bool flag reads as an explicit `false` and a plain
// `arca set NAME` would look like it clears all three bits.
//
// The set of fields covered here is every policy field `set` and `generate` write under a
// `Changed(...)` guard — the four R28 names plus `--canary`, which is written in the same block and
// is the only path in the CLI that disarms a decoy. Checking that the list is complete is a matter
// of reading those two blocks, not of trusting this comment; TestPolicyPredicateCoversEveryPolicyFlag
// fails if either command grows a policy flag this predicate does not know about.
func policyDowngrades(name string, changed func(string) bool, cur *store.Secret, p policyFlags) ([]policyDowngrade, error) {
	if cur == nil {
		return nil, nil
	}
	var out []policyDowngrade
	for _, b := range []struct {
		flag string
		now  bool
		next bool
	}{
		{"--no-print", cur.NoPrint, p.noPrint},
		{"--require-approval", cur.RequireApproval, p.requireApproval},
		{"--require-grant", cur.RequireGrant, p.requireGrant},
	} {
		if changed(strings.TrimPrefix(b.flag, "--")) && b.now && !b.next {
			out = append(out, policyDowngrade{b.flag, "true", "false"})
		}
	}
	if changed("rate") {
		d, err := rateDowngrade(cur, p.rate)
		if err != nil {
			return nil, err
		}
		if d != nil {
			out = append(out, *d)
		}
	}
	// T13 residual: an expiry is a policy, and extending one leaves the value usable for longer.
	if changed("ttl") || changed("expires-at") {
		d, err := expiryDowngrade(cur, p.ttl, p.expiresAt, time.Now())
		if err != nil {
			return nil, err
		}
		if d != nil {
			out = append(out, *d)
		}
	}
	if changed("canary") && !p.canary {
		was, err := canaryNow(name, cur)
		if err != nil {
			return nil, err
		}
		if was {
			out = append(out, policyDowngrade{"--canary", "true", "false"})
		}
	}
	return out, nil
}

// canaryNow reports whether name is a decoy right now, for the purpose of deciding whether this
// invocation disarms one. It deliberately does *not* reuse isCanary().
//
// isCanary() swallows a registry read error and answers "not a canary", which is right where it is
// used: canary alerting is best-effort and must never block an access. Here the same error would
// mean the anchor silently does not fire on the one path that turns a tripwire off — a guard that
// fails open. So the error is returned and `set`/`generate` refuse on it.
//
// The legacy pre-SEC-04 store flag counts, the same as in isCanary(): a store written before the
// designation moved out of the synced file still carries it, and such a secret is still a live decoy.
func canaryNow(name string, cur *store.Secret) (bool, error) {
	if cur != nil && cur.Canary {
		return true, nil
	}
	set, err := loadCanaries()
	if err != nil {
		return false, fmt.Errorf("cannot tell whether %s is a canary, so refusing to change it: %w", name, err)
	}
	return set[name], nil
}

// rateDowngrade compares the stored rate limit against the one this invocation would write and
// reports the change only when it permits *more* uses per unit of time.
//
// T13 names `--rate ""` — clearing the limit. Anchoring only that spelling would be theatre: an
// agent blocked from clearing the limit writes `--rate 1000000/1s` instead and holds the same
// capability. So the comparison is on the rate itself, and clearing is simply the limiting case of
// raising it. A tighter limit, and a limit newly applied to a secret that had none, stay headless.
//
// The window defaulting mirrors checkRateLimit() through the shared policy.RateWindow() helper, so what is
// compared here is what is enforced there. Two copies of that rule would be one refactor away from
// an anchor that guards a policy nobody applies.
// expiryDowngrade reports whether this invocation would leave a secret usable for longer than it
// is now. It is a comparison rather than a spelling match for the reason rateDowngrade is: an
// agent refused one way of relaxing a control reaches for another.
//
// The ordering is what makes it decidable. No expiry at all is the *least* protected state, and an
// earlier expiry is more protected than a later one. So:
//
//   - a secret with no expiry has nothing to relax; anything written is same-or-tighter
//   - moving the instant later extends the window in which the value still works: a downgrade
//   - moving it earlier, or setting one where there was none, tightens: no anchor
//   - clearing it outright is the widest form of that same move, from a deadline to none
//
// Both flags are resolved to an instant first, which is what collapses "extend versus shorten"
// from a rule per spelling into one comparison. `now` is a parameter so the boundary is testable.
func expiryDowngrade(cur *store.Secret, ttl, expiresAt string, now time.Time) (*policyDowngrade, error) {
	if cur.ExpiresAt == nil {
		return nil, nil // it already never expires; there is no protection here to remove
	}
	next, err := policy.ResolveExpiry(ttl, expiresAt, now)
	if err != nil {
		return nil, err // surface the bad flag before prompting, not after
	}
	curDesc := cur.ExpiresAt.UTC().Format(time.RFC3339)
	if next == nil {
		return &policyDowngrade{"--ttl/--expires-at", curDesc, "never"}, nil
	}
	if !next.After(*cur.ExpiresAt) {
		return nil, nil
	}
	return &policyDowngrade{"--ttl/--expires-at", curDesc, next.UTC().Format(time.RFC3339)}, nil
}

func rateDowngrade(cur *store.Secret, rate string) (*policyDowngrade, error) {
	if cur.RateLimit <= 0 {
		return nil, nil // no limit today: anything this invocation writes is the same or tighter
	}
	_, curWin := policy.RateWindow(cur.RateWindow)
	curDesc := fmt.Sprintf("%d/%s", cur.RateLimit, curWin)
	if strings.TrimSpace(rate) == "" {
		return &policyDowngrade{"--rate", curDesc, "unlimited"}, nil
	}
	n, w, err := policy.ParseRate(rate)
	if err != nil {
		return nil, err // surface the bad flag before prompting, not after
	}
	if perSecond(n, w) <= perSecond(cur.RateLimit, cur.RateWindow) {
		return nil, nil
	}
	return &policyDowngrade{"--rate", curDesc, fmt.Sprintf("%d/%s", n, w)}, nil
}

// perSecond normalizes "N per window" so limits with different windows are comparable.
func perSecond(limit int, window string) float64 {
	win, _ := policy.RateWindow(window)
	return float64(limit) / win.Seconds()
}

// requirePolicyOperator anchors a policy relaxation on an existing secret to the operator's
// terminal. It is a no-op for a new secret and for any invocation that only tightens.
//
// It is called *before* the value is read and encrypted, on purpose. The write path overwrites the
// value unconditionally and before the policy block, so a refusal that arrived after the write
// would leave the caller having destroyed the secret it was refused permission to downgrade — the
// anchor would then be a control that only adds damage.
func requirePolicyOperator(cmdName, name string, changed func(string) bool, cur *store.Secret, p policyFlags) error {
	downgrades, err := policyDowngrades(name, changed, cur, p)
	if err != nil || len(downgrades) == 0 {
		return err
	}
	parts := make([]string, 0, len(downgrades))
	for _, d := range downgrades {
		parts = append(parts, d.String())
	}
	return requireOperator(cmdName, fmt.Sprintf("Relax the policy on %s (%s)?", name, strings.Join(parts, "; ")))
}
