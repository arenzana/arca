package main

// Tests for slice S6 — finding R4, ruling D2. Two independent bugs share one finding:
//
//  1. auditPath() honoured $ARCA_AUDIT unconditionally, so a detected agent could point its own
//     audit log at a scratch file. The redirect is refused now (checkAuditRedirect).
//  2. tripCanary() discarded logAudit's error, making the tripwire the one event in arca that was
//     not fail-closed. An unrecordable trip now fails the access.
//
// Ten tests: six assert the NEW behaviour and fail against the pre-fix baseline (f984ce5) per
// merge rule 2; four assert *preserved* behaviour — the operator's own use of $ARCA_AUDIT, an
// $ARCA_AUDIT pointing at the path arca would have used anyway, and the same through a symlink and
// through a hard link — and pass on both sides on purpose, because they are what stops the fix
// overshooting.
//
// Applying this file to the baseline needs one scaffolding function, and the earlier version of
// this comment said the opposite ("using only symbols that exist there"), which cost a reviewer a
// `go vet` failure. The missing symbol is defaultAuditPath, introduced by the fix; the shim is
//
//	func defaultAuditPath() string { return filepath.Join(xdg.StateDir(), "audit.db") }
//
// which is what the baseline's own auditPath() falls back to (main.go:212 @ f984ce5). Add it, do
// not remove the three tests that reference it — subtracting tests to make the file compile is an
// edit to the artifact under test, and "no other change" stops being true the moment it happens.
// One consequence to expect: TestArcaAuditDefaultThroughAHardLinkIsNotARedirect fails at the
// baseline for an environmental reason (the shim's flat path has no D4 layout to link against),
// not a behavioural one.

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/arenzana/arca/internal/audit"
	"github.com/arenzana/arca/internal/xdg"
)

// TestAgentCannotRedirectItsAuditLog is R4 at its narrowest: with an agent marker set, an
// $ARCA_AUDIT pointing anywhere but this store's own DB refuses the command outright.
//
// It also asserts the shadow DB is never created. That is the difference between refusing and
// ignoring: a fallback to the real log would still have opened (and created) whatever the agent
// named, which is a file the operator did not ask for and a signal the agent could probe for.
func TestAgentCannotRedirectItsAuditLog(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "s3cret-value", "set", "API")
	realLog := auditPath() // captured before the redirect, while $ARCA_AUDIT is unset

	shadow := filepath.Join(t.TempDir(), "shadow.db")
	t.Setenv("AI_AGENT", "claude-code")
	t.Setenv("ARCA_AUDIT", shadow)

	err := runArcaErr("", "get", "API")
	if err == nil {
		t.Fatal("an agent redirected its own audit log and the read was allowed")
	}
	if !strings.Contains(err.Error(), "ARCA_AUDIT") {
		t.Fatalf("the refusal must name the variable it refused on, got: %v", err)
	}
	if _, statErr := os.Stat(shadow); !os.IsNotExist(statErr) {
		t.Fatalf("the shadow audit db exists at %s: the refusal has to land before anything opens it", shadow)
	}

	// And the real log must not have recorded the read either — the command never ran.
	a, err := audit.Open(realLog)
	if err != nil {
		t.Fatal(err)
	}
	evs, err := a.Recent("API", 50)
	a.Close()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if e.Op == "read" {
			t.Fatal("a refused command still recorded a read against the real log")
		}
	}
}

// TestAuditRedirectWouldHaveResetTheRateLimit is the consequence worth reading hardest, and the
// reason R4 is HIGH rather than a hygiene item. The audit log IS the rate counter (checkRateLimit
// counts events in whatever DB auditPath() returns), so before the fix a redirect handed the agent
// a fresh budget on every secret — with `arca log` against the real DB showing nothing new.
func TestAuditRedirectWouldHaveResetTheRateLimit(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "rate-limited-value", "set", "API", "--rate", "1/1h")

	runArca(t, "", "get", "API") // burns the single permitted use
	if err := runArcaErr("", "get", "API"); err == nil {
		t.Fatal("precondition failed: the rate limit did not bite on the second read")
	}

	// The exploit: same secret, same window, a log nobody counts against.
	t.Setenv("AI_AGENT", "claude-code")
	t.Setenv("ARCA_AUDIT", filepath.Join(t.TempDir(), "shadow.db"))
	err := runArcaErr("", "get", "API")
	if err == nil {
		t.Fatal("redirecting the audit log reset the rate limit — this is R4")
	}
	if !strings.Contains(err.Error(), "ARCA_AUDIT") {
		t.Fatalf("read was refused, but not by the redirect guard: %v", err)
	}
}

// TestAuditRedirectIsRefusedBeforeTheCommandDoesAnyWork pins the placement of the guard, not just
// its predicate. It runs in the command tree's persistent pre-run hook, so a refused `set` has not
// already written the store. Move the check into the audit path itself and this fails: `set`
// encrypts, saves, bumps the generation, and only then discovers it cannot audit.
func TestAuditRedirectIsRefusedBeforeTheCommandDoesAnyWork(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")

	before, err := os.ReadFile(xdg.StorePath())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AI_AGENT", "claude-code")
	t.Setenv("ARCA_AUDIT", filepath.Join(t.TempDir(), "shadow.db"))

	if err := runArcaErr("planted", "set", "PLANTED"); err == nil {
		t.Fatal("a redirected agent was allowed to write a secret")
	}
	after, err := os.ReadFile(xdg.StorePath())
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("the store changed under a refused command: the guard runs too late")
	}
}

// TestVersionAndHelpSurviveTheRefusal pins the claim newRoot's comment makes about placement:
// cobra checks --help and --version inside execute() *before* it walks the tree for a persistent
// pre-run hook (cobra v1.10.2, command.go:934/945 vs :985), so both stay usable under the refusal.
// That matters because they are what an operator reaches for while diagnosing it, and neither
// reads a secret or the audit log.
//
// Scoped honestly: execArca discards cobra's own writer, so this asserts only that the two return
// no error — not what they printed. The discriminator is the third command in the same process
// environment, which must still be refused; without it a broken guard would pass this vacuously.
func TestVersionAndHelpSurviveTheRefusal(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	t.Setenv("AI_AGENT", "claude-code")
	t.Setenv("ARCA_AUDIT", filepath.Join(t.TempDir(), "shadow.db"))

	if _, err := execArca("", "--version"); err != nil {
		t.Fatalf("--version was refused: %v", err)
	}
	if _, err := execArca("", "--help"); err != nil {
		t.Fatalf("--help was refused: %v", err)
	}
	if err := runArcaErr("", "ls"); err == nil {
		t.Fatal("the environment is not actually hostile here, so the two checks above prove nothing")
	}
}

// TestOperatorMayStillRedirectTheAuditLog is the no-overshoot half. Pointing several stores at one
// log is documented behaviour for a human, and the guard is anchored on agent detection alone, so
// this must keep working — including with no controlling terminal, which is every CI run and every
// cron job. Passes before and after the fix on purpose.
func TestOperatorMayStillRedirectTheAuditLog(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")

	shared := filepath.Join(t.TempDir(), "shared.db")
	t.Setenv("ARCA_AUDIT", shared)
	withNoTTY(t) // an operator's script, not a terminal session

	runArca(t, "v", "set", "API")
	if out := runArca(t, "", "get", "API"); out != "v" {
		t.Fatalf("get = %q, want v", out)
	}

	a, err := audit.Open(shared)
	if err != nil {
		t.Fatal(err)
	}
	evs, err := a.Recent("API", 50)
	a.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) == 0 {
		t.Fatalf("nothing was recorded in the operator's chosen log at %s", shared)
	}
}

// TestArcaAuditPointingAtTheDefaultIsNotARedirect covers the carve-out: $ARCA_AUDIT set to the very
// file arca would have used anyway redirects nothing, so there is nothing to refuse. A harness that
// pins the path explicitly (which arca's own e2e box used to do) is not an attack.
func TestArcaAuditPointingAtTheDefaultIsNotARedirect(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")

	t.Setenv("ARCA_AUDIT", defaultAuditPath())
	t.Setenv("AI_AGENT", "claude-code")
	runArca(t, "v", "set", "API")
	if out := runArca(t, "", "get", "API"); out != "v" {
		t.Fatalf("get = %q, want v", out)
	}
}

// TestArcaAuditDefaultThroughASymlinkBeforeTheDBExists pins resolvePath inside sameFile.
//
// The guard runs before anything opens the DB, so on a fresh machine it has to decide about a file
// that does not exist yet — and os.SameFile cannot help there. Only resolving the paths can see
// that a spelling arriving through a symlinked parent names the same file, which is the exact
// platform quirk D4 already had to handle ($TMPDIR and /var are symlinks to /private/… on macOS).
//
// Reversion: drop resolvePath from sameFile and this fails while the sibling test below still
// passes — which is how I found that a single symlink test proved only the os.SameFile branch.
func TestArcaAuditDefaultThroughASymlinkBeforeTheDBExists(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs elevation on Windows")
	}
	sandbox(t)
	runArca(t, "", "init") // does not record an event, so no audit db yet

	realDir := filepath.Dir(defaultAuditPath())
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(defaultAuditPath()); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARCA_AUDIT", filepath.Join(link, "audit.db"))
	t.Setenv("AI_AGENT", "claude-code")
	runArca(t, "v", "set", "API") // the guard must not refuse a path that is the default
}

// TestArcaAuditDefaultThroughAHardLinkIsNotARedirect pins the os.SameFile branch — the only case
// resolvePath cannot reach, because a hard link is a second name for one inode and no amount of
// path resolution makes the two strings equal.
//
// Scope this honestly: a hard-linked audit DB is not a real deployment, it is the portable way to
// exercise the branch. What the branch is actually there for is a case-insensitive filesystem,
// which is Windows CI, and that is not reachable from this host. The residual either way is
// fail-closed — a spelling sameFile cannot match is refused, with the expected path in the message.
func TestArcaAuditDefaultThroughAHardLinkIsNotARedirect(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Link needs NTFS and elevation on some Windows setups; the branch is exercised on Unix")
	}
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "API") // records an event, so the db exists to be linked

	alias := filepath.Join(t.TempDir(), "alias.db")
	if err := os.Link(defaultAuditPath(), alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARCA_AUDIT", alias)
	t.Setenv("AI_AGENT", "claude-code")
	if out := runArca(t, "", "get", "API"); out != "v" {
		t.Fatalf("get = %q, want v", out)
	}
}

// TestCanaryTripThatCannotBeRecordedIsRefused is the second half of D2.
//
// The discriminating case is `get --no-log` for a human at a terminal: the read event is suppressed,
// so the canary event is the ONLY record that the decoy was touched. Before the fix, logAudit's
// error was discarded there — a caller who had broken the audit DB could take the decoy and leave
// no trace at all except a line on the stderr they themselves were reading.
//
// The access staying non-blocking when the trip DOES record is asserted separately, by TestCanary.
func TestCanaryTripThatCannotBeRecordedIsRefused(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "", "canary", "TRAP", "--template", "github")
	runArca(t, "", "get", "TRAP") // one honest trip, which also creates the audit db

	withTTYResponse(t, "") // --no-log is honoured only for a human at a controlling terminal
	if err := os.WriteFile(auditPath(), []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := execArca("", "get", "TRAP", "--no-log")
	if err == nil {
		t.Fatal("a canary trip that could not be recorded was allowed, leaving no trace of the access")
	}
	if strings.HasPrefix(out, "ghp_") {
		t.Fatalf("the decoy value was disclosed by the refused read: %q", out)
	}
}

// TestCanaryTripThroughAHandleIsRefusedWhenUnrecordable covers the second call site. The MCP
// run_with_handle path bypasses gate() entirely — the handle is the authorization — so it carries
// the fail-closed rule itself. A fix applied only in gate() would leave the widest agent-facing
// path with the old swallow, which is the path an agent actually has.
//
// Scoped honestly: this call already failed before the fix, because the logAudit("exec", …) further
// down the same function is fail-closed. So the discriminator here is WHICH check refuses, which is
// why the message is asserted and not just IsError. The material difference behind that message is
// ordering — the trip now refuses before loadIDs and crypto.Decrypt, so the decoy is never
// decrypted into the process at all.
func TestCanaryTripThroughAHandleIsRefusedWhenUnrecordable(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "", "canary", "TRAP", "--template", "github")
	id := strings.TrimSpace(runArca(t, "", "handle", "create", "TRAP", "--as", "TRAPV", "--command", "sh *", "--ttl", "1h"))
	call(t, mcpRunWithHandle, map[string]any{"handle": id, "command": "sh", "args": []any{"-c", "true"}})

	if err := os.WriteFile(auditPath(), []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := call(t, mcpRunWithHandle, map[string]any{"handle": id, "command": "sh", "args": []any{"-c", "true"}})
	if !res.IsError {
		t.Fatal("an unrecordable canary trip through a handle was allowed")
	}
	if got := text(t, res); !strings.Contains(got, "could not be recorded") {
		t.Fatalf("handle run failed, but not on the unrecordable trip: %q", got)
	}
}
