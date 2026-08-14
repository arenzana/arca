// Tests for per-store state dirs (R5 / design D4).
//
// The three TestQA_ cases cover all four consequences Scott filed under F3 in
// RESEARCH/ARCA_QA_FINDINGS.md — cross-store data loss, a false positive on the rollback control,
// unexpected network reach, and grants that are not store-scoped. They are the reason this slice
// exists and all four FAIL at the pre-D4 baseline `f984ce5`. Everything below them covers the
// keying and the one-time adoption of the old flat layout.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arenzana/arca/internal/audit"
	"github.com/arenzana/arca/internal/remote"
	"github.com/arenzana/arca/internal/xdg"
)

// TestQA_SecondStoreOnSameMachineIsClobberedBySync (Scott, QA) — one operator, one machine, one
// identity, TWO stores (personal and work). Sync is configured for store A. Because sync.json and
// store.gen used to live in a single $XDG_STATE_HOME/arca regardless of which store was loaded,
// running sync against store B reconciled B against store A's backend and replaced its contents.
//
// Note the difference from the existing sync tests: switchMachine() moves ARCA_STORE and
// XDG_STATE_HOME together, which models a second MACHINE. This models a second STORE on the SAME
// machine — the configuration the suite never exercised.
func TestQA_SecondStoreOnSameMachineIsClobberedBySync(t *testing.T) {
	dir := sandbox(t)
	withFakeBackend(t)

	// Store A: the synced one. Several secrets so its generation is well ahead of a freshly
	// created second store — the realistic case, where the main store has history.
	runArca(t, "", "init")
	runArca(t, "value-from-store-A", "set", "PERSONAL_ONLY")
	for _, n := range []string{"A2", "A3", "A4", "A5"} {
		runArca(t, "v", "set", n)
	}
	runArca(t, "", "sync")

	// Store B: a second store on the SAME machine. Same identity, same recipients, same state
	// dir. Only ARCA_STORE moves — exactly what an operator would do.
	storeB := filepath.Join(dir, "work-store.json")
	t.Setenv("ARCA_STORE", storeB)

	runArca(t, "", "init")
	runArca(t, "value-from-store-B", "set", "WORK_ONLY")

	before, err := os.ReadFile(storeB)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(before), "WORK_ONLY") {
		t.Fatalf("precondition failed: store B does not contain WORK_ONLY")
	}

	_, _ = execArca("", "sync")

	after, err := os.ReadFile(storeB)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(after), "WORK_ONLY") {
		t.Errorf("DATA LOSS: store B lost its own secret WORK_ONLY after a sync aimed at store A's backend.\nstore B is now:\n%s", string(after))
	}
	if strings.Contains(string(after), "PERSONAL_ONLY") {
		t.Errorf("CROSS-STORE CONTAMINATION: store B now holds store A's secret PERSONAL_ONLY")
	}
}

// TestQA_RollbackHighWaterMarkIsNotPerStore (Scott, QA) — the same root cause producing a FALSE
// POSITIVE on a tamper-detection control: store.gen was global, so a legitimate second store at a
// lower generation was flagged as rolled back. Alarm fatigue on a security control is a defect in
// its own right.
func TestQA_RollbackHighWaterMarkIsNotPerStore(t *testing.T) {
	dir := sandbox(t)

	runArca(t, "", "init")
	for _, n := range []string{"A1", "A2", "A3", "A4", "A5"} {
		runArca(t, "v", "set", n)
	}

	// A brand-new, unrelated second store starts at generation 1.
	t.Setenv("ARCA_STORE", filepath.Join(dir, "second-store.json"))
	runArca(t, "", "init")

	if regressed, hwm := recordStoreGeneration(1); regressed {
		t.Errorf("FALSE POSITIVE on the rollback control: a brand-new second store (generation 1) is reported as rolled back against the FIRST store's high-water mark %d, because store.gen is shared across stores", hwm)
	}
}

// TestQA_SecondStoreInheritsNeitherSyncConfigNorGrants (Scott, QA) covers consequences 3 and 4 of
// F3, which the two tests above do not: the shared state dir also shared the *sync configuration*
// and the *grants*.
//
// Consequence 3 is the one Scott hit on his very first command — `arca init` against a scratch
// store attempted an auto-sync against the real configured backend, because `sync auto on` lived in
// the shared state dir. The layered pull guards stopped it, so nothing was disclosed; the attempt
// itself is the defect. A store the operator has not configured for sync must not reach the network.
//
// Consequence 4: a grant issued in store A was listed and honoured in store B. Impact is confusion
// rather than disclosure — the agent still only reaches its own store's value — but a grant should
// name the store it authorises.
func TestQA_SecondStoreInheritsNeitherSyncConfigNorGrants(t *testing.T) {
	dir := sandbox(t)
	fake := withFakeBackend(t)

	runArca(t, "", "init")
	runArca(t, "v", "set", "DEPLOY", "--require-grant")
	runArca(t, "", "sync", "init", "s3://bucket/prefix")
	runArca(t, "", "sync", "auto", "on")
	runArca(t, "", "grant", "DEPLOY", "--ttl", "1h")
	if !autoSyncEnabled() {
		t.Fatal("precondition: auto-sync should be on for store A")
	}
	if g, err := loadGrants(); err != nil || len(g) != 1 {
		t.Fatalf("precondition: store A should hold one grant, got %v %v", g, err)
	}

	// A second store on the SAME machine. Only ARCA_STORE moves.
	t.Setenv("ARCA_STORE", filepath.Join(dir, "work-store.json"))
	counted := &countingBackend{Backend: fake}
	old := openBackend
	t.Cleanup(func() { openBackend = old })
	openBackend = func() (remote.Backend, error) { return counted, nil }

	runArca(t, "", "init")
	runArca(t, "v", "set", "WORK_ONLY")

	if counted.calls > 0 {
		t.Errorf("UNEXPECTED NETWORK REACH: a store with no sync configuration made %d backend call(s), inheriting store A's `sync auto on`", counted.calls)
	}
	if autoSyncEnabled() {
		t.Error("the second store inherited store A's auto-sync setting")
	}
	if _, err := os.Stat(syncConfigPath()); err == nil {
		t.Error("the second store inherited store A's sync config, including its backend credentials")
	}
	g, err := loadGrants()
	if err != nil {
		t.Fatal(err)
	}
	if len(g) != 0 {
		t.Errorf("GRANTS ARE NOT STORE-SCOPED: the second store lists %v, granted in store A", g)
	}
}

// TestStoreStateKeyIsStableAndDistinct pins the keying itself: same store ⇒ same dir across calls
// (or every invocation would land somewhere new), different store ⇒ different dir (or the clobber
// above comes back). A relative and an absolute path to the same file must agree, since the key is
// derived from the absolute path.
func TestStoreStateKeyIsStableAndDistinct(t *testing.T) {
	dir := sandbox(t)

	a := storeStateDir()
	if a != storeStateDir() {
		t.Fatal("state dir is not stable across calls for one store")
	}
	if !strings.HasPrefix(a, filepath.Join(xdg.StateDir(), "stores")+string(os.PathSeparator)) {
		t.Fatalf("state dir %s is not under %s", a, storesRoot())
	}

	t.Setenv("ARCA_STORE", filepath.Join(dir, "other.json"))
	if b := storeStateDir(); b == a {
		t.Fatalf("two distinct stores share the state dir %s", b)
	}

	// A relative path to the same file keys the same, because the key uses the absolute path.
	abs := filepath.Join(dir, "rel-target.json")
	t.Setenv("ARCA_STORE", abs)
	want := storeStateDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARCA_STORE", "rel-target.json")
	if got := storeStateDir(); got != want {
		t.Fatalf("relative and absolute paths to one store key differently:\n rel %s\n abs %s", got, want)
	}
}

// plantLegacyState writes the pre-D4 flat layout into xdg.StateDir(): one file per adopted entry plus
// machine-id, which must NOT move. Contents are the file's own name so a test can prove a file
// arrived intact rather than merely existing.
func plantLegacyState(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll(xdg.StateDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range legacyStateEntries {
		p := filepath.Join(xdg.StateDir(), name)
		if name == "sessions" { // a directory, and it must move whole
			if err := os.MkdirAll(p, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(p, "abc.key"), []byte("seed"), 0o600); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(p, []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(machineIDPath(), []byte("host-dead\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestAdoptLegacyStateMovesEverythingOnce is the adoption path: every pre-D4 file lands in this
// store's dir with its contents intact, the claim records the owner, machine-id stays put, and
// nothing is left behind flat.
func TestAdoptLegacyStateMovesEverythingOnce(t *testing.T) {
	sandbox(t)
	plantLegacyState(t)

	dir := storeStateDir() // triggers adoption

	for _, name := range legacyStateEntries {
		if _, err := os.Stat(filepath.Join(xdg.StateDir(), name)); err == nil {
			t.Errorf("%s was left behind in the shared state dir", name)
		}
		moved := filepath.Join(dir, name)
		if name == "sessions" {
			b, err := os.ReadFile(filepath.Join(moved, "abc.key"))
			if err != nil || string(b) != "seed" {
				t.Errorf("sessions/abc.key did not survive the move: %v %q", err, b)
			}
			continue
		}
		b, err := os.ReadFile(moved)
		if err != nil {
			t.Errorf("%s did not arrive: %v", name, err)
			continue
		}
		if string(b) != name {
			t.Errorf("%s arrived with contents %q, want %q", name, b, name)
		}
	}

	// machine-id identifies the MACHINE, not the store: keying it per-store would fork this
	// machine into several escrow identities, each with its own segment sequence.
	if _, err := os.Stat(machineIDPath()); err != nil {
		t.Errorf("machine-id was moved into the per-store dir; it must stay shared: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "machine-id")); err == nil {
		t.Error("machine-id was copied into the per-store dir")
	}

	if owner := adoptedBy(); owner != absStorePath() {
		t.Errorf("the claim records %q, want %q", owner, absStorePath())
	}
	if _, err := os.Stat(adoptLockPath()); err == nil {
		t.Error("the adoption lock was left behind")
	}
}

// TestAdoptIsOnceOnly_SecondStoreGetsFreshDir is D4's "adopt once, then never again": the second,
// distinct store on the machine must not re-adopt (there is nothing left to adopt) and must not
// see the first store's state. `doctor` has to say so, because the visible symptom is otherwise
// "my grants vanished".
func TestAdoptIsOnceOnly_SecondStoreGetsFreshDir(t *testing.T) {
	dir := sandbox(t)
	plantLegacyState(t)

	first := storeStateDir() // adopts
	firstOwner := absStorePath()

	t.Setenv("ARCA_STORE", filepath.Join(dir, "second.json"))
	second := storeStateDir()
	if second == first {
		t.Fatal("the second store reused the first store's dir")
	}
	if _, err := os.Stat(filepath.Join(second, "grants.json")); err == nil {
		t.Error("the second store inherited the first store's grants")
	}
	if owner := adoptedBy(); owner != firstOwner {
		t.Errorf("the claim moved to %q; it must stay with the store that adopted (%q)", owner, firstOwner)
	}

	// doctor has to explain this, because the visible symptom is otherwise "my grants vanished".
	// LOW rather than MED on purpose: a second store starting clean is the correct outcome, and the
	// finding exists to name the cause, not to raise an alarm about a working configuration.
	found := stateDirFinding(t)
	if found.sev != sevLow || !strings.Contains(found.Detail, firstOwner) {
		t.Errorf("doctor finding does not name the owner of the adopted state: %+v (want LOW naming %s)", found, firstOwner)
	}
}

// stateDirFinding runs the state-dir check and returns its single finding.
func stateDirFinding(t *testing.T) finding {
	t.Helper()
	out := checkStateDir(&doctorEnv{})
	if len(out) != 1 || out[0].Check != "state-dir" {
		t.Fatalf("want exactly one state-dir finding, got %+v", out)
	}
	return out[0]
}

// TestAdoptionNeverOverwritesTheNewerPerStoreCopy is the collision case, and it is the one that
// could destroy state rather than merely mislay it: a run that could not adopt still has to work,
// so it writes fresh state into the per-store dir while the shared copy is still sitting flat. When
// adoption later runs, both exist. Overwriting the per-store copy would silently undo whatever that
// run recorded, so the shared copy is left alone and `arca doctor` puts the choice in front of the
// operator — who is the only one who can say which of the two they want.
//
// This also covers the doctor finding for state left in the shared dir, which must name the files:
// the remedy is to move them, and an operator cannot move a condition.
func TestAdoptionNeverOverwritesTheNewerPerStoreCopy(t *testing.T) {
	sandbox(t)
	plantLegacyState(t)

	dst := filepath.Join(storesRoot(), storeStateKey()) // computed, not via storeStateDir: no adoption yet
	if err := os.MkdirAll(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "grants.json"), []byte("newer"), 0o600); err != nil {
		t.Fatal(err)
	}

	out := captureStderr(t, func() { _ = storeStateDir() })
	if !strings.Contains(out, "grants.json") || !strings.Contains(out, "left in place") {
		t.Errorf("the collision was not reported on stderr, got %q", out)
	}

	b, err := os.ReadFile(filepath.Join(dst, "grants.json"))
	if err != nil || string(b) != "newer" {
		t.Fatalf("adoption overwrote the newer per-store copy: %v %q", err, b)
	}
	if _, err := os.Stat(filepath.Join(xdg.StateDir(), "grants.json")); err != nil {
		t.Errorf("the shared copy was destroyed rather than left in place: %v", err)
	}
	// Everything that did NOT collide still moved — one conflict must not strand the other ten.
	if _, err := os.Stat(filepath.Join(dst, "handles.json")); err != nil {
		t.Errorf("handles.json did not move past the collision: %v", err)
	}

	found := stateDirFinding(t)
	if found.sev != sevMed {
		t.Errorf("state left in the shared dir should be MED, got %+v", found)
	}
	if !strings.Contains(found.Detail, "grants.json") {
		t.Errorf("doctor does not name the left-behind grants.json: %s", found.Detail)
	}
}

// adoptHelperEnv makes a test binary invocation act as a bare adoption racer instead of a test.
const adoptHelperEnv = "ARCA_TEST_ADOPT_HELPER"

// TestAdoptHelperProcess is not a test. It is the child half of
// TestConcurrentAdoptionAcrossStoresIsSerialized: it resolves the state dir for whatever store its
// environment names — which is all it takes to trigger adoption — and exits.
func TestAdoptHelperProcess(t *testing.T) {
	if os.Getenv(adoptHelperEnv) == "" {
		t.Skip("helper process for TestConcurrentAdoptionAcrossStoresIsSerialized")
	}
	_ = storeStateDir()
}

// TestConcurrentAdoptionAcrossStoresIsSerialized is what the adoption lock exists for, and it needs
// real processes: the active store comes from the environment, so one process cannot race two
// stores no matter how many goroutines it runs.
//
// Several stores on one machine hit an unadopted state dir simultaneously. Without serialization
// they all pass the "nobody has claimed this" check, all claim it, and each moves whichever entries
// it wins the race for — splitting ONE store's grants, audit DB and sync cursor across several
// stores' dirs, which is unrecoverable without hand-reassembly. Exactly one store must end up
// owning all of it.
//
// I verified the same-process version of this test does NOT pin the lock (removing the lock leaves
// it passing, because rename is atomic so nothing is lost within one store). This one does.
func TestConcurrentAdoptionAcrossStoresIsSerialized(t *testing.T) {
	dir := sandbox(t)
	plantLegacyState(t)
	state := xdg.StateDir()

	const racers = 4
	stores := make([]string, racers)
	cmds := make([]*exec.Cmd, racers)
	for i := range racers {
		stores[i] = filepath.Join(dir, fmt.Sprintf("racer-%d.json", i))
		cmds[i] = exec.Command(os.Args[0], "-test.run=^TestAdoptHelperProcess$") //#nosec G204 -- os.Args[0] is this test binary
		cmds[i].Env = []string{
			adoptHelperEnv + "=1",
			"XDG_STATE_HOME=" + filepath.Dir(state), // xdg.StateDir() appends /arca
			"ARCA_STORE=" + stores[i],
			"HOME=" + dir,
			"PATH=" + os.Getenv("PATH"),
		}
		if err := cmds[i].Start(); err != nil {
			t.Fatal(err)
		}
	}
	for i, c := range cmds {
		if err := c.Wait(); err != nil {
			t.Fatalf("racer %d exited with %v", i, err)
		}
	}

	owner := adoptedBy()
	if owner == "" {
		t.Fatal("no racer claimed the shared state")
	}
	winner := ""
	for _, s := range stores {
		if resolved, err := filepath.EvalSymlinks(filepath.Dir(s)); err == nil {
			s = filepath.Join(resolved, filepath.Base(s))
		}
		if s == owner {
			winner = s
		}
	}
	if winner == "" {
		t.Fatalf("the claim names %q, which is none of the racers", owner)
	}

	// All of it went to one store: a split is the failure mode, and a split is exactly what a
	// per-entry race produces.
	h := sha256.Sum256([]byte(winner))
	winnerDir := filepath.Join(state, "stores", hex.EncodeToString(h[:8]))
	for _, name := range legacyStateEntries {
		if _, err := os.Stat(filepath.Join(winnerDir, name)); err != nil {
			t.Errorf("%s did not land in the winning store's dir: %v", name, err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(state, "stores"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Join(state, "stores", e.Name()) == winnerDir {
			continue
		}
		loser, err := os.ReadDir(filepath.Join(state, "stores", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if len(loser) > 0 {
			t.Errorf("a losing store's dir holds %d adopted entries; the state was split", len(loser))
		}
	}
	if left := legacyStateLeftovers(); len(left) > 0 {
		t.Errorf("%v were left in the shared dir", left)
	}
}

// TestAFailedMoveStillClaimsTheState pins the ordering inside the move: the claim is written
// BEFORE any file is renamed. Write it afterwards and a run that dies mid-move leaves entries flat
// with nobody owning them, so the next command against a *different* store sweeps one store's
// grants and sync cursor into another store's dir — the exact failure this slice exists to prevent,
// reintroduced on the crash path.
//
// The failure is injected by making `stores` a regular file, so the per-store dir cannot be created
// and the move cannot start while the shared dir stays writable. That is the one point where the
// two orderings are observable from a test: claim-first leaves a claim, claim-last leaves none.
func TestAFailedMoveStillClaimsTheState(t *testing.T) {
	dir := sandbox(t)
	plantLegacyState(t)
	if err := os.WriteFile(storesRoot(), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	first := absStorePath()
	out := captureStderr(t, func() { _ = storeStateDir() })
	if !strings.Contains(out, "could not adopt") {
		t.Errorf("a move that could not start should warn, got %q", out)
	}
	if owner := adoptedBy(); owner != first {
		t.Fatalf("claim after a failed move = %q, want %q", owner, first)
	}
	if left := legacyStateLeftovers(); len(left) != len(legacyStateEntries) {
		t.Errorf("a failed move moved something anyway: %v remain", left)
	}

	// The claim is what stops a second store from taking state it does not own.
	t.Setenv("ARCA_STORE", filepath.Join(dir, "second.json"))
	second := storeStateDir()
	if _, err := os.Stat(filepath.Join(second, "grants.json")); err == nil {
		t.Error("a second store swept up state left behind by a failed move")
	}
	if owner := adoptedBy(); owner != first {
		t.Errorf("the claim moved to %q; it belongs to %q", owner, first)
	}
}

// TestAdoptResumesAPartialMove: the claim is written before any file moves, so a run interrupted
// mid-move leaves a claim and a half-moved dir. The owner's next run must finish it. This is the
// property that replaced the old staged-then-published design, whose publish step could fail
// permanently once another process had created `stores/`, stranding the only copy of the state.
func TestAdoptResumesAPartialMove(t *testing.T) {
	sandbox(t)
	plantLegacyState(t)

	// Simulate the crash: claimed, one entry moved, the rest still flat.
	dst := filepath.Join(storesRoot(), storeStateKey())
	if err := os.MkdirAll(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(xdg.StateDir(), "grants.json"), filepath.Join(dst, "grants.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adoptedByPath(), []byte(absStorePath()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := storeStateDir()
	for _, name := range legacyStateEntries {
		if _, err := os.Stat(filepath.Join(got, name)); err != nil {
			t.Errorf("%s was not moved by the resumed adoption: %v", name, err)
		}
	}
	if left := legacyStateLeftovers(); len(left) > 0 {
		t.Errorf("the resumed adoption left %v in the shared dir", left)
	}
	if found := stateDirFinding(t); found.sev != sevOK {
		t.Errorf("a completed adoption should be OK, got %+v", found)
	}
}

// TestAdoptedStateIsNotStolenByAnotherStore: the claim is machine-wide and permanent, so legacy
// entries appearing after an adoption — a leftover from a partial move, or a downgrade-and-upgrade
// cycle — belong to the store that claimed them. A second store must leave them where they are.
func TestAdoptedStateIsNotStolenByAnotherStore(t *testing.T) {
	dir := sandbox(t)
	plantLegacyState(t)
	storeStateDir() // the first store claims and adopts

	if err := os.WriteFile(filepath.Join(xdg.StateDir(), "grants.json"), []byte("first store's"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("ARCA_STORE", filepath.Join(dir, "second.json"))
	second := storeStateDir()

	if _, err := os.Stat(filepath.Join(second, "grants.json")); err == nil {
		t.Error("a second store adopted state claimed by another store")
	}
	b, err := os.ReadFile(filepath.Join(xdg.StateDir(), "grants.json"))
	if err != nil || string(b) != "first store's" {
		t.Errorf("the first store's leftover was moved or destroyed: %v %q", err, b)
	}
}

// TestDoctorIsQuietForTheOnlyStore: the single-store machine is the overwhelmingly common case and
// it must produce no noise. A check that fires on a correct configuration is one an operator learns
// to skim past.
func TestDoctorIsQuietForTheOnlyStore(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")

	if found := stateDirFinding(t); found.sev != sevOK {
		t.Errorf("the only store on a machine should be OK, got %+v", found)
	}

	// Same, after an adoption: the store that inherited the shared state is not a problem either.
	sandbox(t)
	plantLegacyState(t)
	if found := stateDirFinding(t); found.sev != sevOK {
		t.Errorf("the store that adopted the shared state should be OK, got %+v", found)
	}
}

// TestConcurrentAdoptionMovesTheStateExactlyOnce covers concurrent resolution within one process:
// no data race on the path helpers under `-race`, no entry observable in neither location, and no
// lock left behind.
//
// What it does NOT pin, stated so nobody reads more into it than is there: the adoption lock.
// Removing the lock leaves this test passing, because every racer here is the same store and
// rename is atomic, so nothing can be lost. The lock is pinned by
// TestConcurrentAdoptionAcrossStoresIsSerialized, which needs real processes to vary the store.
func TestConcurrentAdoptionMovesTheStateExactlyOnce(t *testing.T) {
	sandbox(t)
	plantLegacyState(t)

	const racers = 8
	dirs := make([]string, racers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			dirs[i] = storeStateDir()
		}()
	}
	close(start)
	wg.Wait()

	for i, d := range dirs {
		if d != dirs[0] {
			t.Fatalf("racer %d resolved a different state dir: %s vs %s", i, d, dirs[0])
		}
	}
	if owner := adoptedBy(); owner != absStorePath() {
		t.Errorf("claim records %q, want %q", owner, absStorePath())
	}
	// Every entry is in exactly one place. The in-place move has no third location, which is the
	// property the staged design lacked: a failed publish left the only copy in a staging dir that
	// nothing would ever read again.
	for _, name := range legacyStateEntries {
		_, inShared := os.Stat(filepath.Join(xdg.StateDir(), name))
		_, inStore := os.Stat(filepath.Join(dirs[0], name))
		if inShared != nil && inStore != nil {
			t.Errorf("%s is in neither the shared dir nor the per-store dir", name)
		}
	}
	if left := legacyStateLeftovers(); len(left) > 0 {
		t.Errorf("concurrent adoption left %v behind", left)
	}
	if _, err := os.Stat(adoptLockPath()); err == nil {
		t.Error("the adoption lock was left behind")
	}
}

// TestAdoptedAuditHistoryStillVerifies is the round trip that matters, and it uses real artifacts
// rather than planted ones: build genuine audit history and state in the per-store layout, take it
// apart into the pre-D4 flat layout, then let adoption put it back and assert the chain still
// verifies with every event intact.
//
// The audit DB is the piece most likely to break silently — it runs in WAL mode, so a move that
// forgot audit.db-wal would strand committed events in a WAL the DB no longer points at.
func TestAdoptedAuditHistoryStillVerifies(t *testing.T) {
	sandbox(t)
	t.Setenv("ARCA_AUDIT", "") // let the DB live in the per-store dir, which is what adoption moves

	runArca(t, "", "init")
	for _, n := range []string{"A", "B", "C"} {
		runArca(t, "v", "set", n)
	}
	runArca(t, "", "grant", "A", "--ttl", "1h")

	dir := storeStateDir()
	a, err := audit.Open(auditPath())
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.Verify()
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
	if !res.OK || res.Checked == 0 {
		t.Fatalf("precondition: audit chain should verify with events, got ok=%v checked=%d", res.OK, res.Checked)
	}
	before := res.Checked

	// Reconstruct the pre-D4 flat layout out of this store's real state.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err := os.Rename(filepath.Join(dir, e.Name()), filepath.Join(xdg.StateDir(), e.Name())); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.RemoveAll(storesRoot()); err != nil {
		t.Fatal(err)
	}
	// Un-claim, so the machine looks pre-per-store again. Nothing wrote a claim here (this sandbox
	// never had legacy state), so a missing file is the normal case.
	if err := os.Remove(adoptedByPath()); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	// A command that reads any state path triggers adoption.
	if got := runArca(t, "", "get", "A"); got != "v" {
		t.Fatalf("get after adoption = %q, want v", got)
	}

	a2, err := audit.Open(auditPath())
	if err != nil {
		t.Fatal(err)
	}
	defer a2.Close()
	res2, err := a2.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !res2.OK {
		t.Fatalf("the audit chain no longer verifies after adoption: %s", res2.Reason)
	}
	if res2.Checked < before {
		t.Fatalf("adoption lost audit events: %d before, %d after", before, res2.Checked)
	}
	// The grant survived too — it is the state a lost dir would silently empty.
	g, err := loadGrants()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := g["A"]; !ok {
		t.Errorf("the grant on A did not survive adoption: %v", g)
	}
}

// TestAdoptDegradesWhenTheStateDirIsUnwritable: adoption is bookkeeping, so a state dir it cannot
// build must not take the operator's command down with it. The legacy files stay on disk (nothing
// is destroyed) and the command still runs.
//
// It also pins the error classification, which is the part that was wrong first time round: an
// unwritable state dir makes the lock's O_EXCL create fail with EACCES, not EEXIST. Treating every
// lock failure as "someone else is adopting" turned this case into a silent two-second stall with
// no diagnostic at all — the bounded runtime below is what catches that regression.
func TestAdoptDegradesWhenTheStateDirIsUnwritable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: mode bits do not deny access")
	}
	if runtime.GOOS == "windows" {
		// os.Chmod on Windows only toggles FILE_ATTRIBUTE_READONLY, which does not deny file
		// creation inside a directory — so the state dir stays writable, adoption succeeds, and
		// the "unwritable state dir" precondition simply cannot be built here. (W4a.)
		t.Skip("Windows os.Chmod cannot make a directory reject file creation; the precondition can't be built")
	}
	sandbox(t)
	plantLegacyState(t)

	if err := os.Chmod(xdg.StateDir(), 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(xdg.StateDir(), 0o700) })

	started := time.Now()
	out := captureStderr(t, func() { _ = storeStateDir() })
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Errorf("a failed adoption waited %v; it must not be mistaken for another process's progress", elapsed)
	}
	if !strings.Contains(out, "could not adopt") {
		t.Errorf("a failed adoption should warn, got %q", out)
	}
	if err := os.Chmod(xdg.StateDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(xdg.StateDir(), "grants.json")); err != nil {
		t.Errorf("a failed adoption destroyed the legacy grants.json: %v", err)
	}
	if adoptedBy() != "" {
		t.Error("a failed adoption claimed the shared state anyway")
	}
}
