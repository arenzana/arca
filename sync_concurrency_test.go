// Tests for the sync concurrency split (R1 / design D1): phase A does the network work
// unlocked and writes nothing, phase B commits under the lock with a compare-and-swap
// against the phase-A snapshot.
//
// The two invariants are tested, not asserted in prose:
//
//	I1  no remote.Backend method runs while the store lock is held
//	    → TestSyncNeverCallsBackendUnderLock
//	I2  every store.json / sync-state.json / store.gen write happens under the lock
//	    → covered indirectly: the CAS tests below fail if a commit lands outside it
package main

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arenzana/arca/internal/remote"
	"github.com/arenzana/arca/internal/store"
	"github.com/arenzana/arca/internal/xdg"
)

// hookBackend runs a hook immediately before a backend call. Because phase A's backend calls
// are the only thing that happens between the snapshot and the commit, a hook here lands a
// simulated concurrent command in exactly the window R1 describes — deterministically, with no
// goroutines or sleeps.
type hookBackend struct {
	remote.Backend
	beforeFetch func()
	beforePush  func()
}

func (h *hookBackend) Fetch(ctx context.Context) ([]byte, remote.Rev, error) {
	if h.beforeFetch != nil {
		h.beforeFetch()
	}
	return h.Backend.Fetch(ctx)
}

func (h *hookBackend) Push(ctx context.Context, env []byte, gen int, prev remote.Rev, auth remote.StoreAuth) (remote.Rev, error) {
	if h.beforePush != nil {
		h.beforePush()
	}
	return h.Backend.Push(ctx, env, gen, prev, auth)
}

// countingBackend records how many backend methods were called. It is how a test proves the
// pre-flight lock probe runs BEFORE the network, rather than merely before the commit.
type countingBackend struct {
	remote.Backend
	calls int
}

func (c *countingBackend) Head(ctx context.Context) (remote.Rev, error) {
	c.calls++
	return c.Backend.Head(ctx)
}

func (c *countingBackend) Fetch(ctx context.Context) ([]byte, remote.Rev, error) {
	c.calls++
	return c.Backend.Fetch(ctx)
}

func (c *countingBackend) Push(ctx context.Context, env []byte, gen int, prev remote.Rev, auth remote.StoreAuth) (remote.Rev, error) {
	c.calls++
	return c.Backend.Push(ctx, env, gen, prev, auth)
}

// lockAssertingBackend fails the test if the store lock is held when any backend method runs.
// This is invariant I1 as an executable check: a network round trip must never sit in front of
// the emergency `rotate` / `recipients rm` an operator runs during an incident.
type lockAssertingBackend struct {
	remote.Backend
	t *testing.T
}

func (l *lockAssertingBackend) check(op string) {
	l.t.Helper()
	if _, err := os.Stat(xdg.StorePath() + ".lock"); err == nil {
		l.t.Errorf("I1 violated: remote.Backend.%s was called while the store lock was held", op)
	}
}

func (l *lockAssertingBackend) Head(ctx context.Context) (remote.Rev, error) {
	l.check("Head")
	return l.Backend.Head(ctx)
}

func (l *lockAssertingBackend) Fetch(ctx context.Context) ([]byte, remote.Rev, error) {
	l.check("Fetch")
	return l.Backend.Fetch(ctx)
}

func (l *lockAssertingBackend) Push(ctx context.Context, env []byte, gen int, prev remote.Rev, auth remote.StoreAuth) (remote.Rev, error) {
	l.check("Push")
	return l.Backend.Push(ctx, env, gen, prev, auth)
}

func (l *lockAssertingBackend) PutIfAbsent(ctx context.Context, key string, data []byte) error {
	l.check("PutIfAbsent")
	return l.Backend.PutIfAbsent(ctx, key, data)
}

func (l *lockAssertingBackend) Get(ctx context.Context, key string) ([]byte, error) {
	l.check("Get")
	return l.Backend.Get(ctx, key)
}

func (l *lockAssertingBackend) List(ctx context.Context, keyPrefix string) ([]string, error) {
	l.check("List")
	return l.Backend.List(ctx, keyPrefix)
}

// withWrappedBackend is withFakeBackend with a decorator around the fake.
func withWrappedBackend(t *testing.T, wrap func(remote.Backend) remote.Backend) *remote.Fake {
	t.Helper()
	f := remote.NewFake()
	wrapped := wrap(f)
	old := openBackend
	t.Cleanup(func() { openBackend = old })
	openBackend = func() (remote.Backend, error) { return wrapped, nil }
	return f
}

// mustBackend hands a test the same backend the CLI would open, wrappers included, so a test can
// drive runSyncCtx directly without reaching around the decorator it just installed.
func mustBackend(t *testing.T) remote.Backend {
	t.Helper()
	b, err := openBackend()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// machineEnv captures the env that identifies "this machine" so a test can switch away with
// switchMachine and come back.
type machineEnv struct{ store, audit, state string }

func thisMachine() machineEnv {
	return machineEnv{
		store: os.Getenv("ARCA_STORE"),
		audit: os.Getenv("ARCA_AUDIT"),
		state: os.Getenv("XDG_STATE_HOME"),
	}
}

func (m machineEnv) restore(t *testing.T) {
	t.Helper()
	t.Setenv("ARCA_STORE", m.store)
	t.Setenv("ARCA_AUDIT", m.audit)
	t.Setenv("XDG_STATE_HOME", m.state)
}

// TestSyncNeverCallsBackendUnderLock is invariant I1 across every code path that talks to the
// backend: bootstrap push, bootstrap pull, fast-forward pull, ordinary push, and the audit
// escrow that rides along with each of them.
func TestSyncNeverCallsBackendUnderLock(t *testing.T) {
	dir := sandbox(t)
	withWrappedBackend(t, func(b remote.Backend) remote.Backend {
		return &lockAssertingBackend{Backend: b, t: t}
	})

	runArca(t, "", "init")
	runArca(t, "hunter2", "set", "API")
	a := thisMachine()

	runArca(t, "", "sync") // bootstrap push

	switchMachine(t, dir)
	runArca(t, "", "sync")            // bootstrap pull
	runArca(t, "v2", "rotate", "API") // mutate
	runArca(t, "", "sync")            // ordinary push

	a.restore(t)
	runArca(t, "", "sync") // fast-forward pull
	if out := runArca(t, "", "get", "API"); out != "v2" {
		t.Fatalf("after fast-forward pull: get API = %q, want v2", out)
	}
}

// TestSyncCASRefusesToResurrectRemovedSecret is R1 itself, in the form that makes it a security
// bug rather than a lost-update curiosity.
//
// An operator removes a compromised secret during an incident. That `rm` lands while a sync is
// already on the network, holding a decision ("fast-forward pull") computed from a snapshot in
// which the secret still existed. Committing that decision writes the remote payload over the
// removal and the secret is back — remediation silently reverted, with the store looking
// perfectly healthy afterwards.
//
// The phase-B compare-and-swap turns that into a reported conflict.
func TestSyncCASRefusesToResurrectRemovedSecret(t *testing.T) {
	dir := sandbox(t)
	armed := false
	withWrappedBackend(t, func(b remote.Backend) remote.Backend {
		return &hookBackend{Backend: b, beforeFetch: func() {
			if !armed {
				return
			}
			armed = false // fire exactly once, on the pull under test
			// The concurrent `arca rm API`, landing between the snapshot and the commit.
			s, err := store.Load(xdg.StorePath())
			if err != nil {
				t.Fatal(err)
			}
			delete(s.Secrets, "API")
			if err := s.Save(); err != nil {
				t.Fatal(err)
			}
		}}
	})

	runArca(t, "", "init")
	runArca(t, "hunter2", "set", "API")
	a := thisMachine()
	runArca(t, "", "sync") // remote at generation G

	// A second machine advances the remote, so machine A has a fast-forward pull to do.
	switchMachine(t, dir)
	runArca(t, "", "sync")
	runArca(t, "v2", "rotate", "API")
	runArca(t, "", "sync") // remote at G+1

	a.restore(t)
	armed = true
	err := runArcaErr("", "sync")
	if err == nil || !strings.Contains(err.Error(), "CONFLICT") {
		t.Fatalf("sync racing a local write = %v, want a reported CONFLICT", err)
	}

	// The load-bearing assertion: the removal survived. Before the fix the pull committed a
	// decision made before the `rm` existed and API came back.
	s, err := store.Load(xdg.StorePath())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Secrets["API"]; ok {
		t.Fatal("sync resurrected a concurrently removed secret — the R1 lost update")
	}
}

// TestSyncCASRetryExhaustion covers the bounded-retry contract. A cursor that keeps moving
// under the sync must produce a clear "run it again" rather than an infinite loop or a
// committed stale decision.
//
// The hook rewrites only sync-state.json's timestamp: that trips the CAS on every attempt
// while leaving the L/S/R verdict a pull, so each restart genuinely re-runs phase A.
func TestSyncCASRetryExhaustion(t *testing.T) {
	dir := sandbox(t)
	armed, fetches := false, 0
	withWrappedBackend(t, func(b remote.Backend) remote.Backend {
		return &hookBackend{Backend: b, beforeFetch: func() {
			if !armed {
				return
			}
			fetches++
			st := loadSyncState()
			// A distinct, deterministic timestamp per attempt — a concurrent auto-sync
			// touching the cursor while this sync is on the network.
			st.LastSync = time.Unix(int64(1700000000+fetches), 0)
			if err := saveSyncState(st); err != nil {
				t.Fatal(err)
			}
		}}
	})

	runArca(t, "", "init")
	runArca(t, "hunter2", "set", "API")
	a := thisMachine()
	runArca(t, "", "sync")

	switchMachine(t, dir)
	runArca(t, "", "sync")
	runArca(t, "v2", "rotate", "API")
	runArca(t, "", "sync")

	a.restore(t)
	before, err := os.ReadFile(xdg.StorePath())
	if err != nil {
		t.Fatal(err)
	}
	armed = true
	err = runArcaErr("", "sync")
	if err == nil || !strings.Contains(err.Error(), "changed underneath this sync") {
		t.Fatalf("sync under sustained contention = %v, want the retry-exhaustion error", err)
	}
	if fetches != syncAttempts {
		t.Fatalf("phase A ran %d times, want %d (one per attempt)", fetches, syncAttempts)
	}
	after, err := os.ReadFile(xdg.StorePath())
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("a sync that exhausted its retries still wrote the store")
	}
}

// TestAutoSyncSkipsWhenStoreLocked pins the non-blocking commit for opportunistic sync.
// `arca edit` holds the store lock for as long as an operator keeps $EDITOR open; a
// best-effort background sync must skip rather than stall the next command behind that, and it
// must not warn about a condition that is neither an error nor actionable.
func TestAutoSyncSkipsWhenStoreLocked(t *testing.T) {
	dir := sandbox(t)
	withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "hunter2", "set", "API")
	a := thisMachine()
	runArca(t, "", "sync")

	// Give this machine a pull to do, so auto-sync reaches the commit rather than
	// short-circuiting on "nothing to do".
	switchMachine(t, dir)
	runArca(t, "", "sync")
	runArca(t, "v2", "rotate", "API")
	runArca(t, "", "sync")
	a.restore(t)

	// Auto-sync only runs when enabled and due.
	t.Setenv("ARCA_SYNC_AUTO", "1")
	st := loadSyncState()
	st.LastSync = time.Now().Add(-2 * autoSyncStaleness)
	if err := saveSyncState(st); err != nil {
		t.Fatal(err)
	}

	before, err := os.ReadFile(xdg.StorePath())
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := lockStore()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	start := time.Now()
	out := captureStderr(t, func() { maybeAutoSync(false) })
	elapsed := time.Since(start)

	if elapsed > lockTimeout/2 {
		t.Fatalf("auto-sync waited %v for the lock; it must not block (lockTimeout %v)", elapsed, lockTimeout)
	}
	if strings.Contains(out, "auto-sync") {
		t.Fatalf("auto-sync warned about ordinary lock contention: %q", out)
	}
	after, err := os.ReadFile(xdg.StorePath())
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("auto-sync committed while another process held the store lock")
	}
}

// TestReadLocalSnapshotDoesNotWrite is invariant I2 for the phase-A read: the snapshot runs
// outside the lock, so it must not touch store.gen the way openStore does. A snapshot of a
// store that looks rolled back still warns — it just must not persist anything.
func TestReadLocalSnapshotDoesNotWrite(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "hunter2", "set", "API")

	// Push the high-water mark above the store's generation, so the snapshot sees a regression.
	s, err := store.Load(xdg.StorePath())
	if err != nil {
		t.Fatal(err)
	}
	hwm := s.Generation + 5
	if err := os.WriteFile(storeGenPath(), []byte(strconv.Itoa(hwm)), 0o600); err != nil {
		t.Fatal(err)
	}
	genBefore, err := os.ReadFile(storeGenPath())
	if err != nil {
		t.Fatal(err)
	}
	storeBefore, err := os.ReadFile(xdg.StorePath())
	if err != nil {
		t.Fatal(err)
	}

	out := captureStderr(t, func() {
		if _, err := readLocalSnapshot(); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "rolled back") {
		t.Fatalf("snapshot of a regressed store should still warn, got %q", out)
	}

	genAfter, err := os.ReadFile(storeGenPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(genBefore) != string(genAfter) {
		t.Fatalf("phase-A snapshot wrote store.gen (%q -> %q); it runs outside the lock", genBefore, genAfter)
	}
	storeAfter, err := os.ReadFile(xdg.StorePath())
	if err != nil {
		t.Fatal(err)
	}
	if string(storeBefore) != string(storeAfter) {
		t.Fatal("phase-A snapshot wrote the store")
	}
}

// TestReadLocalSnapshotSingleRead pins the fix for the latent double read: localStoreForSync
// used to ReadFile the store and then call openStore(), which read it a second time — so the
// bytes sealed into a pushed envelope and the generation they were labelled with could come
// from two different writes. The snapshot's raw bytes must decode to exactly the store it
// returned.
func TestReadLocalSnapshotSingleRead(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "hunter2", "set", "API")

	snap, err := readLocalSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := store.Decode(xdg.StorePath(), snap.raw)
	if err != nil {
		t.Fatalf("snapshot raw bytes did not decode: %v", err)
	}
	if decoded.Generation != snap.s.Generation {
		t.Fatalf("raw bytes are generation %d but the parsed store is %d — two reads",
			decoded.Generation, snap.s.Generation)
	}
	if len(decoded.Secrets) != len(snap.s.Secrets) {
		t.Fatalf("raw bytes hold %d secrets, parsed store %d", len(decoded.Secrets), len(snap.s.Secrets))
	}
}

// TestSyncMissingStoreSnapshot: a fresh machine has no store, and that is not an error — the
// snapshot reports a nil store so a pull can bootstrap it.
func TestSyncMissingStoreSnapshot(t *testing.T) {
	sandbox(t)
	snap, err := readLocalSnapshot()
	if err != nil {
		t.Fatalf("snapshot with no store = %v, want no error", err)
	}
	if snap.s != nil || snap.raw != nil {
		t.Fatalf("snapshot with no store = (%v, %v), want nils", snap.s, snap.raw)
	}
	if err := casLocalUnchanged(snap); err != nil {
		t.Fatalf("CAS against an unchanged missing store = %v, want nil", err)
	}
}

// TestUnrecordedPushCursorLooksLikeAConflict is the reason a push's cursor write is the one
// commit that always waits for the lock instead of skipping.
//
// It reproduces the state a skipped cursor write would leave: the remote holds generation R, the
// local store is at L == R, and the cursor still says S < R. That is L > S && R > S, which the
// rule table reads as "both sides advanced" — so the operator gets a CONFLICT for a store that
// is byte-identical to the remote it supposedly diverged from.
//
// This is why abandoning is safe before a push and unsafe after it, and it is asserted rather
// than argued: if someone later "simplifies" pushStore to use opts.abandonable(), the test above
// keeps passing and this one explains the bill.
func TestUnrecordedPushCursorLooksLikeAConflict(t *testing.T) {
	sandbox(t)
	withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "hunter2", "set", "API")

	before := loadSyncState()
	runArca(t, "", "sync") // pushes; records the cursor
	after := loadSyncState()
	if after.LastGeneration <= before.LastGeneration {
		t.Fatalf("push did not advance the cursor: %d -> %d", before.LastGeneration, after.LastGeneration)
	}

	// Rewind only the cursor — exactly what a skipped cursor write leaves behind.
	unrecorded := after
	unrecorded.LastGeneration = before.LastGeneration
	if err := saveSyncState(unrecorded); err != nil {
		t.Fatal(err)
	}
	err := runArcaErr("", "sync")
	if err == nil || !strings.Contains(err.Error(), "CONFLICT") {
		t.Fatalf("sync with an unrecorded push cursor = %v, want the spurious CONFLICT this proves", err)
	}
}

// TestPushWaitsForTheLockToRecordItsCursor is the fix for the above, through the full path.
//
// The lock is free when the sync starts (so the pre-flight probe passes) and is taken by a
// concurrent process during the network window — the one race the probe cannot close. An
// opportunistic sync, which skips on contention everywhere else, must still WAIT here, because
// its push has already landed on the remote.
func TestPushWaitsForTheLockToRecordItsCursor(t *testing.T) {
	sandbox(t)
	var raced bool
	withWrappedBackend(t, func(b remote.Backend) remote.Backend {
		return &hookBackend{Backend: b, beforePush: func() {
			if raced {
				return // only the sync under test
			}
			raced = true
			unlock, err := lockStore()
			if err != nil {
				t.Fatal(err)
			}
			// A concurrent holder that finishes shortly after the push lands.
			go func() {
				time.Sleep(200 * time.Millisecond)
				unlock()
			}()
		}}
	})
	runArca(t, "", "init")
	runArca(t, "hunter2", "set", "API")

	before := loadSyncState()
	if err := runSyncCtx(context.Background(), mustBackend(t), syncOpts{quiet: true, skipIfLocked: true}); err != nil {
		t.Fatalf("opportunistic push racing a lock holder = %v; it must wait, not skip", err)
	}
	after := loadSyncState()
	if after.LastGeneration <= before.LastGeneration {
		t.Fatalf("the push landed but its cursor was not recorded (%d -> %d); the next sync would report a spurious conflict",
			before.LastGeneration, after.LastGeneration)
	}
}

// TestPushCursorLockTimeoutNamesTheRepair covers the residual case: the wait above genuinely
// expires. The push is on the remote and cannot be undone, so the only honest outcome is an error
// that names both the state and the repair — not a silent skip that surfaces as a conflict later.
func TestPushCursorLockTimeoutNamesTheRepair(t *testing.T) {
	sandbox(t)
	// lockTimeout is a package var precisely so a test can make the expiry cheap.
	orig := lockTimeout
	lockTimeout = 150 * time.Millisecond
	t.Cleanup(func() { lockTimeout = orig })

	var once bool
	withWrappedBackend(t, func(b remote.Backend) remote.Backend {
		return &hookBackend{Backend: b, beforePush: func() {
			if once {
				return
			}
			once = true
			unlock, err := lockStore() // never released within the shortened budget
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(unlock)
		}}
	})
	runArca(t, "", "init")
	runArca(t, "hunter2", "set", "API")

	err := runSyncCtx(context.Background(), mustBackend(t), syncOpts{quiet: true, skipIfLocked: true})
	if err == nil {
		t.Fatal("a push whose cursor could not be recorded reported success")
	}
	for _, want := range []string{"could not record it locally", "arca sync --pull"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

// TestAutoSyncProbeSkipsBeforeAnyBackendCall pins the pre-flight probe. Opportunistic sync
// against a store another process is mid-write on must cost nothing at all — not a skipped
// commit after a completed round trip, but no backend call in the first place. That is what
// keeps the push path's "already landed" problem from arising in the common contended case.
func TestAutoSyncProbeSkipsBeforeAnyBackendCall(t *testing.T) {
	dir := sandbox(t)
	var counter *countingBackend
	withWrappedBackend(t, func(b remote.Backend) remote.Backend {
		counter = &countingBackend{Backend: b}
		return counter
	})
	runArca(t, "", "init")
	runArca(t, "hunter2", "set", "API")
	a := thisMachine()
	runArca(t, "", "sync")

	// Give this machine real work to do, so a skip is a decision rather than a no-op.
	switchMachine(t, dir)
	runArca(t, "", "sync")
	runArca(t, "v2", "rotate", "API")
	runArca(t, "", "sync")
	a.restore(t)

	t.Setenv("ARCA_SYNC_AUTO", "1")
	st := loadSyncState()
	st.LastSync = time.Now().Add(-2 * autoSyncStaleness)
	if err := saveSyncState(st); err != nil {
		t.Fatal(err)
	}

	unlock, err := lockStore()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	counter.calls = 0
	out := captureStderr(t, func() { maybeAutoSync(false) })
	if counter.calls != 0 {
		t.Fatalf("auto-sync made %d backend calls against a locked store; the probe must run first", counter.calls)
	}
	if strings.Contains(out, "auto-sync") {
		t.Fatalf("auto-sync warned about ordinary lock contention: %q", out)
	}
}

// TestCASStoreAppearedUnderUs: phase A saw no local store (a fresh machine bootstrapping with a
// pull), but by commit time a concurrent `arca init` created one. Writing the pulled store over
// it would discard that init, so the CAS restarts.
func TestCASStoreAppearedUnderUs(t *testing.T) {
	sandbox(t)
	snap, err := readLocalSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snap.s != nil {
		t.Fatal("expected an empty sandbox to snapshot as no store")
	}
	runArca(t, "", "init") // the concurrent init
	if err := casLocalUnchanged(snap); !errors.Is(err, errSyncRestart) {
		t.Fatalf("CAS after a store appeared = %v, want errSyncRestart", err)
	}
}

// TestSnapshotRefusesCorruptStore: phase A parses the bytes it is about to seal into an
// envelope, so a corrupt store.json fails the sync instead of being pushed as-is.
func TestSnapshotRefusesCorruptStore(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	if err := os.WriteFile(xdg.StorePath(), []byte(`{"version":1,`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readLocalSnapshot(); err == nil || !strings.Contains(err.Error(), "parse store") {
		t.Fatalf("snapshot of a corrupt store = %v, want a parse error", err)
	}
}

// TestCASDetectsChange is the compare-and-swap in isolation: every way the local state can move
// under a sync must be caught.
func TestCASDetectsChange(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "hunter2", "set", "API")

	tests := []struct {
		name   string
		mutate func(t *testing.T)
		want   error
	}{
		{
			name:   "unchanged",
			mutate: func(*testing.T) {},
			want:   nil,
		},
		{
			name: "store rewritten",
			mutate: func(t *testing.T) {
				s, err := store.Load(xdg.StorePath())
				if err != nil {
					t.Fatal(err)
				}
				if err := s.Save(); err != nil { // Save bumps the generation
					t.Fatal(err)
				}
			},
			want: errSyncRestart,
		},
		{
			name: "store removed",
			mutate: func(t *testing.T) {
				if err := os.Remove(xdg.StorePath()); err != nil {
					t.Fatal(err)
				}
			},
			want: errSyncRestart,
		},
		{
			name: "cursor moved",
			mutate: func(t *testing.T) {
				st := loadSyncState()
				st.LastGeneration += 1
				if err := saveSyncState(st); err != nil {
					t.Fatal(err)
				}
			},
			want: errSyncRestart,
		},
		{
			name: "cursor timestamp moved",
			mutate: func(t *testing.T) {
				st := loadSyncState()
				st.LastSync = time.Unix(1700000000, 0)
				if err := saveSyncState(st); err != nil {
					t.Fatal(err)
				}
			},
			want: errSyncRestart,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Each case gets its own store+cursor so mutations don't leak between subtests.
			sandbox(t)
			runArca(t, "", "init")
			runArca(t, "hunter2", "set", "API")
			if err := saveSyncState(syncState{LastGeneration: 1, LastTag: "t", LastSync: time.Now()}); err != nil {
				t.Fatal(err)
			}
			snap, err := readLocalSnapshot()
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(t)
			if got := casLocalUnchanged(snap); !errors.Is(got, tc.want) {
				t.Fatalf("casLocalUnchanged = %v, want %v", got, tc.want)
			}
		})
	}
}
