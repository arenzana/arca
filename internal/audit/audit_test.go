package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestRecordVerifyWeirdInputs checks the canonical serialization + chain handle awkward field
// values — unicode, NUL bytes, embedded separators, very long strings, empty — without corrupting
// the chain.
func TestRecordVerifyWeirdInputs(t *testing.T) {
	l, _ := openChained(t)
	cases := []Identity{
		{Actor: "a", Agent: "claude-code", Version: "1.0", Session: "s"},
		{Actor: "act\x00or", Agent: "«weird»", Session: "s\t2"},
		{Actor: "emoji🔐", Version: "9.9.9"},
		{},
	}
	names := []string{"SEC", "na\x00me", "emoji🔐", "x"}
	ops := []string{"read", "", "«op»", "read"}
	for i, id := range cases {
		if err := l.Record(ops[i], names[i], "cal ler", id); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	r, err := l.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK || r.Checked != len(cases) {
		t.Fatalf("weird-input chain should verify: %+v", r)
	}
}

// TestConcurrentRecordVerifies checks the hash chain survives concurrent writers: the single
// connection + BEGIN IMMEDIATE must serialize appends so no two events fork the chain.
func TestConcurrentRecordVerifies(t *testing.T) {
	l, _ := openChained(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	l.UseSigner(&Signer{SessionID: "s1", Priv: priv, Pub: pub})

	const workers, per = 8, 20
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				if err := l.Record("read", "SEC", "", Identity{Session: "s1"}); err != nil {
					t.Errorf("concurrent record: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	r, err := l.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK || r.Checked != workers*per {
		t.Fatalf("after %d concurrent records: verify = %+v", workers*per, r)
	}
}

// TestChainPropertyRandomTamper is a property test: for many random op sequences the fresh chain
// verifies, and mutating any single row is always detected.
func TestChainPropertyRandomTamper(t *testing.T) {
	ops := []string{"read", "set", "exec", "canary", "ratelimit", "rotate", "env", "inject"}
	for seed := 0; seed < 25; seed++ {
		l, p := openChained(t)
		n := 3 + seed%9
		for i := 0; i < n; i++ {
			op := ops[(i*7+seed*3)%len(ops)]
			if err := l.Record(op, "S", "", Identity{Session: "x"}); err != nil {
				t.Fatalf("seed %d: record: %v", seed, err)
			}
		}
		if r, _ := l.Verify(); !r.OK || r.Checked != n {
			t.Fatalf("seed %d: fresh chain should verify, got %+v", seed, r)
		}
		id := 1 + seed%n // mutate a row in range
		tamper(t, p, "UPDATE events SET name='HACKED' WHERE id=?", id)
		if r, _ := l.Verify(); r.OK {
			t.Fatalf("seed %d: tampering row %d was not detected", seed, id)
		}
	}
}

func TestCountUsesSince(t *testing.T) {
	l, _ := openChained(t)
	for _, op := range []string{"read", "exec", "set", "inject"} { // set is not a "use"
		if err := l.Record(op, "X", "", Identity{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Record("read", "Y", "", Identity{}); err != nil { // different secret
		t.Fatal(err)
	}
	n, err := l.CountUsesSince("X", time.Now().Add(-time.Hour))
	if err != nil || n != 3 { // read + exec + inject, not set
		t.Fatalf("CountUsesSince = %d, %v; want 3", n, err)
	}
	if n, _ := l.CountUsesSince("X", time.Now().Add(time.Hour)); n != 0 { // window in the future
		t.Fatalf("future-window count = %d, want 0", n)
	}
}

// TestRecordAndQuery exercises the audit DB end to end: record a few events (including agent
// identity) and confirm the aggregates (LastRead count) and ordering (Recent, newest-first)
// come back correctly — including the attributed agent/session.
func TestRecordAndQuery(t *testing.T) {
	l, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	if err := l.Record("set", "FOO", "", Identity{Actor: "tester"}); err != nil {
		t.Fatal(err)
	}
	// Two reads attributed to the same agent/session, to check counting and attribution.
	id := Identity{Actor: "claude", Agent: "claude-code", Version: "2.1.181", Session: "sess1"}
	if err := l.Record("read", "FOO", "curl", id); err != nil {
		t.Fatal(err)
	}
	if err := l.Record("read", "FOO", "curl", id); err != nil {
		t.Fatal(err)
	}

	// LastRead counts only "use" ops (the set above must not be counted).
	lr, cnt, err := l.LastRead("FOO")
	if err != nil {
		t.Fatal(err)
	}
	if cnt != 2 {
		t.Fatalf("read count = %d, want 2", cnt)
	}
	if lr.IsZero() {
		t.Fatal("last read is zero")
	}

	evs, err := l.Recent("FOO", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 3 { // all three events (set + 2 reads) are returned by Recent
		t.Fatalf("events = %d, want 3", len(evs))
	}
	// Newest first, with identity fields preserved through the round-trip.
	if evs[0].Op != "read" || evs[0].Actor != "claude" || evs[0].Agent != "claude-code" ||
		evs[0].Session != "sess1" || evs[0].Caller != "curl" {
		t.Fatalf("latest event = %+v", evs[0])
	}
}

// TestLastReadNever confirms a never-accessed secret reports zero time / zero count rather
// than an error, so `show`/`ls --reads` can render "never".
func TestLastReadNever(t *testing.T) {
	l, err := Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	lr, cnt, err := l.LastRead("NOPE")
	if err != nil {
		t.Fatal(err)
	}
	if !lr.IsZero() || cnt != 0 {
		t.Fatalf("expected zero/0 for an unseen secret, got %v/%d", lr, cnt)
	}
}

// TestOpenBadPath fails to open when the parent of the db path is a regular file, exercising
// the directory-creation error branch.
func TestOpenBadPath(t *testing.T) {
	f := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(f, "audit.db")); err == nil {
		t.Fatal("expected Open to fail when the parent path is a file")
	}
}

// TestOpenCorruptDB covers the schema-setup error path: opening a non-SQLite file fails on the
// first PRAGMA/statement.
func TestOpenCorruptDB(t *testing.T) {
	p := filepath.Join(t.TempDir(), "corrupt.db")
	if err := os.WriteFile(p, []byte("this is not a sqlite database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p); err == nil {
		t.Fatal("expected Open to fail on a corrupt database")
	}
}

func openChained(t *testing.T) (*Log, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "audit.db")
	l, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, p
}

func recordN(t *testing.T, l *Log, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := l.Record("read", "SEC", "", Identity{Agent: "claude-code", Session: "s1"}); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
}

// tamper opens a second handle to the same file and runs raw SQL, simulating an attacker editing
// the DB out from under arca.
func tamper(t *testing.T, path, q string, args ...any) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("tamper %q: %v", q, err)
	}
}

func TestLastOp(t *testing.T) {
	l, _ := openChained(t)
	if _, n, err := l.LastOp("X", "canary"); err != nil || n != 0 {
		t.Fatalf("never-tripped LastOp = %d,%v, want 0,nil", n, err)
	}
	if err := l.Record("canary", "X", "", Identity{}); err != nil {
		t.Fatal(err)
	}
	if err := l.Record("canary", "X", "", Identity{}); err != nil {
		t.Fatal(err)
	}
	if err := l.Record("read", "X", "", Identity{}); err != nil { // different op, must not count
		t.Fatal(err)
	}
	ts, n, err := l.LastOp("X", "canary")
	if err != nil || n != 2 || ts.IsZero() {
		t.Fatalf("LastOp = %v,%d,%v, want a time + 2", ts, n, err)
	}
}

func TestVerifyEmpty(t *testing.T) {
	l, _ := openChained(t)
	r, err := l.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK || r.Checked != 0 || r.Legacy != 0 {
		t.Fatalf("empty log verify = %+v, want OK with nothing checked", r)
	}
}

// The *AfterClose tests exercise the DB-error branches by operating on a closed handle.
func TestRecordAfterClose(t *testing.T) {
	l, _ := openChained(t)
	l.Close()
	if err := l.Record("read", "X", "", Identity{}); err == nil {
		t.Fatal("Record on a closed log should error")
	}
}

func TestVerifyAfterClose(t *testing.T) {
	l, _ := openChained(t)
	l.Close()
	if _, err := l.Verify(); err == nil {
		t.Fatal("Verify on a closed log should error")
	}
}

func TestQueriesAfterClose(t *testing.T) {
	l, _ := openChained(t)
	l.Close()
	if _, _, err := l.LastOp("X", "canary"); err == nil {
		t.Fatal("LastOp on a closed log should error")
	}
	if _, _, err := l.LastRead("X"); err == nil {
		t.Fatal("LastRead on a closed log should error")
	}
	if _, err := l.Recent("", 10); err == nil {
		t.Fatal("Recent on a closed log should error")
	}
	if _, err := l.CountUsesSince("X", time.Now()); err == nil {
		t.Fatal("CountUsesSince on a closed log should error")
	}
	if _, err := l.CountOpSince("X", "exec", time.Now()); err == nil {
		t.Fatal("CountOpSince on a closed log should error")
	}
}

func TestVerifyClean(t *testing.T) {
	l, _ := openChained(t)
	recordN(t, l, 5)
	r, err := l.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK || r.Checked != 5 {
		t.Fatalf("verify = %+v, want OK with 5 checked", r)
	}
}

func TestVerifySigned(t *testing.T) {
	l, _ := openChained(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	l.UseSigner(&Signer{SessionID: "s1", Priv: priv, Pub: pub})
	recordN(t, l, 4)
	r, _ := l.Verify()
	if !r.OK || r.Signed != 4 {
		t.Fatalf("verify = %+v, want OK with 4 signed", r)
	}
}

func TestVerifyDetectsEdit(t *testing.T) {
	l, p := openChained(t)
	recordN(t, l, 5)
	tamper(t, p, "UPDATE events SET name='HACKED' WHERE id=3")
	r, _ := l.Verify()
	if r.OK {
		t.Fatal("an edited event was not detected")
	}
	if r.BrokenID != 3 {
		t.Fatalf("brokenID = %d, want 3", r.BrokenID)
	}
}

func TestVerifyDetectsDelete(t *testing.T) {
	l, p := openChained(t)
	recordN(t, l, 5)
	tamper(t, p, "DELETE FROM events WHERE id=3")
	if r, _ := l.Verify(); r.OK {
		t.Fatal("a deleted middle event was not detected")
	}
}

func TestVerifyDetectsSigForgery(t *testing.T) {
	l, p := openChained(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	l.UseSigner(&Signer{SessionID: "s1", Priv: priv, Pub: pub})
	recordN(t, l, 3)
	// Replace a signature; the chain hash is untouched, so only the signature check can catch
	// this — which is exactly the point of signing.
	tamper(t, p, "UPDATE events SET sig=X'00' WHERE id=2")
	r, _ := l.Verify()
	if r.OK || r.BrokenID != 2 {
		t.Fatalf("verify = %+v, want broken at 2", r)
	}
}

func TestVerifyDetectsTruncation(t *testing.T) {
	l, p := openChained(t)
	recordN(t, l, 5)
	// Delete the most recent event but leave the recorded head claiming 5.
	tamper(t, p, "DELETE FROM events WHERE id=5")
	if r, _ := l.Verify(); r.OK {
		t.Fatal("tail truncation was not detected via the head count")
	}
}

// TestMigrateLegacyDB checks that a DB created before chaining gets the new columns, and that its
// pre-chain rows are reported as legacy while new events chain and verify normally.
func TestMigrateLegacyDB(t *testing.T) {
	p := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE events (
		id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, op TEXT NOT NULL, name TEXT NOT NULL,
		ppid INTEGER, caller TEXT, actor TEXT, agent TEXT, version TEXT, session TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO events (ts,op,name) VALUES ('2020-01-01T00:00:00Z','read','OLD')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	l, err := Open(p) // migrates: adds the chain columns
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	recordN(t, l, 2)
	r, _ := l.Verify()
	if !r.OK || r.Legacy != 1 || r.Checked != 2 {
		t.Fatalf("verify = %+v, want OK with 1 legacy + 2 checked", r)
	}
}
