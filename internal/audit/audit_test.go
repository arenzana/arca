package audit

import (
	"os"
	"path/filepath"
	"testing"
)

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
