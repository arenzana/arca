package audit

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// TestOpenReadOnlySchemaFails covers Open's schema-creation error branch: a real SQLite file
// that lacks the events table and is read-only, so PRAGMA succeeds but CREATE TABLE fails.
func TestOpenReadOnlySchemaFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	p := filepath.Join(t.TempDir(), "ro.db")
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE dummy(x)"); err != nil { // make it a valid db without 'events'
		t.Fatal(err)
	}
	db.Close()
	if err := os.Chmod(p, 0o400); err != nil { // read-only: CREATE TABLE events will fail
		t.Fatal(err)
	}
	defer os.Chmod(p, 0o600) // allow t.TempDir cleanup
	if _, err := Open(p); err == nil {
		t.Fatal("expected Open to fail creating its schema on a read-only database")
	}
}

// TestRecentAllNames covers Recent's no-name-filter branch (the cross-secret history used by
// `arca log` with no argument).
func TestRecentAllNames(t *testing.T) {
	l, err := Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.Record("set", "A", "", Identity{}); err != nil {
		t.Fatal(err)
	}
	if err := l.Record("read", "B", "", Identity{Agent: "claude-code"}); err != nil {
		t.Fatal(err)
	}
	evs, err := l.Recent("", 10) // no name filter → whole history
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("Recent(\"\") returned %d events, want 2", len(evs))
	}
}

// TestRecordGenVerify covers SEC-14's generation binding: recorded generations surface in
// VerifyResult, a regression is pinpointed, and the value is hash-bound (editing a row's
// store_gen — or NULLing it to switch encodings — breaks verification).
func TestRecordGenVerify(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.db")
	l, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	if err := l.Record("init", "-", "", Identity{}); err != nil { // NULL-gen row (pre-SEC-14 shape)
		t.Fatal(err)
	}
	for _, g := range []int{3, 5} {
		if err := l.RecordGen("set", "A", "", Identity{}, g); err != nil {
			t.Fatal(err)
		}
	}
	r, err := l.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK || r.MaxStoreGen != 5 || r.GenRegressedID != 0 {
		t.Fatalf("verify = %+v, want OK with MaxStoreGen 5 and no regression", r)
	}

	// A later event observing an older generation is flagged as a regression, chain still OK.
	if err := l.RecordGen("set", "A", "", Identity{}, 4); err != nil {
		t.Fatal(err)
	}
	r, err = l.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK || r.GenRegressedID == 0 {
		t.Fatalf("verify = %+v, want OK with a flagged generation regression", r)
	}

	// Tampering with a recorded generation breaks that row's hash.
	if _, err := l.db.Exec("UPDATE events SET store_gen=9 WHERE store_gen=5"); err != nil {
		t.Fatal(err)
	}
	if r, _ := l.Verify(); r.OK {
		t.Fatal("verify passed after a store_gen edit")
	}
	if _, err := l.db.Exec("UPDATE events SET store_gen=5 WHERE store_gen=9"); err != nil {
		t.Fatal(err)
	}
	// NULLing a generation (switching the row back to the v1 encoding) also breaks the hash.
	if _, err := l.db.Exec("UPDATE events SET store_gen=NULL WHERE store_gen=5"); err != nil {
		t.Fatal(err)
	}
	if r, _ := l.Verify(); r.OK {
		t.Fatal("verify passed after NULLing a store_gen (encoding downgrade)")
	}
}
