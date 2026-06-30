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
