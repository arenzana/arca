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

// TestAnchorTokenAndCheck covers the anchor primitives in-package: format/parse round
// trip, malformed tokens, and CheckAnchor's three verdicts (extends, diverged, truncated).
func TestAnchorTokenAndCheck(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.db")
	l, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i := 0; i < 3; i++ {
		if err := l.RecordGen("set", "A", "", Identity{}, i+1); err != nil {
			t.Fatal(err)
		}
	}
	r, err := l.Verify()
	if err != nil || !r.OK || r.LastHash == nil {
		t.Fatalf("verify = %+v err %v", r, err)
	}
	tok := FormatAnchor(r.Checked, r.LastHash)
	n, h, err := ParseAnchor(tok)
	if err != nil || n != r.Checked || len(h) != len(r.LastHash) {
		t.Fatalf("round trip: n=%d err=%v", n, err)
	}
	for _, bad := range []string{"", "arca-anchor:v1:x:ff", "arca-anchor:v1:3:zz", "arca-anchor:v2:3:" + "00", "arca-anchor:v1:0:" + "00"} {
		if _, _, err := ParseAnchor(bad); err == nil {
			t.Fatalf("ParseAnchor(%q) should fail", bad)
		}
	}
	// Extends after growth.
	if err := l.RecordGen("set", "A", "", Identity{}, 4); err != nil {
		t.Fatal(err)
	}
	if err := l.CheckAnchor(n, h); err != nil {
		t.Fatalf("grown log should extend the anchor: %v", err)
	}
	// Truncated: an anchor minted beyond the log's length.
	if err := l.CheckAnchor(99, h); err == nil {
		t.Fatal("CheckAnchor(99) should report truncation")
	}
	// Diverged: right position, wrong hash.
	wrong := make([]byte, len(h))
	if err := l.CheckAnchor(n, wrong); err == nil {
		t.Fatal("CheckAnchor with a wrong hash should report divergence")
	}
}

// TestEscrowRowHelpers covers EventsSince and ChainInfoThrough — the escrow segment's
// raw material.
func TestEscrowRowHelpers(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.db")
	l, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i := 0; i < 4; i++ {
		if err := l.RecordGen("read", "S", "curl", Identity{Actor: "me"}, i+1); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := l.EventsSince(0)
	if err != nil || len(rows) != 4 || rows[0].ID >= rows[3].ID {
		t.Fatalf("EventsSince(0) = %d rows err %v", len(rows), err)
	}
	tail, err := l.EventsSince(rows[2].ID)
	if err != nil || len(tail) != 1 || tail[0].ID != rows[3].ID {
		t.Fatalf("EventsSince(mid) = %+v err %v", tail, err)
	}
	n, h, err := l.ChainInfoThrough(rows[1].ID)
	if err != nil || n != 2 || string(h) != string(rows[1].Hash) {
		t.Fatalf("ChainInfoThrough = n%d err %v", n, err)
	}
}
