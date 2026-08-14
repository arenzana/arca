package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arenzana/arca/internal/xdg"
)

// Every writer of local state publishes the same way since S7: a unique temp file in the
// destination's own directory, chmod before any bytes, fsync, rename, fsync the parent directory
// (atomicfile.Write). Before that, each of them open-coded a different subset. Four published
// through a *fixed* "<destination>.tmp", which os.WriteFile only chmods when it creates it — so a
// leftover temp from a crashed run was renamed over the destination mode and all — and two
// concurrent writers shared the one name. saveSyncConfig had been fixed for exactly this under
// SEC-37 and the fix was never carried back up to the function directly above it (R18).
//
// These tests drive each writer through the two shapes a crashed run actually leaves behind.

type stateWriter struct {
	name string
	path func() string
	save func(t *testing.T) error
	// check reads the document back through the writer's own loader, so a save that "succeeds"
	// while publishing something unparseable still fails here.
	check func(t *testing.T)
}

// stateWriters is built inside a test (not as a package var) because every path function resolves
// the active store, which only means anything after sandbox() has set the environment.
func stateWriters() []stateWriter {
	return []stateWriter{
		{
			name: "canary registry",
			path: canariesPath,
			save: func(*testing.T) error { return saveCanaries(map[string]bool{"DECOY": true}) },
			check: func(t *testing.T) {
				t.Helper()
				set, err := loadCanaries()
				if err != nil {
					t.Fatalf("loadCanaries: %v", err)
				}
				if !set["DECOY"] {
					t.Errorf("canary registry = %v, want DECOY present", set)
				}
			},
		},
		{
			name: "escrow cursor",
			path: escrowStatePath,
			save: func(*testing.T) error { return saveEscrowState(escrowState{LastID: 11, Seq: 7}) },
			check: func(t *testing.T) {
				t.Helper()
				if got := loadEscrowState(); got.Seq != 7 || got.LastID != 11 {
					t.Errorf("escrow cursor = %+v, want Seq 7 / LastID 11", got)
				}
			},
		},
		{
			name: "grants",
			path: grantsPath,
			save: func(*testing.T) error {
				return saveGrants(map[string]Grant{"DB": {Secret: "DB", ExpiresAt: time.Now().Add(time.Hour)}})
			},
			check: func(t *testing.T) {
				t.Helper()
				g, err := loadGrants()
				if err != nil {
					t.Fatalf("loadGrants: %v", err)
				}
				if _, ok := g["DB"]; !ok {
					t.Errorf("grants = %v, want DB present", g)
				}
			},
		},
		{
			name: "handles",
			path: handlesPath,
			save: func(*testing.T) error {
				return saveHandles(map[string]Handle{"hdl_x": {ID: "hdl_x", Secret: "DB", EnvName: "DB"}})
			},
			check: func(t *testing.T) {
				t.Helper()
				h, err := loadHandles()
				if err != nil {
					t.Fatalf("loadHandles: %v", err)
				}
				if _, ok := h["hdl_x"]; !ok {
					t.Errorf("handles = %v, want hdl_x present", h)
				}
			},
		},
		{
			name: "store-generation high-water mark",
			path: storeGenPath,
			// recordStoreGeneration is deliberately best-effort and reports no write error, so the
			// only way to tell whether it landed is to read the file — which check does.
			save: func(*testing.T) error {
				recordStoreGeneration(42)
				return nil
			},
			check: func(t *testing.T) {
				t.Helper()
				b, err := os.ReadFile(storeGenPath())
				if err != nil {
					t.Fatalf("read the high-water mark: %v", err)
				}
				if got, _ := strconv.Atoi(strings.TrimSpace(string(b))); got != 42 {
					t.Errorf("high-water mark = %q, want 42", b)
				}
			},
		},
		{
			name: "sync cursor",
			path: syncStatePath,
			save: func(*testing.T) error { return saveSyncState(syncState{LastGeneration: 9, LastTag: "etag-9"}) },
			check: func(t *testing.T) {
				t.Helper()
				if got := loadSyncState(); got.LastGeneration != 9 || got.LastTag != "etag-9" {
					t.Errorf("sync cursor = %+v, want generation 9 / tag etag-9", got)
				}
			},
		},
		{
			// Already on the SEC-37 pattern before S7, so it passes both sides of these two
			// scenarios. It is in the table anyway: it is the writer the others were supposed to
			// match, and a regression here would be the same bug arriving from the other direction.
			name: "sync config",
			path: syncConfigPath,
			save: func(*testing.T) error {
				return saveSyncConfig(syncConfig{URL: "s3://bucket/store", AccessKey: "AK", SecretKey: "SK"})
			},
			check: func(t *testing.T) {
				t.Helper()
				if got := loadSyncConfig(); got.URL != "s3://bucket/store" || got.SecretKey != "SK" {
					t.Errorf("sync config = %+v, want the URL and credentials round-tripped", got)
				}
			},
		},
		{
			// Also already on the pattern. It is the one writer that replaces the whole store with
			// bytes off the network, which makes it the most expensive one to get wrong.
			name: "pulled store",
			path: xdg.StorePath,
			save: func(*testing.T) error { return writeLocalStore([]byte(`{"version":1,"generation":3}`)) },
			check: func(t *testing.T) {
				t.Helper()
				b, err := os.ReadFile(xdg.StorePath())
				if err != nil {
					t.Fatalf("read the pulled store: %v", err)
				}
				if string(b) != `{"version":1,"generation":3}` {
					t.Errorf("pulled store = %q, want the payload verbatim", b)
				}
			},
		},
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return // Windows governs file access by ACL, not Unix mode bits
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Errorf("%s mode = %o, want %o", filepath.Base(path), got, want)
	}
}

// TestStateWritersIgnoreALeftoverTemporaryFileFromACrashedRun is the mode half of R18. A writer
// that publishes through a fixed "<destination>.tmp" reuses whatever file is already at that path
// — and os.WriteFile applies its mode only when it *creates* a file, so a leftover at 0644 was
// renamed on top of a 0600 destination, taking its mode with it. arca then reported nothing wrong:
// the document is correct, and only the mode is different.
func TestStateWritersIgnoreALeftoverTemporaryFileFromACrashedRun(t *testing.T) {
	for _, w := range stateWriters() {
		t.Run(w.name, func(t *testing.T) {
			sandbox(t)
			if err := os.MkdirAll(storeStateDir(), 0o700); err != nil {
				t.Fatal(err)
			}
			stale := w.path() + ".tmp"
			if err := os.WriteFile(stale, []byte("half a document from a run that died"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(stale, 0o644); err != nil { // WriteFile only chmods on create
				t.Fatal(err)
			}

			if err := w.save(t); err != nil {
				t.Fatalf("save: %v", err)
			}
			assertMode(t, w.path(), 0o600)
			w.check(t)
		})
	}
}

// TestStateWritersSurviveALeftoverTemporaryDirectory is the collision half. The same fixed name is
// also the thing two concurrent writers race over, and the cheapest way to prove a writer no
// longer depends on it is to make that one path unusable: a directory cannot be written to or
// renamed over, so any writer that still reaches for "<destination>.tmp" fails outright.
//
// A directory at that path is not only a test contrivance. `arca` publishes into a state dir the
// operator can reach, and a stale entry of any kind there must not be able to stop a secret from
// being stored.
func TestStateWritersSurviveALeftoverTemporaryDirectory(t *testing.T) {
	for _, w := range stateWriters() {
		t.Run(w.name, func(t *testing.T) {
			sandbox(t)
			if err := os.MkdirAll(storeStateDir(), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(w.path()+".tmp", 0o700); err != nil {
				t.Fatal(err)
			}

			if err := w.save(t); err != nil {
				t.Fatalf("save: %v", err)
			}
			assertMode(t, w.path(), 0o600)
			w.check(t)
		})
	}
}

// TestStateWritersLeaveNoTemporaryFileBehind guards the state dir against litter. It is not
// cosmetic: `arca doctor` and the D4 adoption scan both enumerate this directory, and a half-
// written document sitting next to a real one is exactly the ambiguity D4 exists to remove.
func TestStateWritersLeaveNoTemporaryFileBehind(t *testing.T) {
	for _, w := range stateWriters() {
		t.Run(w.name, func(t *testing.T) {
			sandbox(t)
			if err := os.MkdirAll(storeStateDir(), 0o700); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Dir(w.path())
			before := dirEntries(t, dir)

			if err := w.save(t); err != nil {
				t.Fatalf("save: %v", err)
			}
			var added []string
			for name := range dirEntries(t, dir) {
				if !before[name] {
					added = append(added, name)
				}
			}
			if len(added) != 1 || added[0] != filepath.Base(w.path()) {
				t.Errorf("save added %v to %s, want just %s", added, dir, filepath.Base(w.path()))
			}
		})
	}
}

func dirEntries(t *testing.T, dir string) map[string]bool {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	m := make(map[string]bool, len(ents))
	for _, e := range ents {
		m[e.Name()] = true
	}
	return m
}

// TestEveryStatePublishGoesThroughAtomicfile is the guard that makes the claim in atomicfile's
// package comment — "the next writer cannot regress a step it never had to write" — true rather
// than aspirational. Nothing in the language stops a tenth writer from open-coding its own
// temp-and-rename and rediscovering R17 and R18 together, and a reviewer who is not looking for it
// will not see the missing fsync: the code looks finished.
//
// So the invariant is asserted mechanically, over the syntax tree rather than over the text, so a
// mention of os.Rename in a comment is not a finding. Anything on the allowlist is there with the
// reason it is not a state publish; a new entry should be as hard to add as writing that reason.
func TestEveryStatePublishGoesThroughAtomicfile(t *testing.T) {
	allowed := map[string]string{
		"lock.go": "the store lock is *acquired* by winning a rename, not published by one: the " +
			"rename is the mutex, and a stale lock is recovered by the steal path rather than by " +
			"having been made durable",
		"statedir.go": "the D4 adoption move relocates entries between two state directories. It " +
			"is resumable rather than durable by design — every entry is re-Stat'ed on the next " +
			"run, so an interrupted move finishes itself and a lost rename costs nothing",
	}

	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	found := map[string][]int{}
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "os" || sel.Sel.Name != "Rename" {
				return true
			}
			found[name] = append(found[name], fset.Position(call.Pos()).Line)
			return true
		})
	}

	for name, lines := range found {
		if _, ok := allowed[name]; !ok {
			t.Errorf("%s calls os.Rename at line(s) %v. Local state is published through "+
				"atomicfile.Write, which also fsyncs the parent directory (R17) and chmods before "+
				"it writes (R18); a hand-rolled rename silently drops both. If this rename is not "+
				"a state publish, add %s to the allowlist in this test with the reason.", name, lines, name)
		}
	}
}
