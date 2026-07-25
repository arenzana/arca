package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The generation counter is the store's rollback tripwire (SEC-14). recordAudit binds it into the
// hash-chained, signed audit event, and audit.Verify reports a later event carrying a *lower*
// generation than an earlier one as GenRegressed — evidence the store file was restored from an
// older copy. Every test in this file exists because that signal only means something if the
// counter and the file can never disagree.

// diskGeneration reads the generation straight out of the JSON rather than through Load, so a bug
// in Load's tolerance for odd documents cannot mask a bug in Save.
func diskGeneration(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc struct {
		Generation int `json:"generation"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return doc.Generation
}

// TestGenerationDoesNotAdvanceWhenTheWriteFails is R16. Save used to bump the counter as its first
// statement, so any failure past that point left the in-memory store one generation ahead of the
// file — and the audit event recorded for that command bound a generation that never existed on
// disk. The next process loaded the real, lower generation, recorded it, and Verify called the
// pair a rollback. A false alarm on a tamper-evidence signal is worse than no alarm.
//
// Two failure points, deliberately at opposite ends of the write. A fix that only moved the bump
// past the marshal would still be wrong at the rename.
func TestGenerationDoesNotAdvanceWhenTheWriteFails(t *testing.T) {
	cases := []struct {
		name string
		skip func(t *testing.T)
		// breaks makes the next Save fail. Naming where in the sequence each one lands keeps the
		// case names from drifting away from what they actually exercise.
		breaks func(t *testing.T, path string)
		// readable says whether the store document still exists afterwards, and so whether the
		// on-disk generation can be asserted as well as the in-memory one.
		readable bool
	}{
		{
			// Fails at CreateTemp, the earliest failure a caller can provoke: the directory exists
			// but nothing can be written into it. Marshalling has already happened by this point,
			// so a fix that only moved the bump past the marshal would still be wrong here.
			name: "the temp file cannot be created",
			skip: func(t *testing.T) {
				t.Helper()
				if runtime.GOOS == "windows" {
					t.Skip("a 0500 directory does not block the owner from writing on Windows")
				}
				if os.Geteuid() == 0 {
					t.Skip("running as root bypasses directory permissions")
				}
			},
			breaks: func(t *testing.T, path string) {
				t.Helper()
				dir := filepath.Dir(path)
				if err := os.Chmod(dir, 0o500); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // let t.TempDir clean up
			},
			readable: true,
		},
		{
			// Fails at the rename, with every step before it having succeeded: POSIX makes renaming
			// a non-directory onto a directory EISDIR. This is the last failure that can still
			// leave the counter and the file disagreeing.
			name: "the rename cannot replace the destination",
			breaks: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			},
			readable: false, // the destination is a directory now; there is no document to read
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skip != nil {
				tc.skip(t)
			}
			dir := filepath.Join(t.TempDir(), "state")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "store.json")

			s := New(path, []string{"age1xyz"})
			if err := s.Save(); err != nil {
				t.Fatalf("first Save: %v", err)
			}
			if s.Generation != 1 {
				t.Fatalf("after one Save, Generation = %d, want 1", s.Generation)
			}
			onDisk := diskGeneration(t, path)

			// The failing Save. Break the path only now, so the successful write above is a real
			// one and `onDisk` is a real reading.
			tc.breaks(t, path)
			s.Secrets["FOO"] = &Secret{Value: "ciphertext"}
			if err := s.Save(); err == nil {
				t.Fatal("Save succeeded, want an error — this test cannot assert anything about a failed write that did not fail")
			}

			if s.Generation != 1 {
				t.Errorf("after a failed Save, Generation = %d, want 1 — the in-memory counter is ahead of the file, so this command's audit event binds a generation that never existed on disk", s.Generation)
			}
			if tc.readable {
				if got := diskGeneration(t, path); got != onDisk {
					t.Errorf("on-disk generation = %d, want %d unchanged", got, onDisk)
				}
			}
		})
	}
}

// TestGenerationAdvancesExactlyOncePerSuccessfulSave is the no-overshoot pin for the test above:
// the counter still has to move, and by exactly one, or the rollback tripwire stops working in the
// other direction. A fix that simply stopped bumping would satisfy R16 and break SEC-14.
func TestGenerationAdvancesExactlyOncePerSuccessfulSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	s := New(path, []string{"age1xyz"})
	for want := 1; want <= 4; want++ {
		if err := s.Save(); err != nil {
			t.Fatalf("Save %d: %v", want, err)
		}
		if s.Generation != want {
			t.Fatalf("in-memory Generation = %d, want %d", s.Generation, want)
		}
		if got := diskGeneration(t, path); got != want {
			t.Fatalf("on-disk generation = %d, want %d", got, want)
		}
	}
}

// TestSaveWritesTheAdvancedGenerationNotThePreviousOne pins the half of R16 that a careless fix
// gets backwards. Moving the bump to the end of Save without also marshalling the advanced value
// writes generation N to disk while leaving N+1 in memory — the same disagreement as the bug, with
// the sign flipped, and it would still trip GenRegressed on the next process.
func TestSaveWritesTheAdvancedGenerationNotThePreviousOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	s := New(path, []string{"age1xyz"})
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	if got, want := diskGeneration(t, path), s.Generation; got != want {
		t.Fatalf("on-disk generation = %d but the in-memory store says %d; they must never disagree after a successful Save", got, want)
	}

	// And through Load, since that is how the next process sees it.
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Generation != s.Generation {
		t.Errorf("reloaded generation = %d, want %d", loaded.Generation, s.Generation)
	}
}

// TestSaveLandsAt0600OverAnExistingLooserFile guards the mode through the new helper. The store
// holds age ciphertext, but it also holds every secret *name*, and a world-readable store leaks
// the shape of the operator's infrastructure even when no value can be decrypted.
func TestSaveLandsAt0600OverAnExistingLooserFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows governs file access by ACL, not Unix mode bits")
	}
	path := filepath.Join(t.TempDir(), "store.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil { // WriteFile only chmods on create
		t.Fatal(err)
	}
	s := New(path, []string{"age1xyz"})
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 600", got)
	}
}

// TestSaveLeavesNoTemporaryFileBesideTheStore matters here specifically because the store usually
// lives in a git repository: a leaked `.store-*.tmp` holding a full copy of the previous store
// shows up in `git status`, and an operator who commits it has published a document arca went to
// some trouble to replace.
func TestSaveLeavesNoTemporaryFileBesideTheStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.json")
	s := New(path, []string{"age1xyz"})
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != "store.json" {
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("store directory holds %v, want just store.json", names)
	}
}
