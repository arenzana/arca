package atomicfile

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// swapSyncDir replaces the package's directory-fsync hook for one test. Restoring it from
// t.Cleanup rather than a manual defer means a t.Fatal inside the test body cannot leave the
// hook installed for the rest of the package.
func swapSyncDir(t *testing.T, fn func(string) error) {
	t.Helper()
	old := syncDir
	t.Cleanup(func() { syncDir = old })
	syncDir = fn
}

// mustWriteFile is the "how the file got there beforehand" half of these tests: a plain,
// non-atomic write at whatever mode the scenario needs.
func mustWriteFile(t *testing.T, path string, data []byte, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatalf("seed %s: %v", path, err)
	}
	// WriteFile only applies perm when it creates the file — the very bug this package exists to
	// close — so a re-seed of an existing path needs an explicit chmod to mean what it says.
	if err := os.Chmod(path, perm); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

// TestWriteLandsAtTheModeAskedForOverAnExistingLooserFile is the SEC-37 property, generalized.
// os.WriteFile applies its mode only on create, so a writer that published through a fixed temp
// name could rename a 0644 file over a 0600 destination and silently widen it.
func TestWriteLandsAtTheModeAskedForOverAnExistingLooserFile(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "state.json")
	mustWriteFile(t, dst, []byte("old"), 0o644)

	if err := Write(dst, []byte("new"), 0o600); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Unix mode bits only: Windows governs access by ACL and reports a writable file as 0666.
	if runtime.GOOS != "windows" {
		if got := modeOf(t, dst); got != 0o600 {
			t.Errorf("mode = %o, want 600 — the destination kept the looser mode it already had", got)
		}
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "new" {
		t.Errorf("contents = %q, want %q", b, "new")
	}
}

// TestWriteHonoursAModeOtherThanTheTempFileDefault exists because the test above cannot fail for
// the reason it appears to. os.CreateTemp already creates at 0600, so with every current caller
// asking for 0600 the explicit Chmod is indistinguishable from doing nothing: delete it and the
// mode assertions still pass. That would leave `perm` as a parameter the helper silently ignores,
// and the first caller to ask for anything else would get 0600 with no error and no clue.
//
// Asking for a mode CreateTemp does not hand out is what separates the two mechanisms.
func TestWriteHonoursAModeOtherThanTheTempFileDefault(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows governs file access by ACL, not Unix mode bits")
	}
	for _, perm := range []os.FileMode{0o400, 0o640, 0o644} {
		t.Run(fmt.Sprintf("%o", perm), func(t *testing.T) {
			dst := filepath.Join(t.TempDir(), "state.json")
			if err := Write(dst, []byte("new"), perm); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if got := modeOf(t, dst); got != perm {
				t.Errorf("mode = %o, want %o — the perm argument was not applied, so the file kept whatever mode it was created at", got, perm)
			}
		})
	}
}

// TestWriteFsyncsTheParentDirectoryAfterTheRename is R17's regression test, and the ordering half
// is the part that matters: an fsync issued *before* the rename flushes a directory that does not
// yet mention the new file, which looks identical in a diff and buys nothing. The hook therefore
// asserts two things at once — that it ran at all, and that the destination already holds the new
// bytes by the time it runs.
func TestWriteFsyncsTheParentDirectoryAfterTheRename(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "state.json")
	mustWriteFile(t, dst, []byte("old"), 0o600)

	var calls int
	var sawDir string
	var contentsWhenSynced []byte
	swapSyncDir(t, func(d string) error {
		calls++
		sawDir = d
		contentsWhenSynced, _ = os.ReadFile(dst)
		return nil
	})

	if err := Write(dst, []byte("new"), 0o600); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if calls != 1 {
		t.Fatalf("parent directory fsynced %d times, want exactly 1", calls)
	}
	if sawDir != dir {
		t.Errorf("fsynced %q, want the destination's own directory %q", sawDir, dir)
	}
	if string(contentsWhenSynced) != "new" {
		t.Errorf("destination held %q when the directory was fsynced, want %q — the fsync ran before the rename, so it flushed a directory that did not yet mention the new file", contentsWhenSynced, "new")
	}
}

// TestWriteReportsADirectorySyncFailureAfterTheWriteHasCommitted pins the documented meaning of
// that error: the rename has already taken effect, so the new contents are visible to every
// reader. The error says "committed, but this may not survive a crash", which is a thing a caller
// is entitled to learn — swallowing it would report full durability arca did not get.
func TestWriteReportsADirectorySyncFailureAfterTheWriteHasCommitted(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "state.json")
	mustWriteFile(t, dst, []byte("old"), 0o600)

	boom := errors.New("no fsync for you")
	swapSyncDir(t, func(string) error { return boom })

	err := Write(dst, []byte("new"), 0o600)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want it to wrap %v", err, boom)
	}
	if !strings.Contains(err.Error(), "may not survive a crash") {
		t.Errorf("err = %q, want it to say the write landed anyway", err)
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "new" {
		t.Errorf("contents = %q, want %q — the rename happens before the directory fsync, so the new bytes must be visible even on this error path", b, "new")
	}
}

// TestWriteCreatesTheParentDirectory covers the fresh-machine case every caller relies on: a
// state directory that nothing has touched yet. Each caller used to MkdirAll for itself, and
// saveEscrowState is the one that proved the arrangement fragile — it inherited the directory
// from another function until D4 moved the file, then had to grow its own.
func TestWriteCreatesTheParentDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does", "not", "exist")
	dst := filepath.Join(dir, "state.json")

	if err := Write(dst, []byte("new"), 0o600); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Unix mode bits only (see above); on Windows the property under test is that the parent
	// directory was created, which the successful Write above already established.
	if runtime.GOOS != "windows" {
		if got := modeOf(t, dir); got != 0o700 {
			t.Errorf("directory mode = %o, want 700", got)
		}
		if got := modeOf(t, dst); got != 0o600 {
			t.Errorf("file mode = %o, want 600", got)
		}
	}
}

// TestWriteLeavesNoTemporaryFileBehind covers both exits. On success the rename consumes the temp
// file; on failure the deferred Remove has to. A writer that litters is not merely untidy here —
// the directory it litters into is the one arca globs to find a store's state.
func TestWriteLeavesNoTemporaryFileBehind(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		dir := t.TempDir()
		if err := Write(filepath.Join(dir, "state.json"), []byte("new"), 0o600); err != nil {
			t.Fatalf("Write: %v", err)
		}
		assertOnlyEntries(t, dir, "state.json")
	})

	t.Run("failure at the rename", func(t *testing.T) {
		dir := t.TempDir()
		dst := filepath.Join(dir, "state.json")
		// A directory at the destination makes the rename fail (POSIX: renaming a non-directory
		// onto a directory is EISDIR) with everything before it having succeeded, which is the
		// only exit where a temp file actually exists to be leaked.
		if err := os.Mkdir(dst, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := Write(dst, []byte("new"), 0o600); err == nil {
			t.Fatal("Write succeeded onto a directory, want an error")
		}
		assertOnlyEntries(t, dir, "state.json")
	})
}

func assertOnlyEntries(t *testing.T, dir string, want ...string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(ents))
	for _, e := range ents {
		got = append(got, e.Name())
	}
	if len(got) != len(want) {
		t.Fatalf("directory holds %v, want exactly %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("directory holds %v, want exactly %v", got, want)
		}
	}
}

// TestWriteReportsAParentDirectoryItCannotCreate covers the first step's error path. It is not
// hypothetical: `$ARCA_STORE` is operator-supplied, and pointing it inside a regular file is an
// ordinary typo. The error has to name the directory, because "permission denied" on its own sends
// an operator looking at the wrong thing.
func TestWriteReportsAParentDirectoryItCannotCreate(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Write(filepath.Join(notADir, "state.json"), []byte("new"), 0o600)
	if err == nil {
		t.Fatal("Write succeeded under a regular file, want an error")
	}
	if !strings.Contains(err.Error(), notADir) {
		t.Errorf("err = %q, want it to name the directory %q", err, notADir)
	}
}

// TestWriteReportsATemporaryFileItCannotCreate covers the second step's error path — the directory
// exists but nothing can be written into it, which is what a state dir restored from a backup with
// the wrong mode looks like.
func TestWriteReportsATemporaryFileItCannotCreate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a 0500 directory does not block the owner from writing on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory permissions")
	}
	dir := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // let t.TempDir clean up

	err := Write(filepath.Join(dir, "state.json"), []byte("new"), 0o600)
	if err == nil {
		t.Fatal("Write succeeded into a read-only directory, want an error")
	}
	if !strings.Contains(err.Error(), "temp file") || !strings.Contains(err.Error(), dir) {
		t.Errorf("err = %q, want it to say a temp file in %q could not be created", err, dir)
	}
}

// TestWriteWrapsItsErrorsWithThePathThatFailed guards the boundary contract: a caller that gets an
// error from a state write has to be able to tell an operator which file it was.
func TestWriteWrapsItsErrorsWithThePathThatFailed(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "state.json")
	if err := os.Mkdir(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	err := Write(dst, []byte("new"), 0o600)
	if err == nil {
		t.Fatal("Write succeeded onto a directory, want an error")
	}
	if !strings.Contains(err.Error(), dst) {
		t.Errorf("err = %q, want it to name %q", err, dst)
	}
}

// TestConcurrentWritersNeverPublishASplice is the reason the temp name is unique rather than
// "<destination>.tmp". Under the fixed name, two writers share one temp file: they interleave
// their bytes into it and each renames the other's half-written result into place. A unique name
// per call makes the rename the only shared step, and rename is atomic.
//
// The assertion is on what a *reader* can observe, not on which writer wins — the last writer is
// deliberately unspecified. Every read must be one whole payload.
func TestConcurrentWritersNeverPublishASplice(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "state.json")

	const writers = 8
	payloads := make(map[string]bool, writers)
	for i := range writers {
		// Distinct lengths as well as distinct contents: a splice of two same-length payloads can
		// still be the right size, and size is the cheapest thing a reader would check.
		payloads[strings.Repeat(fmt.Sprintf("%d", i), 64+i*17)] = true
	}
	// Seed the destination so a reader never races an as-yet-nonexistent path; that would be a
	// different (and uninteresting) failure than the one under test.
	mustWriteFile(t, dst, []byte("seed"), 0o600)
	payloads["seed"] = true

	bad := make(chan string, writers+1)
	stop := make(chan struct{})

	var readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			b, err := os.ReadFile(dst)
			if err != nil {
				// On Windows the publish is MoveFileEx(REPLACE_EXISTING) and a concurrent opener
				// can lose the race with a sharing violation. That is an availability artifact, not
				// a splice — the integrity property here only constrains reads that SUCCEED (W3:
				// document, do not retry). On Unix a read error is a real failure.
				if runtime.GOOS == "windows" {
					continue
				}
				bad <- fmt.Sprintf("read: %v", err)
				return
			}
			if !payloads[string(b)] {
				bad <- fmt.Sprintf("read a document no writer ever wrote (%d bytes)", len(b))
				return
			}
		}
	}()

	var writersWG sync.WaitGroup
	for p := range payloads {
		if p == "seed" {
			continue
		}
		writersWG.Add(1)
		go func(p string) {
			defer writersWG.Done()
			if err := Write(dst, []byte(p), 0o600); err != nil {
				// Same Windows race, writer side: a concurrent open of the destination makes
				// MoveFileEx(REPLACE_EXISTING) fail with Access denied. The write did not land, no
				// splice was published, and Write's defer removes the temp — so on Windows this is
				// availability, not integrity. Production serializes writers with the store lock;
				// this test deliberately runs them lock-free to stress the rename itself.
				if runtime.GOOS == "windows" {
					return
				}
				bad <- fmt.Sprintf("Write: %v", err)
			}
		}(p)
	}
	writersWG.Wait()
	close(stop)
	readers.Wait()

	select {
	case msg := <-bad:
		t.Fatal(msg)
	default:
	}

	if runtime.GOOS != "windows" {
		if got := modeOf(t, dst); got != 0o600 {
			t.Errorf("mode = %o, want 600", got)
		}
	}
	// No leftovers, whichever writer went last.
	assertOnlyEntries(t, dir, "state.json")
}

// TestWriteAcceptsAnEmptyDocument is a boundary case that reaches the store: `arca rm` of the last
// secret still writes a well-formed document, and a zero-length payload must not be special-cased
// into a no-op that leaves yesterday's file in place.
func TestWriteAcceptsAnEmptyDocument(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "state.json")
	mustWriteFile(t, dst, []byte("old"), 0o600)

	if err := Write(dst, nil, 0o600); err != nil {
		t.Fatalf("Write: %v", err)
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, []byte{}) {
		t.Errorf("contents = %q, want empty", b)
	}
}
