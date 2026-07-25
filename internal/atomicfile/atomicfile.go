// Package atomicfile writes a file so that a concurrent reader never sees a partial document,
// the destination always lands at exactly the mode asked for, and a power loss immediately after
// a successful write cannot resurrect the old contents.
//
// Every one of arca's state writers used to open-code some subset of this. They disagreed about
// which subset — the store fsynced its temp file, the sync config enforced its mode, and none of
// them fsynced the parent directory — so "atomic" meant something slightly different in each of
// nine places and the weakest one set the real guarantee. One helper is the point: the next
// writer cannot regress a step it never had to write.
package atomicfile

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// syncDir is a var so this package's own tests can observe that Write fsyncs the parent
// directory, and — the part that actually matters — that it does so *after* the rename.
// An fsync before the rename flushes a directory that does not yet mention the new file.
var syncDir = fsyncDir

// Write replaces path with data, atomically, at exactly perm, and durably.
//
// The sequence, and the reason each step is present:
//
//  1. MkdirAll(dir, 0700). Every caller writes into a state directory it owns and may be the
//     first thing on this machine to touch it.
//  2. CreateTemp in that same directory. Same directory means same filesystem, which is what
//     makes step 5's rename atomic. A *unique* name is what makes it safe: two concurrent
//     writers cannot scribble over each other's half-written temp file, and a stale temp file
//     left behind by a crashed run can neither block this write nor lend it a mode.
//  3. Chmod(perm), explicitly, before any bytes are written. os.WriteFile applies its mode only
//     when it creates the file, so writing through a fixed temp name that already exists at 0644
//     renames a 0644 file over the destination. This is the SEC-37 pattern; steps 2 and 3
//     together are what generalize it away from being one function's local fix.
//  4. Write, then Sync. The bytes are on the disk before anything points at them, so a crash
//     cannot publish a truncated document.
//  5. Close, then Rename. Atomic replacement: a reader sees the whole old file or the whole new
//     one, never a splice of the two.
//  6. syncDir. The rename is a modification of the *directory*, not of the file, and it is not
//     durable until the directory is flushed. Without this, a power loss can leave the directory
//     entry pointing at the old inode after arca has already reported the secret stored.
//
// Write returns an error from step 6 rather than swallowing it. The rename has already taken
// effect at that point, so the change is visible to every reader; what the error means is
// "committed, but this may not survive a crash", which is a thing the caller should be able to
// learn. Filesystems that do not implement the call at all are handled in fsyncDir, not here.
func Write(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return fmt.Errorf("create a temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename below succeeds

	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpName, path, err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("fsync %s (the write landed but may not survive a crash): %w", dir, err)
	}
	return nil
}
