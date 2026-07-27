//go:build !windows

package atomicfile

import (
	"path/filepath"
	"testing"
)

// TestFsyncDirSucceedsOnARealDirectory is the one leg of fsyncDir that can be asserted portably:
// that opening the directory read-only is in fact enough to fsync it. The three tolerated errno
// values (EINVAL, ENOTSUP, ENOSYS) are properties of filesystems this suite cannot mount — some
// FUSE and network mounts — so they are covered by reading the code, not by a test that would have
// to lie about what it exercised.
func TestFsyncDirSucceedsOnARealDirectory(t *testing.T) {
	if err := fsyncDir(t.TempDir()); err != nil {
		t.Errorf("fsyncDir on a real directory: %v", err)
	}
}

// TestFsyncDirReportsADirectoryItCannotOpen pins that an open failure is returned rather than
// folded into the tolerated set. A missing state directory is a real problem worth surfacing, and
// it is exactly the kind of error the errno allowlist could swallow if it were written as
// "tolerate anything".
func TestFsyncDirReportsADirectoryItCannotOpen(t *testing.T) {
	if err := fsyncDir(filepath.Join(t.TempDir(), "no", "such", "dir")); err == nil {
		t.Error("fsyncDir on a nonexistent directory returned nil, want an error")
	}
}
