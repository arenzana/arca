//go:build !windows

package atomicfile

import (
	"errors"
	"os"
	"syscall"
)

// fsyncDir flushes a directory's own metadata, so that a rename performed inside it survives a
// power loss. Opening the directory read-only is sufficient: fsync(2) on a directory fd is the
// documented way to make the entry durable, and it needs no write access.
//
// Three errno values are tolerated rather than returned. A few filesystems — some FUSE mounts,
// some network mounts — simply do not implement fsync on a directory and answer EINVAL, ENOTSUP
// or ENOSYS. That is the filesystem declining to offer the guarantee, not arca failing to ask
// for it, and turning it into a write error would fail every mutation on those mounts without
// making anything more durable. Every other error is returned, because it means the call was
// available and did not succeed.
func fsyncDir(dir string) error {
	f, err := os.Open(dir) //#nosec G304 -- the caller's own state directory, and it is only fsynced: never read, written, or interpreted
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.ENOSYS) {
			return nil
		}
		return err
	}
	return nil
}
