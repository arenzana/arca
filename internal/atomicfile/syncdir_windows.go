//go:build windows

package atomicfile

// fsyncDir is a no-op on Windows.
//
// There is no portable equivalent of fsync(2) on a directory here: os.File.Sync maps to
// FlushFileBuffers, which needs a handle opened for write access, and a directory handle cannot
// be opened that way. So the durability step Unix gets after the rename is not available to ask
// for, and this is a real gap rather than a difference that cancels out — a power loss on
// Windows immediately after a write can still lose the rename. Named and given its own file so
// the platform difference is visible in one place instead of being implied by an #ifdef-shaped
// silence, and so a future Windows-specific fix has somewhere obvious to land.
func fsyncDir(string) error { return nil }
