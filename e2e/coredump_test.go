//go:build e2e

package e2e

import (
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// TestCoreDumpsDisabledForChildren checks the wiring the unit tests cannot: that main() actually
// calls disableCoreDumps before any command runs, for the real binary.
//
// It asserts through a grandchild — `arca exec` runs `sh -c 'ulimit -c'`, which reports the limit
// it inherited from arca. That is the property that matters operationally: by the time arca holds
// a decrypted value, neither it nor anything it spawns can be dumped.
func TestCoreDumpsDisabledForChildren(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no RLIMIT_CORE on Windows; disableCoreDumps is a documented no-op there")
	}

	// Raise this process's soft limit first, so the arca child inherits a NON-zero one. Without
	// this the assertion below would pass on any host that already defaults RLIMIT_CORE to 0
	// (macOS and most Linux distros do) — i.e. it would pass whether or not arca did anything.
	var orig syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &orig); err != nil {
		t.Skipf("cannot read RLIMIT_CORE: %v", err)
	}
	if orig.Max == 0 {
		t.Skip("hard RLIMIT_CORE is 0 on this host; the soft limit cannot be raised, so this check would be vacuous")
	}
	raised := orig
	raised.Cur = orig.Max
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &raised); err != nil {
		t.Skipf("cannot raise RLIMIT_CORE for the setup: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Setrlimit(syscall.RLIMIT_CORE, &orig) })

	b := sandbox(t)
	if _, errOut, code := b.run(t, "", "init"); code != 0 {
		t.Fatalf("init failed (%d): %s", code, errOut)
	}
	if _, errOut, code := b.run(t, "sekritvalue123", "set", "DEMO"); code != 0 {
		t.Fatalf("set failed (%d): %s", code, errOut)
	}

	out, errOut, code := b.run(t, "", "exec", "--only", "DEMO", "--", "sh", "-c", "ulimit -c")
	if code != 0 {
		t.Fatalf("exec failed (%d): %s", code, errOut)
	}
	if got := strings.TrimSpace(out); got != "0" {
		t.Errorf("core limit inherited from arca = %q, want %q — main() is not disabling core dumps, "+
			"so a crash could dump the decrypted value it was holding", got, "0")
	}
}
