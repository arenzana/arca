//go:build !windows

package main

import (
	"syscall"
	"testing"
)

// coreLimit reports the current RLIMIT_CORE soft limit.
func coreLimit(t *testing.T) uint64 {
	t.Helper()
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &rl); err != nil {
		t.Fatalf("getrlimit(RLIMIT_CORE): %v", err)
	}
	return uint64(rl.Cur)
}
