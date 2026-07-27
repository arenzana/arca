//go:build windows

package main

import "testing"

// coreLimit exists only so the shared test compiles on Windows; RLIMIT_CORE has no analogue
// there, and TestDisableCoreDumps returns before reaching this.
func coreLimit(t *testing.T) uint64 {
	t.Helper()
	return 0
}
