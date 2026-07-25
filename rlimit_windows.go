//go:build windows

package main

// disableCoreDumps is a no-op on Windows: there is no RLIMIT_CORE.
//
// The equivalent exposure — Windows Error Reporting writing a crash dump that would contain
// injected secret values — is controlled by machine-wide policy (the WER LocalDumps registry
// keys), not by anything a process can set for itself. Suppressing it is an operator/deployment
// decision, so this returns nil rather than pretending to have handled it.
func disableCoreDumps() error { return nil }
