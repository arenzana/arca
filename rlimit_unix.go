//go:build !windows

package main

import "syscall"

// disableCoreDumps sets this process's RLIMIT_CORE soft limit to 0.
//
// The MCP server holds injected secret values in cleartext for its whole lifetime: as
// redactPattern.value (redact.go), inside the child's environment, and transiently as the
// plaintext returned by crypto.Decrypt. If arca crashes — including an OOM the agent can
// deliberately drive by choosing a runaway command — a core dump on a host that collects them
// contains every one of those values in the clear. An attacker who cannot read a secret through
// arca's policy should not get it from arca's corpse.
//
// Only the soft limit is lowered. Lowering the hard limit is irreversible for the process and
// buys nothing here: arca never wants to raise it back.
func disableCoreDumps() error {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &rl); err != nil {
		return err
	}
	if rl.Cur == 0 { // already off (common: many distros default to 0)
		return nil
	}
	rl.Cur = 0
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &rl)
}
