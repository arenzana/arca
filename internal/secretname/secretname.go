// Package secretname decides what a secret may be called.
//
// This is a security boundary, not a formatting rule. arca injects secrets into child processes
// as environment variables, so a name is also an env-var name, and some env-var names are
// instructions to the loader or the shell rather than data. A value stored under one of those
// hijacks the child instead of being consumed by it.
//
// It lives in its own package because the rule has to hold identically on every write path
// (set, generate, rotate, import, canary, grant, handle) and again at every injection site, and a
// second copy of it that drifted would be a code-execution bug rather than an inconsistency.
package secretname

import (
	"fmt"
	"regexp"
	"strings"
)

var nameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// reserved are environment-variable names that must never be used as a secret name: a value
// injected under one of them (via exec/env/run_with_secrets/handle) hijacks the child process
// rather than being consumed by it. LD_*/DYLD_* load attacker code into the dynamic linker;
// PATH/CDPATH redirect binary lookup; IFS/BASH_ENV/ENV/SHELLOPTS/PS*/PROMPT_COMMAND alter shell
// parsing; the language-runtime hooks below inject libraries or startup code. Because the store
// keeps recipient public keys in cleartext and is meant to be git-synced, anyone who can write
// the store could otherwise craft a correctly-encrypted entry under one of these names and get
// code execution on the operator's next `arca exec`. The shape check (nameRe) alone does NOT stop
// this: every name here is a valid identifier. Matched case-insensitively so a case-folding
// platform (Windows) or a confusable can't slip through.
var reserved = map[string]bool{
	"PATH": true, "IFS": true, "BASH_ENV": true, "ENV": true, "SHELLOPTS": true,
	"BASHOPTS": true, "CDPATH": true, "PS1": true, "PS2": true, "PS3": true, "PS4": true,
	"PROMPT_COMMAND": true, "GLOBIGNORE": true, "FIGNORE": true,
	"PERL5LIB": true, "PERL5OPT": true, "PYTHONPATH": true, "PYTHONSTARTUP": true,
	"NODE_OPTIONS": true, "RUBYOPT": true, "RUBYLIB": true, "GEM_PATH": true,
	"GIT_SSH": true, "GIT_SSH_COMMAND": true, "GIT_EXTERNAL_DIFF": true, "GIT_PAGER": true,
	"HOSTALIASES": true, "TERMINFO": true, "TERMCAP": true, "PAGER": true, "EDITOR": true,
	"HOME": true, "SHELL": true, "TMPDIR": true, "TEMP": true, "TMP": true,
}

// Reserved reports whether name would hijack a child process if injected as an environment
// variable. It matches the reserved table case-insensitively plus the dynamic-linker prefixes
// LD_*, DYLD_*, and XDG_* (HOME/SHELL/TMPDIR hijack the child's working environment;
// XDG_* relocates config/state the way PATH relocates binaries — audit L5).
func Reserved(name string) bool {
	u := strings.ToUpper(name)
	if reserved[u] {
		return true
	}
	return strings.HasPrefix(u, "LD_") || strings.HasPrefix(u, "DYLD_") || strings.HasPrefix(u, "XDG_")
}

// Validate rejects names that aren't safe identifiers, or that would hijack a child process's
// environment (reserved names like PATH/LD_PRELOAD). It is enforced on every write and re-checked
// at every env-injection site, so an already-poisoned store can't be used either.
func Validate(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("invalid secret name %q: must match [A-Za-z_][A-Za-z0-9_]*", name)
	}
	if Reserved(name) {
		return fmt.Errorf("secret name %q is a reserved environment variable and can't be used: injecting it would hijack the child process", name)
	}
	return nil
}
