package secretname

import "testing"

func TestValidateAcceptsIdentifiers(t *testing.T) {
	for _, n := range []string{"A", "_", "API_KEY", "a1", "_x9", "lower_case", "MiXeD_42"} {
		if err := Validate(n); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", n, err)
		}
	}
}

func TestValidateRejectsBadShapes(t *testing.T) {
	// Leading digits, punctuation and whitespace are all rejected by shape alone. The empty
	// string matters most: it is what an unset variable or a trailing separator produces.
	for _, n := range []string{"", "1ABC", "a-b", "a.b", "a b", "a/b", "a$b", "ÁCCENT", "a\nb", "a\tb"} {
		if Validate(n) == nil {
			t.Errorf("Validate(%q) = nil, want an error", n)
		}
	}
}

// The names that make this a security boundary rather than a style rule. Each of these is a
// perfectly valid identifier, so the shape check alone lets every one of them through.
func TestValidateRejectsReserved(t *testing.T) {
	for _, n := range []string{
		"PATH", "IFS", "BASH_ENV", "ENV", "SHELLOPTS", "CDPATH", "PROMPT_COMMAND",
		"PYTHONPATH", "NODE_OPTIONS", "PERL5OPT", "RUBYOPT", "GEM_PATH",
		"GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF", "EDITOR", "PAGER", "TERMINFO",
		"LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
		"HOME", "SHELL", "TMPDIR", "XDG_CONFIG_HOME",
	} {
		if err := Validate(n); err == nil {
			t.Errorf("Validate(%q) = nil, want a reserved-name error", n)
		}
	}
}

// Case folding is the bypass this guards: on a case-insensitive platform `path` and `PATH` reach
// the same variable, so matching only the upper-case spelling would leave the hole open.
func TestReservedIsCaseInsensitive(t *testing.T) {
	for _, n := range []string{"path", "Path", "pAtH", "ld_preload", "Ld_Preload", "dyld_insert_libraries"} {
		if !Reserved(n) {
			t.Errorf("Reserved(%q) = false, want true", n)
		}
		if Validate(n) == nil {
			t.Errorf("Validate(%q) = nil, want a reserved-name error", n)
		}
	}
}

// The linker prefixes are matched as prefixes, not as a fixed list, so a variable nobody
// enumerated (a new LD_* knob) is still refused.
func TestReservedCoversLinkerPrefixes(t *testing.T) {
	for _, n := range []string{"LD_AUDIT", "LD_SOMETHING_NEW", "DYLD_FRAMEWORK_PATH", "XDG_DATA_HOME"} {
		if !Reserved(n) {
			t.Errorf("Reserved(%q) = false, want true (prefix match)", n)
		}
	}
	// ...without swallowing names that merely start with the same letters.
	for _, n := range []string{"LDAP_URL", "LD", "DYLDX", "LDFLAGS"} {
		if Reserved(n) {
			t.Errorf("Reserved(%q) = true, want false", n)
		}
	}
}

func TestReservedAllowsOrdinaryNames(t *testing.T) {
	for _, n := range []string{"API_KEY", "DATABASE_URL", "STRIPE_SECRET", "HOMEPAGE_TOKEN"} {
		if Reserved(n) {
			t.Errorf("Reserved(%q) = true, want false", n)
		}
	}
}
