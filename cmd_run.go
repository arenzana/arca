// The commands that hand a secret to another process: inject, exec and env.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/arenzana/arca/internal/crypto"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var refRe = regexp.MustCompile(`arca://[A-Za-z_][A-Za-z0-9_]*`)

// newInject resolves arca://NAME references on stdin and writes the result to stdout — so an
// agent can put references in a config/template and have them filled in at render time,
// manipulating references rather than secrets. no-print secrets are refused (use exec); every
// resolved secret is audited.
func newInject() *cobra.Command {
	return &cobra.Command{
		Use:   "inject",
		Short: "Resolve arca://NAME references on stdin, writing the result to stdout",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			ids, err := loadIDs()
			if err != nil {
				return err
			}
			data, err := readAllLimited(os.Stdin, maxInputBytes)
			if err != nil {
				return err
			}
			// ReplaceAllStringFunc can't return an error, so we capture the first failure in a
			// closure variable and surface it after the scan (leaving the reference untouched).
			var firstErr error
			out := refRe.ReplaceAllStringFunc(string(data), func(m string) string {
				name := strings.TrimPrefix(m, "arca://")
				sec := s.Secrets[name]
				switch {
				case sec == nil:
					if firstErr == nil {
						firstErr = fmt.Errorf("no such secret: %s", name)
					}
					return m
				case sec.NoPrint:
					if firstErr == nil {
						firstErr = fmt.Errorf("%s is marked --no-print; use `exec`, not inject", name)
					}
					return m
				}
				if err := gate(sec, name, ""); err != nil {
					if firstErr == nil {
						firstErr = err
					}
					return m
				}
				plain, err := crypto.Decrypt(sec.Value, ids)
				if err != nil {
					if firstErr == nil {
						firstErr = fmt.Errorf("decrypt %s: %w", name, err)
					}
					return m
				}
				if err := logAudit("inject", name, ""); err != nil {
					if firstErr == nil {
						firstErr = err
					}
					return m
				}
				return string(plain)
			})
			if firstErr != nil {
				return firstErr
			}
			fmt.Print(out)
			return nil
		},
	}
}

// newExec runs a command with selected secrets injected as environment variables. This is the
// "use without revealing" path: the command can read $NAME, but the value never lands on
// arca's stdout or in an agent's context. It's also the only way to use a --no-print secret.
func newExec() *cobra.Command {
	var only []string
	var redactMode string
	var reveal bool
	c := &cobra.Command{
		Use:   "exec [--only a,b] -- command [args...]",
		Short: "Run a command with secrets injected as env (audited)",
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("no command given")
			}
			s, err := openStore()
			if err != nil {
				return err
			}
			ids, err := loadIDs()
			if err != nil {
				return err
			}
			names := s.Names()
			if len(only) > 0 { // least privilege: inject just what was asked for
				names = only
			}
			switch redactMode {
			case "auto", "on", "off":
			default:
				return fmt.Errorf("--redact must be auto, on, or off (got %q)", redactMode)
			}

			caller := filepath.Base(args[0])   // recorded as the audit "caller"
			cmdline := strings.Join(args, " ") // matched against a require-grant secret's command pattern
			env := os.Environ()
			var injected []redactPattern
			for _, name := range names {
				sec := s.Secrets[name]
				if sec == nil {
					return fmt.Errorf("no such secret: %s", name)
				}
				// Defense in depth against a poisoned/hand-edited store: never inject a name
				// that isn't a valid identifier (e.g. LD_PRELOAD-style or `=`-bearing names).
				if validName(name) != nil {
					fmt.Fprintf(os.Stderr, "skip %q: not a valid env name\n", name)
					continue
				}
				if err := gate(sec, name, cmdline); err != nil {
					return err
				}
				plain, err := crypto.Decrypt(sec.Value, ids)
				if err != nil {
					return fmt.Errorf("decrypt %s: %w", name, err)
				}
				env = append(env, name+"="+string(plain))
				injected = append(injected, redactPattern{name: name, value: plain})
				if err := logAudit("exec", name, caller); err != nil {
					return err
				}
			}

			cmd := exec.Command(args[0], args[1:]...) //#nosec G204 -- `arca exec` deliberately runs the user-specified command
			cmd.Env = env
			cmd.Stdin = os.Stdin

			// Redact injected secret values from the child's output so a command that prints one
			// doesn't leak it to whoever reads stdout/stderr (an AI agent, a log). Default `auto`
			// redacts only a stream that isn't an interactive terminal — i.e. one being captured —
			// and passes a real TTY straight through (a human at a prompt, no buffering latency).
			pats := buildRedactPatterns(injected, reveal, os.Stderr)
			// `auto` redacts a captured (non-terminal) stream and steps aside for a human at a real
			// TTY. But an AI agent commonly allocates a PTY to capture a child's output, which would
			// otherwise disable redaction — so a detected agent always gets redaction regardless of
			// the TTY check (SEC-11).
			agent := detectIdentity().Agent != ""
			redactStream := func(f *os.File) bool {
				switch redactMode {
				case "off":
					return false
				case "on":
					return true
				default:
					return len(pats) > 0 && (agent || !term.IsTerminal(int(f.Fd())))
				}
			}
			var redactors []*redactWriter
			if cmd.Stdout = os.Stdout; len(pats) > 0 && redactStream(os.Stdout) {
				rw := newRedactWriter(os.Stdout, pats)
				cmd.Stdout = rw
				redactors = append(redactors, rw)
			}
			if cmd.Stderr = os.Stderr; len(pats) > 0 && redactStream(os.Stderr) {
				rw := newRedactWriter(os.Stderr, pats)
				cmd.Stderr = rw
				redactors = append(redactors, rw)
			}

			runErr := cmd.Run()
			// Flush held-back tails and record any catches before honoring the exit code (which
			// may os.Exit). A secret appearing in output is a potential leak, so it's audited.
			for _, rw := range redactors {
				if err := rw.Flush(); err != nil {
					fmt.Fprintf(os.Stderr, "redact: flush failed: %v\n", err)
				}
			}
			caught := map[string]int{}
			for _, rw := range redactors {
				for name, n := range rw.hits {
					caught[name] += n
				}
			}
			for name, n := range caught {
				fmt.Fprintf(os.Stderr, "redact: caught %s in output (%d occurrence(s))\n", name, n)
				if err := logAudit("redact", name, caller); err != nil {
					fmt.Fprintf(os.Stderr, "redact: audit failed for %s: %v\n", name, err)
				}
			}

			if runErr != nil {
				// Propagate the child's exit code so `arca exec -- foo` behaves like `foo`.
				if ee, ok := runErr.(*exec.ExitError); ok {
					os.Exit(ee.ExitCode())
				}
				return runErr
			}
			return nil
		},
	}
	c.Flags().StringSliceVar(&only, "only", nil, "subset of secrets to inject (default: all)")
	c.Flags().StringVar(&redactMode, "redact", "auto", "redact injected secret values from output: auto (captured streams only), on, or off")
	c.Flags().BoolVar(&reveal, "reveal", false, "when redacting, reveal a few characters of long secrets instead of the name (weaker)")
	// Stop flag parsing at the first positional arg so the wrapped command's own flags
	// (e.g. `-auto-approve`) aren't interpreted by arca.
	c.Flags().SetInterspersed(false)
	return c
}

// newEnv dumps all secrets as shell assignments for `eval "$(arca env)"`. Each secret is
// audited (op "env"), and --no-print secrets are skipped so they can't be revealed this way.
func newEnv() *cobra.Command {
	var noExport bool
	c := &cobra.Command{
		Use:   "env",
		Short: `Print shell assignments for eval "$(arca env)" (audited per secret)`,
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			ids, err := loadIDs()
			if err != nil {
				return err
			}
			for _, name := range s.Names() {
				// Defense in depth: never emit `export <name>=…` for a name that isn't a valid
				// identifier — a crafted name in a poisoned store could otherwise inject shell
				// when the output is run via `eval "$(arca env)"`.
				if validName(name) != nil {
					fmt.Fprintf(os.Stderr, "skip %q: not a valid env name\n", name)
					continue
				}
				if s.Secrets[name].NoPrint {
					fmt.Fprintf(os.Stderr, "skip %s (--no-print)\n", name)
					continue
				}
				// Don't let one unusable secret blank out the whole `eval "$(arca env)"`: skip the
				// ones that simply can't be released here — disabled/expired (turned off) and
				// require-grant (needs a command to authorize against). An interactive approval
				// denial below is a deliberate "no" and still fails the command. Mirrors the
				// --no-print / invalid-name skips above.
				if s.Secrets[name].Disabled || s.Secrets[name].Expired(time.Now()) {
					fmt.Fprintf(os.Stderr, "skip %s (disabled/expired)\n", name)
					continue
				}
				if s.Secrets[name].RequireGrant {
					fmt.Fprintf(os.Stderr, "skip %s (require-grant; use exec)\n", name)
					continue
				}
				if err := gate(s.Secrets[name], name, ""); err != nil {
					return err
				}
				plain, err := crypto.Decrypt(s.Secrets[name].Value, ids)
				if err != nil {
					return fmt.Errorf("decrypt %s: %w", name, err)
				}
				if err := logAudit("env", name, ""); err != nil {
					return err
				}
				if noExport {
					fmt.Printf("%s=%s\n", name, shellQuote(string(plain)))
				} else {
					fmt.Printf("export %s=%s\n", name, shellQuote(string(plain)))
				}
			}
			return nil
		},
	}
	c.Flags().BoolVar(&noExport, "no-export", false, "omit the leading 'export '")
	return c
}
