// Command arca is an age-encrypted secret store with cleartext metadata and a local audit log,
// designed to sit safely in front of AI agents.
//
// The CLI is intentionally split into three "access shapes" with different trust levels:
//
//   - get / env    — reveal a value to stdout (blocked for --no-print secrets);
//   - inject       — resolve arca://NAME references in a template to stdout (also blocked for
//     --no-print secrets);
//   - exec         — inject values into a subprocess's environment, so a command can *use* a
//     secret while the value never appears on arca's stdout or in an agent's
//     context. This is the sanctioned path for --no-print secrets.
//
// Every access is written to the audit log with the calling AI agent's name/version/session
// (auto-detected) plus an explicit $ARCA_ACTOR, so `arca log` can answer who touched what.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"filippo.io/age"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/arenzana/arca/internal/audit"
	"github.com/arenzana/arca/internal/crypto"
	"github.com/arenzana/arca/internal/store"
)

// version is set at build/release time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	// Cobra prints the error itself (SilenceErrors=false); we just set the exit code.
	if err := newRoot().Execute(); err != nil {
		os.Exit(1)
	}
}

// newRoot builds the command tree. It's a constructor (not a package-level var) so tests can
// get a fresh, isolated command instance per invocation.
func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "arca",
		Short:         "age-encrypted secrets with metadata and an audit log",
		Long:          "arca stores secrets as age-encrypted values with cleartext metadata in a JSON\nstore, and records every access in a local SQLite audit log.",
		Version:       version,
		SilenceUsage:  true, // don't dump usage on every runtime error
		SilenceErrors: false,
	}
	cmds := []*cobra.Command{
		newInit(), newSet(), newGet(), newRotate(), newLs(), newShow(), newStale(),
		newRm(), newImport(), newInject(), newExec(), newEnv(), newLog(), newMCP(),
		newRecipients(), newReencrypt(),
	}
	root.AddCommand(cmds...)
	registerCompletions(cmds)
	return root
}

// ----------------------------------------------------------------------------
// Paths. All three locations are overridable via env so the store can be pointed at a
// dotfiles repo (git-synced) while the audit DB stays local, and tests can sandbox everything.
// ----------------------------------------------------------------------------

// xdgHome returns $env if set, else $HOME/def — an XDG-with-fallback helper.
func xdgHome(env, def string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, def)
}

func configDir() string { return filepath.Join(xdgHome("XDG_CONFIG_HOME", ".config"), "arca") }
func stateDir() string  { return filepath.Join(xdgHome("XDG_STATE_HOME", ".local/state"), "arca") }

// storePath is the JSON store (git-syncable). Override with $ARCA_STORE.
func storePath() string {
	if p := os.Getenv("ARCA_STORE"); p != "" {
		return p
	}
	return filepath.Join(configDir(), "store.json")
}

// auditPath is the local SQLite audit DB (do not sync). Override with $ARCA_AUDIT.
func auditPath() string {
	if p := os.Getenv("ARCA_AUDIT"); p != "" {
		return p
	}
	return filepath.Join(stateDir(), "audit.db")
}

// identityPath is the age private key. It defaults to reusing the caller's existing
// $SOPS_AGE_KEY_FILE so arca shares one key with sops; override with $ARCA_IDENTITY.
func identityPath() string {
	if p := os.Getenv("ARCA_IDENTITY"); p != "" {
		return p
	}
	if p := os.Getenv("SOPS_AGE_KEY_FILE"); p != "" {
		return p
	}
	return filepath.Join(configDir(), "identity.txt")
}

// ----------------------------------------------------------------------------
// Shared helpers.
// ----------------------------------------------------------------------------

func openStore() (*store.Store, error) { return store.Load(storePath()) }
func loadIDs() ([]age.Identity, error) { return crypto.LoadIdentities(identityPath()) }

// logAudit records one access event. Auditing is fail-closed by DEFAULT: if the audit log
// cannot be written, the operation is aborted (the error is returned). For reads, callers log
// *before* revealing the secret, so a secret that cannot be audited is never disclosed.
//
// Set ARCA_STRICT_AUDIT to a falsey value (0/false/off/no) to opt into best-effort auditing,
// where a failed audit write is swallowed and never breaks the operation.
func logAudit(op, name, caller string) error {
	if err := recordAudit(op, name, caller); err != nil {
		if strictAudit() {
			return fmt.Errorf("audit failed (fail-closed; set ARCA_STRICT_AUDIT=0 to override): %w", err)
		}
		// best-effort: swallow
	}
	return nil
}

// recordAudit opens the audit log and writes one event with the auto-detected identity.
func recordAudit(op, name, caller string) error {
	a, err := audit.Open(auditPath())
	if err != nil {
		return err
	}
	defer a.Close()
	return a.Record(op, name, caller, detectIdentity())
}

// strictAudit reports whether fail-closed auditing is in effect. It is the DEFAULT; set
// ARCA_STRICT_AUDIT to a falsey value (0/false/off/no/lax) to opt into best-effort auditing.
func strictAudit() bool {
	switch strings.ToLower(os.Getenv("ARCA_STRICT_AUDIT")) {
	case "0", "false", "off", "no", "lax", "best-effort":
		return false
	}
	return true
}

// detectIdentity figures out who/what is accessing a secret: the explicit $ARCA_ACTOR plus an
// auto-detected AI agent (name, version, session) from well-known environment variables. This
// is what lets `arca log` attribute access to a specific agent session without the user
// having to configure anything.
func detectIdentity() audit.Identity {
	id := audit.Identity{Actor: os.Getenv("ARCA_ACTOR")}
	switch {
	case envSet("CLAUDECODE", "CLAUDE_CODE_SESSION_ID"):
		id.Agent = "claude-code"
		id.Session = os.Getenv("CLAUDE_CODE_SESSION_ID")
		// Claude Code's binary lives under .../<version>/claude, so the version falls out of
		// the exec path.
		id.Version = firstSemver(os.Getenv("CLAUDE_CODE_EXECPATH"))
	case envSet("CURSOR_TRACE_ID"):
		id.Agent = "cursor"
		id.Session = os.Getenv("CURSOR_TRACE_ID")
	}
	// Generic fallback for other agents: AI_AGENT="name_version_agent"
	// (e.g. "claude-code_2-1-181_agent"); the version uses '-' for '.'.
	if id.Agent == "" {
		if ai := os.Getenv("AI_AGENT"); ai != "" {
			parts := strings.SplitN(ai, "_", 3)
			id.Agent = parts[0]
			if len(parts) > 1 {
				id.Version = strings.ReplaceAll(parts[1], "-", ".")
			}
		}
	}
	return id
}

// envSet reports whether any of the named environment variables is non-empty.
func envSet(keys ...string) bool {
	for _, k := range keys {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

var semverRe = regexp.MustCompile(`\d+\.\d+\.\d+`)

// firstSemver pulls the first "X.Y.Z" out of s (e.g. a version embedded in a path), or "".
func firstSemver(s string) string { return semverRe.FindString(s) }

// shortID truncates long ids (e.g. session UUIDs) for compact table display.
func shortID(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// readValue reads a secret from a TTY without echo, or from piped stdin. Secrets are NEVER
// taken as command-line arguments (which would leak via shell history / `ps`).
func readValue(prompt string) ([]byte, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, prompt)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return b, err
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, err
	}
	// Strip a single trailing newline (from `echo`/editors) but preserve internal newlines,
	// so multi-line secrets like PEM keys round-trip intact.
	return []byte(strings.TrimRight(string(b), "\r\n")), nil
}

func contains(ss []string, x string) bool {
	for _, s := range ss {
		if s == x {
			return true
		}
	}
	return false
}

// shellQuote single-quotes a value for safe `eval` in a POSIX shell (used by `env`).
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// approve enforces a per-secret human approval gate before a value is released.
//
// ARCA_APPROVAL=allow|deny short-circuits the prompt (for trusted automation, tests, or
// MCP-mediated approval). Otherwise it prompts on the controlling terminal (/dev/tty, so it
// works even when stdin is piped). With no override and no terminal, access is DENIED — an
// agent can't self-approve.
func approve(name, who string) error {
	switch strings.ToLower(os.Getenv("ARCA_APPROVAL")) {
	case "allow", "yes", "1", "approve":
		return nil
	case "deny", "no", "0":
		return fmt.Errorf("approval denied for %s", name)
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("%s requires approval, but no terminal is available to confirm", name)
	}
	defer tty.Close()
	fmt.Fprintf(tty, "Release %q to %s? [y/N] ", name, who)
	var resp string
	fmt.Fscanln(tty, &resp)
	if strings.EqualFold(strings.TrimSpace(resp), "y") {
		return nil
	}
	return fmt.Errorf("approval declined for %s", name)
}

// approverWho returns a short human-readable descriptor of the requester for the prompt.
func approverWho() string {
	id := detectIdentity()
	switch {
	case id.Agent != "":
		w := id.Agent
		if id.Version != "" {
			w += "/" + id.Version
		}
		if id.Session != "" {
			w += " (" + shortID(id.Session) + ")"
		}
		return w
	case id.Actor != "":
		return id.Actor
	}
	return "this process"
}

// gate runs the approval check for a secret if it requires one. A no-op otherwise.
func gate(sec *store.Secret, name string) error {
	// Hard expiry is checked first: an expired secret is refused on every access path
	// (get / inject / exec / env / MCP), before any approval prompt or decryption.
	if sec.Expired(time.Now()) {
		return fmt.Errorf("%s expired at %s", name, sec.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if sec.RequireApproval {
		return approve(name, approverWho())
	}
	return nil
}

// parseTTL parses a relative duration for --ttl. It extends Go's time.ParseDuration (ns…h)
// with 'd' (days) and 'w' (weeks) suffixes, the units people actually reach for with secrets.
func parseTTL(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if n := len(s); n >= 2 {
		switch s[n-1] {
		case 'd', 'w':
			num, err := strconv.ParseFloat(s[:n-1], 64)
			if err != nil {
				return 0, fmt.Errorf("invalid duration %q", s)
			}
			hours := 24.0
			if s[n-1] == 'w' {
				hours = 24 * 7
			}
			return time.Duration(num * hours * float64(time.Hour)), nil
		}
	}
	return time.ParseDuration(s)
}

// applyExpiry sets sec.ExpiresAt from the mutually-exclusive --ttl (relative) and
// --expires-at (absolute RFC3339 or YYYY-MM-DD) flags. It is a no-op when neither is given,
// so re-setting a secret without the flags preserves any existing expiry.
func applyExpiry(sec *store.Secret, ttl, expiresAt string) error {
	switch {
	case ttl != "" && expiresAt != "":
		return fmt.Errorf("use either --ttl or --expires-at, not both")
	case ttl != "":
		d, err := parseTTL(ttl)
		if err != nil {
			return fmt.Errorf("ttl: %w", err)
		}
		if d <= 0 {
			return fmt.Errorf("ttl must be positive")
		}
		t := time.Now().UTC().Add(d)
		sec.ExpiresAt = &t
	case expiresAt != "":
		t, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			if t, err = time.Parse("2006-01-02", expiresAt); err != nil {
				return fmt.Errorf("expires-at: want RFC3339 or YYYY-MM-DD, got %q", expiresAt)
			}
		}
		t = t.UTC()
		sec.ExpiresAt = &t
	}
	return nil
}

// ----------------------------------------------------------------------------
// Commands.
// ----------------------------------------------------------------------------

// newInit creates the store, deriving the recipient from the caller's existing age key (or
// generating one if none exists). It refuses to clobber an existing store without --force.
func newInit() *cobra.Command {
	var force bool
	c := &cobra.Command{
		Use:   "init",
		Short: "Initialize the store (reuses $SOPS_AGE_KEY_FILE or generates an identity)",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if _, err := os.Stat(storePath()); err == nil && !force {
				return fmt.Errorf("store already exists at %s (use --force)", storePath())
			}
			idPath := identityPath()
			var recips []string
			if _, err := os.Stat(idPath); err == nil {
				// Reuse the existing identity (e.g. the sops age key).
				ids, err := crypto.LoadIdentities(idPath)
				if err != nil {
					return err
				}
				if recips, err = crypto.RecipientsFromIdentities(ids); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "using identity %s\n", idPath)
			} else {
				// No key yet: generate one and persist it 0600.
				idStr, rec, err := crypto.GenerateIdentity()
				if err != nil {
					return err
				}
				if err := os.MkdirAll(filepath.Dir(idPath), 0o700); err != nil {
					return err
				}
				if err := os.WriteFile(idPath, []byte(idStr+"\n"), 0o600); err != nil {
					return err
				}
				recips = []string{rec}
				fmt.Fprintf(os.Stderr, "generated new identity at %s\n", idPath)
			}
			if err := store.New(storePath(), recips).Save(); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "initialized store at %s\nrecipients: %s\n", storePath(), strings.Join(recips, ", "))
			return nil
		},
	}
	c.Flags().BoolVar(&force, "force", false, "overwrite an existing store")
	return c
}

// newSet adds or updates a secret. The value comes from a TTY/stdin (never an arg). On an
// existing secret it preserves CreatedAt and only touches the fields the user supplied.
func newSet() *cobra.Command {
	var tags []string
	var desc, rotate, ttl, expiresAt string
	var meta map[string]string
	var noPrint, requireApproval bool
	c := &cobra.Command{
		Use:   "set NAME",
		Short: "Add or update a secret (value from TTY or stdin)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			s, err := openStore()
			if err != nil {
				return err
			}
			recips, err := crypto.ParseRecipients(s.Recipients)
			if err != nil {
				return err
			}
			val, err := readValue("Value: ")
			if err != nil {
				return err
			}
			armored, err := crypto.Encrypt(val, recips)
			if err != nil {
				return err
			}

			now := time.Now().UTC()
			sec := s.Secrets[name]
			if sec == nil { // new secret
				sec = &store.Secret{CreatedAt: now}
				s.Secrets[name] = sec
			}
			sec.Value = armored
			sec.UpdatedAt = now
			if len(tags) > 0 {
				sec.Tags = tags
			}
			if desc != "" {
				sec.Description = desc
			}
			if rotate != "" {
				t, err := time.Parse("2006-01-02", rotate)
				if err != nil {
					return fmt.Errorf("rotate-after: %w", err)
				}
				sec.RotateAfter = &t
			}
			if err := applyExpiry(sec, ttl, expiresAt); err != nil {
				return err
			}
			if len(meta) > 0 {
				if sec.Meta == nil {
					sec.Meta = map[string]string{}
				}
				for k, v := range meta {
					sec.Meta[k] = v
				}
			}
			// Only change the policy when the flag was actually given, so re-setting a secret
			// doesn't silently clear its no-print bit.
			if cmd.Flags().Changed("no-print") {
				sec.NoPrint = noPrint
			}
			if cmd.Flags().Changed("require-approval") {
				sec.RequireApproval = requireApproval
			}
			if err := s.Save(); err != nil {
				return err
			}
			if err := logAudit("set", name, ""); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "stored %s\n", name)
			return nil
		},
	}
	c.Flags().StringSliceVar(&tags, "tag", nil, "tags (repeatable or comma-separated)")
	c.Flags().StringVar(&desc, "desc", "", "description")
	c.Flags().StringVar(&rotate, "rotate-after", "", "rotation date (YYYY-MM-DD)")
	c.Flags().StringVar(&ttl, "ttl", "", "expire after a relative duration (e.g. 30m, 12h, 7d, 2w)")
	c.Flags().StringVar(&expiresAt, "expires-at", "", "expire at an absolute time (RFC3339 or YYYY-MM-DD)")
	c.Flags().StringToStringVar(&meta, "meta", nil, "extra metadata key=value (repeatable)")
	c.Flags().BoolVar(&noPrint, "no-print", false, "exec-only: get/env/inject refuse to reveal it")
	c.Flags().BoolVar(&requireApproval, "require-approval", false, "require human approval (TTY) before each release")
	return c
}

// newGet decrypts and prints one secret. It refuses --no-print secrets (the whole point of
// that flag is that the value must not reach stdout) and records a "read" in the audit log.
func newGet() *cobra.Command {
	var nl, noLog bool
	c := &cobra.Command{
		Use:   "get NAME",
		Short: "Decrypt and print one secret (records a read)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			s, err := openStore()
			if err != nil {
				return err
			}
			sec := s.Secrets[name]
			if sec == nil {
				return fmt.Errorf("no such secret: %s", name)
			}
			if sec.NoPrint {
				return fmt.Errorf("%s is marked --no-print; use `exec` instead", name)
			}
			if err := gate(sec, name); err != nil {
				return err
			}
			ids, err := loadIDs()
			if err != nil {
				return err
			}
			plain, err := crypto.Decrypt(sec.Value, ids)
			if err != nil {
				return fmt.Errorf("decrypt %s: %w", name, err)
			}
			// Log before revealing: under fail-closed auditing, a read that cannot be
			// recorded must not disclose the value.
			if !noLog {
				if err := logAudit("read", name, ""); err != nil {
					return err
				}
			}
			os.Stdout.Write(plain) // raw, no trailing newline unless -n
			if nl {
				fmt.Println()
			}
			return nil
		},
	}
	c.Flags().BoolVarP(&nl, "newline", "n", false, "append a trailing newline")
	c.Flags().BoolVar(&noLog, "no-log", false, "do not record this read")
	return c
}

// newLs lists secrets and their metadata. It never decrypts; with --reads it joins the audit
// DB for last-read/count, which is why that data lives outside the store.
func newLs() *cobra.Command {
	var tag string
	var reads, jsonOut bool
	c := &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List secrets and metadata (no decryption)",
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			var a *audit.Log
			if reads || jsonOut { // --json always enriches with last-read when available
				if a, err = audit.Open(auditPath()); err == nil {
					defer a.Close()
				}
			}
			if jsonOut {
				views := []secretView{}
				for _, name := range s.Names() {
					sec := s.Secrets[name]
					if tag != "" && !contains(sec.Tags, tag) {
						continue
					}
					var lr time.Time
					var cnt int
					if a != nil {
						lr, cnt, _ = a.LastRead(name)
					}
					views = append(views, viewOf(name, sec, lr, cnt))
				}
				return emitJSON(views)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			defer w.Flush()
			if reads {
				fmt.Fprintln(w, "NAME\tTAGS\tUPDATED\tLAST READ\tREADS\tDESCRIPTION")
			} else {
				fmt.Fprintln(w, "NAME\tTAGS\tUPDATED\tDESCRIPTION")
			}
			for _, name := range s.Names() {
				sec := s.Secrets[name]
				if tag != "" && !contains(sec.Tags, tag) {
					continue
				}
				if reads && a != nil {
					lr, cnt, _ := a.LastRead(name)
					lrs := "never"
					if !lr.IsZero() {
						lrs = lr.Local().Format("2006-01-02 15:04")
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
						name, strings.Join(sec.Tags, ","), sec.UpdatedAt.Local().Format("2006-01-02"), lrs, cnt, sec.Description)
				} else {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
						name, strings.Join(sec.Tags, ","), sec.UpdatedAt.Local().Format("2006-01-02"), sec.Description)
				}
			}
			return nil
		},
	}
	c.Flags().StringVar(&tag, "tag", "", "filter by tag")
	c.Flags().BoolVar(&reads, "reads", false, "include last-read / read-count from the audit log")
	c.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return c
}

// newShow prints one secret's metadata (never the value), enriched with last-read info from
// the audit DB.
func newShow() *cobra.Command {
	var jsonOut bool
	c := &cobra.Command{
		Use:   "show NAME",
		Short: "Show metadata for a secret (no decryption)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			s, err := openStore()
			if err != nil {
				return err
			}
			sec := s.Secrets[name]
			if sec == nil {
				return fmt.Errorf("no such secret: %s", name)
			}
			var lr time.Time
			var cnt int
			if a, err := audit.Open(auditPath()); err == nil {
				lr, cnt, _ = a.LastRead(name)
				a.Close()
			}
			if jsonOut {
				return emitJSON(viewOf(name, sec, lr, cnt))
			}
			fmt.Printf("name:         %s\n", name)
			fmt.Printf("created:      %s\n", sec.CreatedAt.Local().Format(time.RFC3339))
			fmt.Printf("updated:      %s\n", sec.UpdatedAt.Local().Format(time.RFC3339))
			if lr.IsZero() {
				fmt.Printf("last read:    never\n")
			} else {
				fmt.Printf("last read:    %s (%d total)\n", lr.Local().Format(time.RFC3339), cnt)
			}
			if sec.NoPrint {
				fmt.Printf("policy:       no-print (exec-only)\n")
			}
			if sec.RequireApproval {
				fmt.Printf("policy:       requires approval\n")
			}
			if len(sec.Tags) > 0 {
				fmt.Printf("tags:         %s\n", strings.Join(sec.Tags, ", "))
			}
			if sec.Description != "" {
				fmt.Printf("description:  %s\n", sec.Description)
			}
			if sec.RotateAfter != nil {
				fmt.Printf("rotate after: %s\n", sec.RotateAfter.Format("2006-01-02"))
			}
			if sec.ExpiresAt != nil {
				state := "valid"
				if sec.Expired(time.Now()) {
					state = "EXPIRED"
				}
				fmt.Printf("expires:      %s (%s)\n", sec.ExpiresAt.Local().Format(time.RFC3339), state)
			}
			for k, v := range sec.Meta {
				fmt.Printf("meta.%s: %s\n", k, v)
			}
			return nil
		},
	}
	c.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return c
}

// newRm deletes a secret from the store and logs the removal.
func newRm() *cobra.Command {
	return &cobra.Command{
		Use:     "rm NAME",
		Aliases: []string{"remove"},
		Short:   "Remove a secret",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			s, err := openStore()
			if err != nil {
				return err
			}
			if _, ok := s.Secrets[name]; !ok {
				return fmt.Errorf("no such secret: %s", name)
			}
			delete(s.Secrets, name)
			if err := s.Save(); err != nil {
				return err
			}
			if err := logAudit("rm", name, ""); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "removed %s\n", name)
			return nil
		},
	}
}

// newImport reads dotenv-style KEY=value lines from stdin and stores each, e.g. to migrate
// from a sops file: `sops -d secrets.env | arca import`.
func newImport() *cobra.Command {
	return &cobra.Command{
		Use:   "import",
		Short: "Import KEY=value (dotenv) lines from stdin",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			recips, err := crypto.ParseRecipients(s.Recipients)
			if err != nil {
				return err
			}
			sc := bufio.NewScanner(os.Stdin)
			sc.Buffer(make([]byte, 1<<20), 1<<20) // allow long values (up to 1 MiB/line)
			now := time.Now().UTC()
			n := 0
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				line = strings.TrimPrefix(line, "export ")
				k, v, ok := strings.Cut(line, "=")
				if !ok {
					continue
				}
				k = strings.TrimSpace(k)
				v = strings.Trim(strings.TrimSpace(v), `"'`) // drop surrounding quotes
				armored, err := crypto.Encrypt([]byte(v), recips)
				if err != nil {
					return err
				}
				sec := s.Secrets[k]
				if sec == nil {
					sec = &store.Secret{CreatedAt: now}
					s.Secrets[k] = sec
				}
				sec.Value = armored
				sec.UpdatedAt = now
				n++
			}
			if err := sc.Err(); err != nil {
				return err
			}
			if err := s.Save(); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "imported %d secret(s)\n", n)
			return nil
		},
	}
}

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
			data, err := io.ReadAll(os.Stdin)
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
				if err := gate(sec, name); err != nil {
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
			caller := filepath.Base(args[0]) // recorded as the audit "caller"
			env := os.Environ()
			for _, name := range names {
				sec := s.Secrets[name]
				if sec == nil {
					return fmt.Errorf("no such secret: %s", name)
				}
				if err := gate(sec, name); err != nil {
					return err
				}
				plain, err := crypto.Decrypt(sec.Value, ids)
				if err != nil {
					return fmt.Errorf("decrypt %s: %w", name, err)
				}
				env = append(env, name+"="+string(plain))
				if err := logAudit("exec", name, caller); err != nil {
					return err
				}
			}
			cmd := exec.Command(args[0], args[1:]...)
			cmd.Env = env
			cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
			if err := cmd.Run(); err != nil {
				// Propagate the child's exit code so `arca exec -- foo` behaves like `foo`.
				if ee, ok := err.(*exec.ExitError); ok {
					os.Exit(ee.ExitCode())
				}
				return err
			}
			return nil
		},
	}
	c.Flags().StringSliceVar(&only, "only", nil, "subset of secrets to inject (default: all)")
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
				if s.Secrets[name].NoPrint {
					fmt.Fprintf(os.Stderr, "skip %s (--no-print)\n", name)
					continue
				}
				if err := gate(s.Secrets[name], name); err != nil {
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

// newLog prints the access history, including the attributed AI agent and session.
func newLog() *cobra.Command {
	var limit int
	var jsonOut bool
	c := &cobra.Command{
		Use:   "log [NAME]",
		Short: "Show access history",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := ""
			if len(args) > 0 {
				name = args[0]
			}
			a, err := audit.Open(auditPath())
			if err != nil {
				return err
			}
			defer a.Close()
			evs, err := a.Recent(name, limit)
			if err != nil {
				return err
			}
			if jsonOut {
				views := []eventView{}
				for _, e := range evs {
					views = append(views, eventView{
						Time: e.TS, Op: e.Op, Name: e.Name, Agent: e.Agent,
						Version: e.Version, Session: e.Session, Actor: e.Actor, Caller: e.Caller,
					})
				}
				return emitJSON(views)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			defer w.Flush()
			fmt.Fprintln(w, "TIME\tOP\tNAME\tAGENT\tSESSION\tACTOR\tCALLER")
			for _, e := range evs {
				agent := e.Agent
				if e.Version != "" {
					agent += "/" + e.Version
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					e.TS.Local().Format("2006-01-02 15:04:05"), e.Op, e.Name, agent, shortID(e.Session), e.Actor, e.Caller)
			}
			return nil
		},
	}
	c.Flags().IntVar(&limit, "limit", 50, "max events")
	c.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return c
}

// newRotate replaces an existing secret's value while preserving CreatedAt, and logs the
// change as a distinct "rotate" event (vs the initial "set"). Optionally advances the next
// rotation date.
func newRotate() *cobra.Command {
	var rotate, ttl, expiresAt string
	c := &cobra.Command{
		Use:   "rotate NAME",
		Short: "Replace an existing secret's value (keeps created_at; logs a rotation)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			s, err := openStore()
			if err != nil {
				return err
			}
			sec := s.Secrets[name]
			if sec == nil {
				return fmt.Errorf("no such secret: %s (use `set` to create)", name)
			}
			recips, err := crypto.ParseRecipients(s.Recipients)
			if err != nil {
				return err
			}
			val, err := readValue("New value: ")
			if err != nil {
				return err
			}
			armored, err := crypto.Encrypt(val, recips)
			if err != nil {
				return err
			}
			sec.Value = armored
			sec.UpdatedAt = time.Now().UTC()
			if rotate != "" {
				t, err := time.Parse("2006-01-02", rotate)
				if err != nil {
					return fmt.Errorf("rotate-after: %w", err)
				}
				sec.RotateAfter = &t
			}
			if err := applyExpiry(sec, ttl, expiresAt); err != nil {
				return err
			}
			if err := s.Save(); err != nil {
				return err
			}
			if err := logAudit("rotate", name, ""); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "rotated %s\n", name)
			return nil
		},
	}
	c.Flags().StringVar(&rotate, "rotate-after", "", "set the next rotation date (YYYY-MM-DD)")
	c.Flags().StringVar(&ttl, "ttl", "", "refresh expiry to a relative duration (e.g. 30m, 12h, 7d, 2w)")
	c.Flags().StringVar(&expiresAt, "expires-at", "", "refresh expiry to an absolute time (RFC3339 or YYYY-MM-DD)")
	return c
}

// newStale lists secrets due for rotation: those whose rotate_after is in the past (or within
// --within days). With --missing it instead lists secrets that have no rotation policy at all.
func newStale() *cobra.Command {
	var within int
	var missing, jsonOut bool
	c := &cobra.Command{
		Use:   "stale",
		Short: "List secrets due for rotation (rotate_after past, or within --within days)",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			now := time.Now()
			w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			defer w.Flush()

			if missing {
				views := []secretView{}
				if !jsonOut {
					fmt.Fprintln(w, "NAME\tTAGS\tUPDATED")
				}
				for _, name := range s.Names() {
					sec := s.Secrets[name]
					if sec.RotateAfter != nil {
						continue
					}
					if jsonOut {
						views = append(views, viewOf(name, sec, time.Time{}, 0))
					} else {
						fmt.Fprintf(w, "%s\t%s\t%s\n", name, strings.Join(sec.Tags, ","), sec.UpdatedAt.Local().Format("2006-01-02"))
					}
				}
				if jsonOut {
					return emitJSON(views)
				}
				return nil
			}

			// cutoff = now (+within days): surface anything whose rotation is due or whose hard
			// expiry falls on or before it. With the default --within 0 that means overdue
			// rotations and already-expired secrets; a larger window looks ahead.
			cutoff := now.AddDate(0, 0, within)
			views := []staleView{}
			if !jsonOut {
				fmt.Fprintln(w, "NAME\tROTATE AFTER\tEXPIRES\tSTATUS")
			}
			for _, name := range s.Names() {
				sec := s.Secrets[name]
				rotDue := sec.RotateAfter != nil && !sec.RotateAfter.After(cutoff)
				expSoon := sec.ExpiresAt != nil && !sec.ExpiresAt.After(cutoff)
				if !rotDue && !expSoon {
					continue
				}
				ra, ex := "-", "-"
				var status []string
				if rotDue {
					ra = sec.RotateAfter.Format("2006-01-02")
					days := int(now.Sub(*sec.RotateAfter).Hours() / 24)
					if days < 0 { // due in the future but within the window
						status = append(status, fmt.Sprintf("rotate in %dd", -days))
					} else {
						status = append(status, fmt.Sprintf("%dd overdue", days))
					}
				}
				if expSoon {
					ex = sec.ExpiresAt.Local().Format("2006-01-02 15:04")
					if now.After(*sec.ExpiresAt) {
						status = append(status, "EXPIRED")
					} else {
						status = append(status, "expiring")
					}
				}
				if jsonOut {
					views = append(views, staleView{Name: name, RotateAfter: sec.RotateAfter, ExpiresAt: sec.ExpiresAt, Status: status})
				} else {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", name, ra, ex, strings.Join(status, ", "))
				}
			}
			if jsonOut {
				return emitJSON(views)
			}
			return nil
		},
	}
	c.Flags().IntVar(&within, "within", 0, "also include secrets due within N days")
	c.Flags().BoolVar(&missing, "missing", false, "instead, list secrets with no rotation policy")
	c.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return c
}
