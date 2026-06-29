// arca — an age-encrypted secret store with cleartext metadata and a local audit log.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	if err := newRoot().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "arca",
		Short:         "age-encrypted secrets with metadata and an audit log",
		Long:          "arca stores secrets as age-encrypted values with cleartext metadata in a JSON\nstore, and records every access in a local SQLite audit log.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(
		newInit(), newSet(), newGet(), newRotate(), newLs(), newShow(), newStale(),
		newRm(), newImport(), newExec(), newEnv(), newLog(),
	)
	return root
}

// ---- paths -----------------------------------------------------------------

func xdgHome(env, def string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, def)
}

func configDir() string { return filepath.Join(xdgHome("XDG_CONFIG_HOME", ".config"), "arca") }
func stateDir() string  { return filepath.Join(xdgHome("XDG_STATE_HOME", ".local/state"), "arca") }

func storePath() string {
	if p := os.Getenv("ARCA_STORE"); p != "" {
		return p
	}
	return filepath.Join(configDir(), "store.json")
}

func auditPath() string {
	if p := os.Getenv("ARCA_AUDIT"); p != "" {
		return p
	}
	return filepath.Join(stateDir(), "audit.db")
}

func identityPath() string {
	if p := os.Getenv("ARCA_IDENTITY"); p != "" {
		return p
	}
	if p := os.Getenv("SOPS_AGE_KEY_FILE"); p != "" {
		return p
	}
	return filepath.Join(configDir(), "identity.txt")
}

// ---- helpers ---------------------------------------------------------------

func openStore() (*store.Store, error) { return store.Load(storePath()) }
func loadIDs() ([]age.Identity, error) { return crypto.LoadIdentities(identityPath()) }

func logAudit(op, name, caller string) {
	a, err := audit.Open(auditPath())
	if err != nil {
		return
	}
	defer a.Close()
	_ = a.Record(op, name, caller, detectIdentity())
}

// detectIdentity figures out who/what is accessing a secret: the explicit $ARCA_ACTOR plus an
// auto-detected AI agent (name, version, session) from well-known environment variables.
func detectIdentity() audit.Identity {
	id := audit.Identity{Actor: os.Getenv("ARCA_ACTOR")}
	switch {
	case envSet("CLAUDECODE", "CLAUDE_CODE_SESSION_ID"):
		id.Agent = "claude-code"
		id.Session = os.Getenv("CLAUDE_CODE_SESSION_ID")
		id.Version = firstSemver(os.Getenv("CLAUDE_CODE_EXECPATH"))
	case envSet("CURSOR_TRACE_ID"):
		id.Agent = "cursor"
		id.Session = os.Getenv("CURSOR_TRACE_ID")
	}
	// Generic fallback: AI_AGENT="name_version_agent" (e.g. claude-code_2-1-181_agent).
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

func envSet(keys ...string) bool {
	for _, k := range keys {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

var semverRe = regexp.MustCompile(`\d+\.\d+\.\d+`)

func firstSemver(s string) string { return semverRe.FindString(s) }

func shortID(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// readValue reads a secret from a TTY (no echo) or from piped stdin.
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

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// ---- commands --------------------------------------------------------------

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
				ids, err := crypto.LoadIdentities(idPath)
				if err != nil {
					return err
				}
				if recips, err = crypto.RecipientsFromIdentities(ids); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "using identity %s\n", idPath)
			} else {
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

func newSet() *cobra.Command {
	var tags []string
	var desc, rotate string
	var meta map[string]string
	c := &cobra.Command{
		Use:   "set NAME",
		Short: "Add or update a secret (value from TTY or stdin)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
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
			if sec == nil {
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
			if len(meta) > 0 {
				if sec.Meta == nil {
					sec.Meta = map[string]string{}
				}
				for k, v := range meta {
					sec.Meta[k] = v
				}
			}
			if err := s.Save(); err != nil {
				return err
			}
			logAudit("set", name, "")
			fmt.Fprintf(os.Stderr, "stored %s\n", name)
			return nil
		},
	}
	c.Flags().StringSliceVar(&tags, "tag", nil, "tags (repeatable or comma-separated)")
	c.Flags().StringVar(&desc, "desc", "", "description")
	c.Flags().StringVar(&rotate, "rotate-after", "", "rotation date (YYYY-MM-DD)")
	c.Flags().StringToStringVar(&meta, "meta", nil, "extra metadata key=value (repeatable)")
	return c
}

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
			ids, err := loadIDs()
			if err != nil {
				return err
			}
			plain, err := crypto.Decrypt(sec.Value, ids)
			if err != nil {
				return fmt.Errorf("decrypt %s: %w", name, err)
			}
			os.Stdout.Write(plain)
			if nl {
				fmt.Println()
			}
			if !noLog {
				logAudit("read", name, "")
			}
			return nil
		},
	}
	c.Flags().BoolVarP(&nl, "newline", "n", false, "append a trailing newline")
	c.Flags().BoolVar(&noLog, "no-log", false, "do not record this read")
	return c
}

func newLs() *cobra.Command {
	var tag string
	var reads bool
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
			if reads {
				if a, err = audit.Open(auditPath()); err == nil {
					defer a.Close()
				}
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
	return c
}

func newShow() *cobra.Command {
	return &cobra.Command{
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
			fmt.Printf("name:         %s\n", name)
			fmt.Printf("created:      %s\n", sec.CreatedAt.Local().Format(time.RFC3339))
			fmt.Printf("updated:      %s\n", sec.UpdatedAt.Local().Format(time.RFC3339))
			if lr.IsZero() {
				fmt.Printf("last read:    never\n")
			} else {
				fmt.Printf("last read:    %s (%d total)\n", lr.Local().Format(time.RFC3339), cnt)
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
			for k, v := range sec.Meta {
				fmt.Printf("meta.%s: %s\n", k, v)
			}
			return nil
		},
	}
}

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
			logAudit("rm", name, "")
			fmt.Fprintf(os.Stderr, "removed %s\n", name)
			return nil
		},
	}
}

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
			sc.Buffer(make([]byte, 1<<20), 1<<20)
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
				v = strings.Trim(strings.TrimSpace(v), `"'`)
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
			if len(only) > 0 {
				names = only
			}
			caller := filepath.Base(args[0])
			env := os.Environ()
			for _, name := range names {
				sec := s.Secrets[name]
				if sec == nil {
					return fmt.Errorf("no such secret: %s", name)
				}
				plain, err := crypto.Decrypt(sec.Value, ids)
				if err != nil {
					return fmt.Errorf("decrypt %s: %w", name, err)
				}
				env = append(env, name+"="+string(plain))
				logAudit("exec", name, caller)
			}
			cmd := exec.Command(args[0], args[1:]...)
			cmd.Env = env
			cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
			if err := cmd.Run(); err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					os.Exit(ee.ExitCode())
				}
				return err
			}
			return nil
		},
	}
	c.Flags().StringSliceVar(&only, "only", nil, "subset of secrets to inject (default: all)")
	c.Flags().SetInterspersed(false) // arca flags before the command; everything after is the command
	return c
}

func newEnv() *cobra.Command {
	var noExport bool
	c := &cobra.Command{
		Use:   "env",
		Short: `Print shell assignments for eval "$(arca env)" (bulk; NOT per-read audited)`,
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
				plain, err := crypto.Decrypt(s.Secrets[name].Value, ids)
				if err != nil {
					return fmt.Errorf("decrypt %s: %w", name, err)
				}
				if noExport {
					fmt.Printf("%s=%s\n", name, shellQuote(string(plain)))
				} else {
					fmt.Printf("export %s=%s\n", name, shellQuote(string(plain)))
				}
				logAudit("env", name, "")
			}
			return nil
		},
	}
	c.Flags().BoolVar(&noExport, "no-export", false, "omit the leading 'export '")
	return c
}

func newLog() *cobra.Command {
	var limit int
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
	return c
}

func newRotate() *cobra.Command {
	var rotate string
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
			if err := s.Save(); err != nil {
				return err
			}
			logAudit("rotate", name, "")
			fmt.Fprintf(os.Stderr, "rotated %s\n", name)
			return nil
		},
	}
	c.Flags().StringVar(&rotate, "rotate-after", "", "set the next rotation date (YYYY-MM-DD)")
	return c
}

func newStale() *cobra.Command {
	var within int
	var missing bool
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
				fmt.Fprintln(w, "NAME\tTAGS\tUPDATED")
				for _, name := range s.Names() {
					sec := s.Secrets[name]
					if sec.RotateAfter == nil {
						fmt.Fprintf(w, "%s\t%s\t%s\n", name, strings.Join(sec.Tags, ","), sec.UpdatedAt.Local().Format("2006-01-02"))
					}
				}
				return nil
			}

			cutoff := now.AddDate(0, 0, within)
			fmt.Fprintln(w, "NAME\tROTATE AFTER\tSTATUS")
			for _, name := range s.Names() {
				sec := s.Secrets[name]
				if sec.RotateAfter == nil || sec.RotateAfter.After(cutoff) {
					continue
				}
				days := int(now.Sub(*sec.RotateAfter).Hours() / 24)
				status := fmt.Sprintf("%dd overdue", days)
				if days < 0 {
					status = fmt.Sprintf("due in %dd", -days)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", name, sec.RotateAfter.Format("2006-01-02"), status)
			}
			return nil
		},
	}
	c.Flags().IntVar(&within, "within", 0, "also include secrets due within N days")
	c.Flags().BoolVar(&missing, "missing", false, "instead, list secrets with no rotation policy")
	return c
}
