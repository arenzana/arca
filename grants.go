package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/arenzana/arca/internal/audit"
)

// A Grant is a just-in-time, command-scoped authorization to use a `--require-grant` secret: an
// agent may use secret S, optionally only for a command matching a pattern, at most N times, until
// it expires. Grants are local operational state (like the audit DB and session keys), so they
// live in a JSON file under the state dir, not the git-synced store.
//
// Use counting is derived from the tamper-evident audit log (how many `exec` events for the secret
// since the grant was issued) rather than mutated on the grant, so it can't be rolled back and
// there's no write race to lose.
type Grant struct {
	Secret    string    `json:"secret"`
	Agent     string    `json:"agent,omitempty"`    // "" = any agent
	Command   string    `json:"command,omitempty"`  // glob against the command line; "" = any command
	MaxUses   int       `json:"max_uses,omitempty"` // 0 = unlimited
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type grantFile struct {
	Grants map[string]Grant `json:"grants"` // keyed by secret name; one active grant per secret
}

func grantsPath() string { return filepath.Join(stateDir(), "grants.json") }

func loadGrants() (map[string]Grant, error) {
	b, err := os.ReadFile(grantsPath()) //#nosec G304 -- path derives from the operator's state dir, not untrusted input
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]Grant{}, nil
		}
		return nil, err
	}
	var gf grantFile
	if err := json.Unmarshal(b, &gf); err != nil {
		return nil, fmt.Errorf("parse grants: %w", err)
	}
	if gf.Grants == nil {
		gf.Grants = map[string]Grant{}
	}
	return gf.Grants, nil
}

func saveGrants(g map[string]Grant) error {
	if err := os.MkdirAll(filepath.Dir(grantsPath()), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(grantFile{Grants: g}, "", "  ")
	if err != nil {
		return err
	}
	tmp := grantsPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil { //#nosec G304 -- operator state dir
		return err
	}
	return os.Rename(tmp, grantsPath())
}

// globMatch reports whether s matches pattern, where '*' is a wildcard for any run of characters.
// It's a deliberately simple matcher for command lines (no path semantics).
func globMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(s, mid)
		if i < 0 {
			return false
		}
		s = s[i+len(mid):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}

// checkGrant authorizes using a require-grant secret for a given command line, or returns why not.
// It is the JIT/command-scoped enforcement point, called only from the command-bearing paths
// (exec, MCP run_with_secrets). Matching is argv-based and therefore a guardrail expressing intent,
// not a sandbox (an agent controls argv); the agent/uses/expiry checks are firm.
func checkGrant(name, cmdline string) error {
	grants, err := loadGrants()
	if err != nil {
		return err
	}
	g, ok := grants[name]
	if !ok {
		return fmt.Errorf("%s requires a grant, but none is active (issue one with: arca grant %s --command '…' --uses N --ttl 15m)", name, name)
	}
	if time.Now().After(g.ExpiresAt) {
		return fmt.Errorf("the grant for %s expired at %s", name, g.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if g.Agent != "" {
		if a := detectIdentity().Agent; a != g.Agent {
			return fmt.Errorf("the grant for %s is restricted to agent %q (caller is %q)", name, g.Agent, a)
		}
	}
	if g.Command != "" && !globMatch(g.Command, cmdline) {
		return fmt.Errorf("the grant for %s does not authorize this command (allowed pattern: %q)", name, g.Command)
	}
	if g.MaxUses > 0 {
		used, err := grantUses(name, g.CreatedAt)
		if err != nil {
			return err
		}
		if used >= g.MaxUses {
			return fmt.Errorf("the grant for %s is exhausted (%d of %d uses)", name, used, g.MaxUses)
		}
	}
	return nil
}

// grantUses counts how many times the secret has been used via exec since the grant was issued.
func grantUses(name string, since time.Time) (int, error) {
	a, err := audit.Open(auditPath())
	if err != nil {
		return 0, err
	}
	defer a.Close()
	return a.CountOpSince(name, "exec", since)
}

func newGrant() *cobra.Command {
	var command, ttl, agent string
	var uses int
	c := &cobra.Command{
		Use:   "grant SECRET",
		Short: "Authorize a require-grant secret for a command, a number of uses, and a time window",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			if err := validName(name); err != nil {
				return err
			}
			if ttl == "" {
				return fmt.Errorf("a grant must be time-bounded; pass --ttl (e.g. 15m, 2h)")
			}
			d, err := parseTTL(ttl)
			if err != nil {
				return err
			}
			now := time.Now().UTC()

			// Warn (don't fail) if the secret isn't actually gated on grants — the grant is inert
			// until the secret is marked --require-grant.
			if s, err := openStore(); err == nil {
				if sec := s.Secrets[name]; sec == nil {
					fmt.Fprintf(os.Stderr, "note: no secret named %q yet; the grant will apply once it exists\n", name)
				} else if !sec.RequireGrant {
					fmt.Fprintf(os.Stderr, "note: %q is not marked --require-grant, so this grant has no effect until it is\n", name)
				}
			}

			grants, err := loadGrants()
			if err != nil {
				return err
			}
			grants[name] = Grant{
				Secret: name, Agent: agent, Command: command, MaxUses: uses,
				ExpiresAt: now.Add(d), CreatedAt: now,
			}
			if err := saveGrants(grants); err != nil {
				return err
			}
			if err := logAudit("grant", name, ""); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "granted %s until %s\n", name, now.Add(d).Local().Format("2006-01-02 15:04:05"))
			return nil
		},
	}
	c.Flags().StringVar(&command, "command", "", "only authorize a command line matching this glob (e.g. 'terraform *')")
	c.Flags().IntVar(&uses, "uses", 0, "maximum number of uses (0 = unlimited within the window)")
	c.Flags().StringVar(&ttl, "ttl", "", "how long the grant is valid (e.g. 15m, 2h, 1d) — required")
	c.Flags().StringVar(&agent, "agent", "", "restrict to a specific detected agent (e.g. claude-code)")
	return c
}

func newRevoke() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke SECRET",
		Short: "Remove the active grant for a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			grants, err := loadGrants()
			if err != nil {
				return err
			}
			if _, ok := grants[name]; !ok {
				return fmt.Errorf("no active grant for %s", name)
			}
			delete(grants, name)
			if err := saveGrants(grants); err != nil {
				return err
			}
			if err := logAudit("revoke", name, ""); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "revoked the grant for %s\n", name)
			return nil
		},
	}
}

func newGrants() *cobra.Command {
	return &cobra.Command{
		Use:   "grants",
		Short: "List active grants and their remaining uses",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			grants, err := loadGrants()
			if err != nil {
				return err
			}
			if len(grants) == 0 {
				fmt.Fprintln(os.Stderr, "no active grants")
				return nil
			}
			names := make([]string, 0, len(grants))
			for n := range grants {
				names = append(names, n)
			}
			sort.Strings(names)

			now := time.Now()
			rows := make([][]string, 0, len(names))
			for _, n := range names {
				g := grants[n]
				agent, command := g.Agent, g.Command
				if agent == "" {
					agent = "any"
				}
				if command == "" {
					command = "any"
				}
				uses := "unlimited"
				if g.MaxUses > 0 {
					used, _ := grantUses(n, g.CreatedAt)
					uses = fmt.Sprintf("%d/%d", used, g.MaxUses)
				}
				expires := g.ExpiresAt.Local().Format("2006-01-02 15:04:05")
				if now.After(g.ExpiresAt) {
					expires += " (expired)"
				}
				rows = append(rows, []string{n, agent, command, uses, expires})
			}
			renderTable([]string{"SECRET", "AGENT", "COMMAND", "USES", "EXPIRES"}, rows)
			return nil
		},
	}
}
