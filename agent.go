// Safer agent defaults. The MCP server (mcp.go) historically exposed EVERY secret to a connected
// AI agent, with the per-secret guards (--no-print, --require-approval, --require-grant) all opt-in.
// This flips the model to deny-by-default under --strict: only secrets explicitly marked
// agent-exposed (`arca agent allow NAME`) are visible or usable to an agent.
//
// Rollout is warn-then-flip: today --strict is opt-in and the default still exposes everything but
// prints a loud notice (and `doctor` flags it). A future major makes --strict the default.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// mcpStrictFlag is set by `arca mcp --strict`. agentStrict() also honours ARCA_AGENT_STRICT so the
// mode can be enabled without editing the MCP launch command (e.g. from an agent-runner's env).
var mcpStrictFlag bool

func agentStrict() bool {
	if mcpStrictFlag {
		return true
	}
	switch strings.ToLower(os.Getenv("ARCA_AGENT_STRICT")) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// agentDenied reports whether, under strict mode, the named secret is off-limits to an agent because
// it hasn't been explicitly exposed. In non-strict mode nothing is denied (legacy behavior).
func agentDenied(exposed bool) bool { return agentStrict() && !exposed }

const agentDenyHint = "not exposed to agents; the operator must run `arca agent allow %s` (or start the server without --strict)"

func newAgent() *cobra.Command {
	c := &cobra.Command{
		Use:   "agent",
		Short: "Control which secrets the MCP server exposes to AI agents",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	c.AddCommand(newAgentAllow(), newAgentDeny(), newAgentLs())
	return c
}

// setAgentExposed flips the flag on one secret and persists + audits it.
func setAgentExposed(name string, exposed bool, op string) error {
	unlock, err := lockStore()
	if err != nil {
		return err
	}
	defer unlock()
	s, err := openStore()
	if err != nil {
		return err
	}
	sec := s.Secrets[name]
	if sec == nil {
		return fmt.Errorf("no such secret: %s", name)
	}
	sec.AgentExposed = exposed
	if err := s.Save(); err != nil {
		return err
	}
	return logAudit(op, name, "")
}

func newAgentAllow() *cobra.Command {
	return &cobra.Command{
		Use:   "allow NAME",
		Short: "Expose a secret to AI agents (visible/usable via the MCP server under --strict)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := setAgentExposed(args[0], true, "agent-allow"); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "%s is now exposed to agents (revoke with `arca agent deny %s`)\n", args[0], args[0])
			return nil
		},
	}
}

func newAgentDeny() *cobra.Command {
	return &cobra.Command{
		Use:   "deny NAME",
		Short: "Stop exposing a secret to AI agents",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := setAgentExposed(args[0], false, "agent-deny"); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "%s is no longer exposed to agents\n", args[0])
			return nil
		},
	}
}

func newAgentLs() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List secrets currently exposed to AI agents",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			n := 0
			for _, name := range s.Names() {
				if s.Secrets[name].AgentExposed {
					fmt.Println(sanitize(name))
					n++
				}
			}
			if n == 0 {
				fmt.Fprintln(os.Stderr, "no secrets are exposed to agents; under a --strict MCP server an agent sees nothing until you `arca agent allow NAME`")
			}
			return nil
		},
	}
}
