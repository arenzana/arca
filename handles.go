package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/spf13/cobra"
)

// A Handle is an opaque capability token for an AI agent: it lets the agent *use* a secret through
// MCP `run_with_handle` — inject it into a command — without ever learning the secret's name or
// value, and without being able to enumerate the store. It's the capability form of a reference:
// the agent holds `hdl_…`, arca holds the mapping. Handles are local operational state (like grants
// and session keys), so they live in a JSON file under the state dir, not the git-synced store.
type Handle struct {
	ID        string    `json:"id"`
	Secret    string    `json:"secret"`            // the real secret this handle unlocks
	EnvName   string    `json:"env_name"`          // env var the value is injected under
	Command   string    `json:"command,omitempty"` // glob the run command must match; "" = any
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

func handlesPath() string { return filepath.Join(stateDir(), "handles.json") }

type handleFile struct {
	Handles map[string]Handle `json:"handles"`
}

func loadHandles() (map[string]Handle, error) {
	b, err := os.ReadFile(handlesPath()) //#nosec G304 -- path derives from the operator's state dir
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]Handle{}, nil
		}
		return nil, err
	}
	var hf handleFile
	if err := json.Unmarshal(b, &hf); err != nil {
		return nil, fmt.Errorf("parse handles: %w", err)
	}
	if hf.Handles == nil {
		hf.Handles = map[string]Handle{}
	}
	return hf.Handles, nil
}

func saveHandles(h map[string]Handle) error {
	if err := os.MkdirAll(filepath.Dir(handlesPath()), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(handleFile{Handles: h}, "", "  ")
	if err != nil {
		return err
	}
	tmp := handlesPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil { //#nosec G304 -- operator state dir
		return err
	}
	return os.Rename(tmp, handlesPath())
}

func newHandleID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "hdl_" + hex.EncodeToString(b), nil
}

// resolveHandle validates a handle for a command line and returns it, or an opaque error the agent
// can't mine for information about the store.
func resolveHandle(id, cmdline string) (*Handle, error) {
	handles, err := loadHandles()
	if err != nil {
		return nil, err
	}
	h, ok := handles[id]
	if !ok {
		return nil, fmt.Errorf("unknown or revoked handle")
	}
	if time.Now().After(h.ExpiresAt) {
		return nil, fmt.Errorf("handle has expired")
	}
	if h.Command != "" && !globMatch(h.Command, cmdline) {
		return nil, fmt.Errorf("handle does not authorize this command")
	}
	return &h, nil
}

func newHandle() *cobra.Command {
	c := &cobra.Command{
		Use:   "handle",
		Short: "Mint and manage opaque capability handles for agents (create/ls/revoke)",
	}
	c.AddCommand(newHandleCreate(), newHandleLs(), newHandleRevoke())
	return c
}

func newHandleCreate() *cobra.Command {
	var ttl, command, as string
	var override bool
	c := &cobra.Command{
		Use:   "create SECRET",
		Short: "Mint a handle letting an agent use SECRET (via MCP run_with_handle) without its name or value",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			if err := validName(name); err != nil {
				return err
			}
			if ttl == "" {
				return fmt.Errorf("a handle must be time-bounded; pass --ttl (e.g. 1h)")
			}
			d, err := parseTTL(ttl)
			if err != nil {
				return err
			}
			// A handle is a bearer capability that lets its holder use the secret via
			// run_with_handle, which bypasses the grant/approval gates. Minting one is therefore a
			// privileged, operator-only act: a detected agent must not be able to mint a handle for
			// itself (that would let it self-issue the very authorization those gates withhold).
			// This mirrors the agent-can't-self-approve invariant (see approve()).
			if id := detectIdentity(); id.Agent != "" {
				return fmt.Errorf("refusing to mint a handle: %s looks like an AI agent, and handles are operator-issued capabilities", id.Agent)
			}
			s, err := openStore()
			if err != nil {
				return err
			}
			sec := s.Secrets[name]
			if sec == nil {
				return fmt.Errorf("no such secret: %s", name)
			}
			// run_with_handle bypasses grant/approval, so minting a handle for such a secret converts
			// "authorize/approve each use" into "approve once, use freely for the TTL". Make that an
			// explicit, audited operator decision rather than a silent laundering of the policy.
			if (sec.RequireApproval || sec.RequireGrant) && !override {
				var which string
				switch {
				case sec.RequireApproval && sec.RequireGrant:
					which = "--require-approval and --require-grant"
				case sec.RequireApproval:
					which = "--require-approval"
				default:
					which = "--require-grant"
				}
				return fmt.Errorf("%s is %s; a handle would bypass that per-use gate. Re-run with --override to accept this", name, which)
			}
			env := as
			if env == "" {
				env = name
			}
			if err := validName(env); err != nil {
				return fmt.Errorf("--as must be a valid env-var name: %w", err)
			}
			id, err := newHandleID()
			if err != nil {
				return err
			}
			now := time.Now().UTC()
			handles, err := loadHandles()
			if err != nil {
				return err
			}
			handles[id] = Handle{ID: id, Secret: name, EnvName: env, Command: command, ExpiresAt: now.Add(d), CreatedAt: now}
			if err := saveHandles(handles); err != nil {
				return err
			}
			// Record an --override mint distinctly, so authorizing a handle past an approval/grant
			// gate leaves a clear audit trail rather than looking like an ordinary handle.
			op := "handle-create"
			if override && (sec.RequireApproval || sec.RequireGrant) {
				op = "handle-override"
				fmt.Fprintf(os.Stderr, "warning: handle for %s bypasses its per-use gate for %s\n", name, ttl)
			}
			if err := logAudit(op, name, id); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "handle for %s (injected as $%s), valid until %s:\n",
				name, env, now.Add(d).Local().Format("2006-01-02 15:04:05"))
			fmt.Println(id) // the capability, to stdout so it can be captured and handed to an agent
			return nil
		},
	}
	c.Flags().StringVar(&ttl, "ttl", "", "how long the handle is valid (e.g. 1h, 2h) — required")
	c.Flags().StringVar(&command, "command", "", "only authorize a command line matching this glob (e.g. 'psql *')")
	c.Flags().StringVar(&as, "as", "", "env var to inject the value under (default: the secret name)")
	c.Flags().BoolVar(&override, "override", false, "allow minting a handle for a --require-approval/--require-grant secret (the handle bypasses that per-use gate)")
	return c
}

func newHandleRevoke() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke HANDLE",
		Short: "Revoke a handle",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			id := args[0]
			handles, err := loadHandles()
			if err != nil {
				return err
			}
			h, ok := handles[id]
			if !ok {
				return fmt.Errorf("no such handle: %s", id)
			}
			delete(handles, id)
			if err := saveHandles(handles); err != nil {
				return err
			}
			if err := logAudit("handle-revoke", h.Secret, id); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "revoked handle %s\n", id)
			return nil
		},
	}
}

func newHandleLs() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List active handles (operator view: which secret each unlocks)",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			handles, err := loadHandles()
			if err != nil {
				return err
			}
			if len(handles) == 0 {
				fmt.Fprintln(os.Stderr, "no active handles")
				return nil
			}
			ids := make([]string, 0, len(handles))
			for id := range handles {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			now := time.Now()
			rows := make([][]string, 0, len(ids))
			for _, id := range ids {
				h := handles[id]
				command := h.Command
				if command == "" {
					command = "any"
				}
				expires := h.ExpiresAt.Local().Format("2006-01-02 15:04:05")
				if now.After(h.ExpiresAt) {
					expires += " (expired)"
				}
				rows = append(rows, []string{id, h.Secret, h.EnvName, command, expires})
			}
			renderTable([]string{"HANDLE", "SECRET", "AS", "COMMAND", "EXPIRES"}, rows)
			return nil
		},
	}
}
