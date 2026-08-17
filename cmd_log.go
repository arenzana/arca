// The log command and the audit-chain verification behind `log --verify`.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/arenzana/arca/internal/audit"
	"github.com/spf13/cobra"
)

// newLog prints the access history, including the attributed AI agent and session.
func newLog() *cobra.Command {
	var limit int
	var jsonOut, verify, requireSigned, remoteCheck, printAnchor bool
	var anchor string
	c := &cobra.Command{
		Use:   "log [NAME]",
		Short: "Show access history (--verify checks the log's integrity)",
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
			if verify {
				return verifyLog(a, requireSigned, anchor, remoteCheck, printAnchor)
			}
			if requireSigned {
				return fmt.Errorf("--require-signed is only valid with --verify")
			}
			if anchor != "" {
				return fmt.Errorf("--anchor is only valid with --verify")
			}
			if remoteCheck {
				return fmt.Errorf("--remote is only valid with --verify")
			}
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
			rows := make([][]string, 0, len(evs))
			for _, e := range evs {
				agent := e.Agent
				if e.Version != "" {
					agent += "/" + e.Version
				}
				// Sanitize the untrusted columns (name, and the agent/session/actor/caller strings,
				// which for a detected agent come from its own environment); colorOp(op) is a trusted
				// enum. See SEC-07.
				rows = append(rows, []string{
					e.TS.Local().Format("2006-01-02 15:04:05"), colorOp(e.Op), sanitize(e.Name),
					sanitize(agent), sanitize(shortID(e.Session)), sanitize(e.Actor), sanitize(e.Caller),
				})
			}
			renderTable([]string{"TIME", "OP", "NAME", "AGENT", "SESSION", "ACTOR", "CALLER"}, rows)
			return nil
		},
	}
	c.Flags().IntVar(&limit, "limit", 50, "max events")
	c.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	c.Flags().BoolVar(&verify, "verify", false, "verify the audit log's hash chain and signatures instead of printing it")
	c.Flags().BoolVar(&requireSigned, "require-signed", false, "with --verify, also fail if any chained event is unsigned")
	c.Flags().StringVar(&anchor, "anchor", "", "with --verify, also require the log to extend this previously-emitted anchor token")
	c.Flags().BoolVar(&remoteCheck, "remote", false, "with --verify, also require the log to extend its escrowed off-machine history (needs sync configured)")
	c.Flags().BoolVar(&printAnchor, "print-anchor", false, "with --verify, print a fresh anchor token on stdout (keep it off-machine; do not capture this from an agent session)")
	return c
}

// verifyLog runs an integrity check of the audit log and prints the result. It returns a non-zero
// error when the chain or a signature is broken, so it can gate a cron/CI check. With requireSigned
// it also fails when any chained event lacks a signature (a stripped or never-applied signature),
// which a default verify only reports as a count. With a previously-emitted anchor token, it also
// fails unless the chain still extends that head — the defense against the store and the audit DB
// being rolled back *together* to a consistent older state, which every in-DB check necessarily
// misses (SEC-14).
func verifyLog(a *audit.Log, requireSigned bool, anchor string, remoteCheck, printAnchor bool) error {
	r, err := a.Verify()
	if err != nil {
		return err
	}
	if !r.OK {
		if r.BrokenID != 0 {
			return fmt.Errorf("audit log integrity FAILED at event %d: %s", r.BrokenID, r.Reason)
		}
		return fmt.Errorf("audit log integrity FAILED: %s", r.Reason)
	}
	if requireSigned && r.Unsigned > 0 {
		return fmt.Errorf("audit log integrity FAILED: %d of %d chained event(s) are unsigned (--require-signed)", r.Unsigned, r.Checked)
	}
	// Store-generation cross-checks (SEC-14). The chain is intact, so the generations recorded in
	// it are trustworthy; a regression within the log, or a store older than the log's view, is
	// rollback evidence (a resurrected rotated/deleted secret) and fails the verify.
	if r.GenRegressedID != 0 {
		return fmt.Errorf("store ROLLBACK detected: event %d observed an older store generation than an earlier event — an older store copy was restored while auditing continued (check the store's git history; rotate any resurrected secrets)", r.GenRegressedID)
	}
	if r.MaxStoreGen > 0 {
		if s, err := openStore(); err == nil && s.Generation < r.MaxStoreGen {
			return fmt.Errorf("store ROLLBACK detected: the store is at generation %d but the audit log has verified events up to generation %d — the store file is older than the last audited operation (check the store's git history; rotate any resurrected secrets)", s.Generation, r.MaxStoreGen)
		}
	}
	// The anchor check runs only on an already-verified chain: the stored hashes are trustworthy
	// once the chain has been recomputed from genesis, so extending the anchored head proves the
	// history the anchor was minted over is still present and unmodified.
	if anchor != "" {
		n, h, err := audit.ParseAnchor(anchor)
		if err != nil {
			return err
		}
		if err := a.CheckAnchor(n, h); err != nil {
			return fmt.Errorf("audit log integrity FAILED: %w — the store and audit DB may have been rolled back together; treat every secret readable at the anchor time as potentially resurrected", err)
		}
	}
	// The escrowed history is the same check with an off-machine witness: segments this
	// machine pushed on past syncs are append-only on the backend, so a local log that
	// no longer extends them was rewritten or truncated here (SEC-14, Option B).
	if remoteCheck {
		b, err := openBackend()
		if err != nil {
			return err
		}
		if err := verifyAgainstEscrow(context.Background(), a, b); err != nil {
			return fmt.Errorf("audit log integrity FAILED: %w", err)
		}
	}
	fmt.Fprintf(os.Stderr, "audit log OK: %d event(s) chained, %d signed", r.Checked, r.Signed)
	if r.Unsigned > 0 {
		fmt.Fprintf(os.Stderr, ", %d UNSIGNED", r.Unsigned)
	}
	if r.Legacy > 0 {
		fmt.Fprintf(os.Stderr, ", %d legacy (pre-chain, unverifiable)", r.Legacy)
	}
	if anchor != "" {
		fmt.Fprintf(os.Stderr, ", anchor extended")
	}
	fmt.Fprintln(os.Stderr)
	// A fresh anchor is opt-in (--print-anchor). Printing it on every --verify
	// put a low-secrecy token on stdout that agents capture (audit M2). Keep it
	// off the default path; mint it deliberately and store it off this machine.
	if printAnchor && r.Checked > 0 && r.LastHash != nil {
		fmt.Println(audit.FormatAnchor(r.Checked, r.LastHash))
	}
	return nil
}
