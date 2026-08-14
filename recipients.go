// Multi-recipient / team support. A store encrypts every value to one or more age recipients
// (see Store.Recipients); `set`/`rotate`/`import` already wrap to all of them. These commands
// manage that recipient set and re-wrap existing secrets when it changes — e.g. to add or
// remove a teammate's key. Changing the set does NOT touch existing ciphertext until
// `reencrypt` runs, so the workflow is: recipients add/rm  →  reencrypt.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/arenzana/arca/internal/crypto"
	"github.com/arenzana/arca/internal/store"
)

// reencryptStore decrypts every secret with the local identity and re-wraps it to the store's
// current recipient set, in memory (the caller Saves). It's the shared core of `reencrypt` and the
// auto-re-encrypt that `recipients rm` runs. UpdatedAt is left untouched — only the envelope changes.
func reencryptStore(s *store.Store) (int, error) {
	ids, err := loadIDs()
	if err != nil {
		return 0, err
	}
	recips, err := crypto.ParseRecipients(s.Recipients)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, name := range s.Names() {
		sec := s.Secrets[name]
		plain, err := crypto.Decrypt(sec.Value, ids)
		if err != nil {
			return n, fmt.Errorf("decrypt %s (is your identity still a recipient?): %w", name, err)
		}
		armored, err := crypto.Encrypt(plain, recips)
		if err != nil {
			return n, fmt.Errorf("encrypt %s: %w", name, err)
		}
		sec.Value = armored
		n++
	}
	return n, nil
}

// warnRecipientRevocation spells out the hard truth of SEC-15: removing a recipient (even with the
// re-encryption that now runs automatically) does NOT revoke the removed holder's access to secrets
// they could already read. Re-encryption only protects the *current* store going forward — the
// removed key still decrypts local clones, backups, and every prior version of the git-synced store.
// The only true revocation of a secret is to rotate its value, so the leaked ciphertext goes dead.
func warnRecipientRevocation(w io.Writer, s *store.Store) {
	fmt.Fprintln(w, "\n⚠  Removing a recipient does NOT revoke access to secrets they could already read.")
	fmt.Fprintln(w, "   The removed key can still decrypt any copy it already had — local clones, backups,")
	fmt.Fprintln(w, "   and every prior version of the store in git history. Re-encryption only protects")
	fmt.Fprintln(w, "   the CURRENT store going forward.")
	names := s.Names()
	if len(names) == 0 {
		return
	}
	fmt.Fprintln(w, "   To truly deny the removed holder a secret, ROTATE its value (the old ciphertext")
	fmt.Fprintln(w, "   then decrypts to a dead value):")
	const maxList = 10
	for i, name := range names {
		if i == maxList {
			fmt.Fprintf(w, "     … and %d more (see `arca ls`)\n", len(names)-maxList)
			break
		}
		fmt.Fprintf(w, "     arca rotate %s\n", sanitize(name))
	}
}

// newRecipients is the parent command; bare `arca recipients` lists the current set.
func newRecipients() *cobra.Command {
	c := &cobra.Command{
		Use:   "recipients",
		Short: "Manage the age recipients secrets are encrypted to",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			for _, r := range s.Recipients {
				if label := s.Label(r); label != "" {
					fmt.Printf("%s  %s\n", r, label)
				} else {
					fmt.Println(r)
				}
			}
			return nil
		},
	}
	c.AddCommand(newRecipientsAdd(), newRecipientsRm(), newRecipientsPin())
	return c
}

func newRecipientsAdd() *cobra.Command {
	var label string
	c := &cobra.Command{
		Use:   "add RECIPIENT [RECIPIENT...]",
		Short: "Add age recipient(s) (run `reencrypt` to apply to existing secrets)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			// A label names WHO/WHICH machine a key belongs to (for exposure reporting). It can't be
			// applied unambiguously to a batch, so require exactly one recipient when --label is given.
			if label != "" && len(args) != 1 {
				return fmt.Errorf("--label applies to a single recipient; add them one at a time")
			}
			// The widest mutation arca supports: a new recipient decrypts every secret, permanently,
			// on every machine the store reaches, without ever entering an access path (T12). Anchored
			// to a human. `recipients rm` is not — removal only restricts.
			//
			// The prompt shows the key, because "add a recipient" is not the decision — *which* key is.
			// It is the only chance to notice an unfamiliar one before the reencrypt makes it total.
			if err := requireOperator("recipients add", fmt.Sprintf(
				"Add %s as a recipient? It will be able to decrypt every secret in the store after `reencrypt`.",
				strings.Join(args, ", "))); err != nil {
				return err
			}
			unlock, err := lockStore()
			if err != nil {
				return err
			}
			defer unlock()
			s, err := openStore()
			if err != nil {
				return err
			}
			// Validate every recipient parses as an age recipient before mutating anything.
			if _, err := crypto.ParseRecipients(args); err != nil {
				return fmt.Errorf("invalid recipient: %w", err)
			}
			var added []string
			for _, r := range args {
				if contains(s.Recipients, r) {
					continue
				}
				s.Recipients = append(s.Recipients, r)
				added = append(added, r)
			}
			// Record the label even if the recipient already existed (lets `add --label` back-fill a
			// label onto an already-present key without re-adding it).
			relabeled := ""
			if label != "" {
				if s.Label(args[0]) != label {
					relabeled = args[0]
				}
				s.SetLabel(args[0], label)
			}
			if len(added) == 0 && label == "" {
				fmt.Fprintln(os.Stderr, "no new recipients")
				return nil
			}
			if err := s.Save(); err != nil {
				return err
			}
			// Audit each added key by name (SEC-44). Adding a recipient grants permanent decryption
			// rights to every secret, on every machine the store reaches — the widest-blast-radius
			// mutation arca supports — and it went unrecorded until now, so the log could show a
			// `reencrypt` with no trace of the key it re-wrapped to. Recorded after the save, matching
			// `recipients rm`, so the log never claims a change that failed to persist.
			for _, r := range added {
				if err := logAudit("recipients-add", r, ""); err != nil {
					return err
				}
			}
			// A relabel is audited too: labels are how an operator recognizes a key during review
			// (`who-can-read`, `exposure`, `doctor`), so renaming an unfamiliar key to something
			// trusted-looking is a way to hide it from exactly that check.
			if relabeled != "" {
				if err := logAudit("recipients-label", relabeled, ""); err != nil {
					return err
				}
			}
			// Accept exactly the keys the operator was just shown into the local baseline, so the
			// T12 load-time warning does not fire on a key this machine deliberately added. Only
			// these keys: see pinAdd. Best-effort for the same reason recordStoreGeneration is —
			// a lost pin costs a spurious warning later, never a failed command, and it fails
			// toward warning rather than toward silence.
			if len(added) > 0 {
				_ = pinAdd(added...)
			}
			if len(added) > 0 {
				fmt.Fprintf(os.Stderr, "added %d recipient(s); run `arca reencrypt` to re-wrap existing secrets\n", len(added))
			} else {
				fmt.Fprintf(os.Stderr, "labeled recipient %q\n", label)
			}
			return nil
		},
	}
	c.Flags().StringVar(&label, "label", "", "human label for the recipient (e.g. \"alice@laptop\"); used by exposure reports")
	return c
}

func newRecipientsRm() *cobra.Command {
	var noReencrypt bool
	c := &cobra.Command{
		Use:   "rm RECIPIENT [RECIPIENT...]",
		Short: "Remove age recipient(s), re-wrap existing secrets, and warn what revocation does/doesn't do",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			unlock, err := lockStore()
			if err != nil {
				return err
			}
			defer unlock()
			s, err := openStore()
			if err != nil {
				return err
			}
			kept := make([]string, 0, len(s.Recipients))
			for _, r := range s.Recipients {
				if !contains(args, r) {
					kept = append(kept, r)
				}
			}
			if len(kept) == 0 {
				return fmt.Errorf("refusing to remove all recipients (no key could decrypt new secrets)")
			}
			removed := len(s.Recipients) - len(kept)
			if removed == 0 {
				fmt.Fprintln(os.Stderr, "no matching recipients")
				return nil
			}
			s.Recipients = kept
			for _, r := range args { // drop labels for removed recipients
				s.SetLabel(r, "")
			}
			if err := s.Save(); err != nil {
				return err
			}
			if err := logAudit("recipients-rm", "*", ""); err != nil {
				return err
			}
			// Drop just these keys from the local baseline. Not a re-pin from the store: rm is
			// deliberately unanchored because removal only restricts, so re-pinning here would
			// hand an agent an unanchored way to accept a key that arrived by sync, simply by
			// removing some unrelated one. See pinRemove.
			_ = pinRemove(args...)

			// Automatically re-wrap existing ciphertext to the remaining keys, so the *current* store
			// immediately stops being decryptable by the removed one (closing the old rm→reencrypt gap).
			// A failure here (e.g. our identity can't decrypt) is reported, not fatal: the removal stands.
			if noReencrypt {
				fmt.Fprintf(os.Stderr, "removed %d recipient(s); re-encryption skipped (run `arca reencrypt` to apply)\n", removed)
			} else if n, err := reencryptStore(s); err != nil {
				fmt.Fprintf(os.Stderr, "removed %d recipient(s), but automatic re-encryption failed: %v\n  run `arca reencrypt` once your identity can decrypt the store.\n", removed, err)
			} else if err := s.Save(); err != nil {
				return err
			} else {
				_ = logAudit("reencrypt", "*", "")
				fmt.Fprintf(os.Stderr, "removed %d recipient(s) and re-encrypted %d secret(s) to the remaining key(s)\n", removed, n)
			}

			// The essential honesty (SEC-15): re-encryption is not revocation of what was already read.
			warnRecipientRevocation(os.Stderr, s)
			return nil
		},
	}
	c.Flags().BoolVar(&noReencrypt, "no-reencrypt", false, "don't re-wrap existing secrets now (do it later with `arca reencrypt`)")
	return c
}

// newRecipientsPin accepts the store's current recipient set as this machine's baseline, which is
// what stops the T12 load-time warning. Anchored to an operator, and for the same reason `add` is:
// this is the control that makes an injected key visible, so an agent that could reach the accept
// path unanchored could add a key on one machine, sync it here, and pin away the evidence. The
// prompt lists the keys that are not yet accepted, because *which* key is the decision.
func newRecipientsPin() *cobra.Command {
	return &cobra.Command{
		Use:   "pin",
		Short: "Accept the current recipient set as this machine's expected baseline",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			added, removed, pinned := recipientDrift(s)
			if pinned && len(added) == 0 && len(removed) == 0 {
				fmt.Fprintln(os.Stderr, "recipient set already matches the pinned baseline; nothing to accept")
				return nil
			}
			var q strings.Builder
			q.WriteString("Accept the current recipient set as expected on this machine?")
			for _, r := range added {
				label := s.Label(r)
				if label == "" {
					label = "unlabeled"
				}
				fmt.Fprintf(&q, "\n  + %s (%s) — will be able to decrypt every secret in this store", r, label)
			}
			for _, r := range removed {
				fmt.Fprintf(&q, "\n  - %s — no longer present", r)
			}
			if err := requireOperator("recipients pin", q.String()); err != nil {
				return err
			}
			if err := writeRecipientPin(s); err != nil {
				return err
			}
			// Audited like the other recipient-set changes (SEC-44): accepting a key into the
			// baseline is the moment an unfamiliar recipient stops being reported, so the log
			// should say who stopped reporting it and when.
			for _, r := range added {
				if err := logAudit("recipients-pin", r, ""); err != nil {
					return err
				}
			}
			fmt.Fprintf(os.Stderr, "pinned %d recipient(s) as this machine's baseline\n", len(s.Recipients))
			return nil
		},
	}
}

// newReencrypt decrypts every secret with the local identity and re-wraps it to the current
// recipient set. This is how a recipient change actually takes effect on stored ciphertext.
// UpdatedAt is left untouched: the value content is unchanged, only its encryption envelope.
func newReencrypt() *cobra.Command {
	return &cobra.Command{
		Use:   "reencrypt",
		Short: "Re-encrypt every secret to the current recipient set",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// The second half of T12: `recipients add` stages a key, `reencrypt` is what actually
			// re-wraps every value to it. Anchoring only the add would leave the payload step open to
			// an agent racing a legitimate pending change.
			if err := requireOperator("reencrypt",
				"Re-encrypt every secret to the store's current recipient set?"); err != nil {
				return err
			}
			unlock, err := lockStore()
			if err != nil {
				return err
			}
			defer unlock()
			s, err := openStore()
			if err != nil {
				return err
			}
			n, err := reencryptStore(s)
			if err != nil {
				return err
			}
			if err := s.Save(); err != nil {
				return err
			}
			if err := logAudit("reencrypt", "*", ""); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "re-encrypted %d secret(s) to %d recipient(s)\n", n, len(s.Recipients))
			return nil
		},
	}
}
