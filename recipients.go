// Multi-recipient / team support. A store encrypts every value to one or more age recipients
// (see Store.Recipients); `set`/`rotate`/`import` already wrap to all of them. These commands
// manage that recipient set and re-wrap existing secrets when it changes — e.g. to add or
// remove a teammate's key. Changing the set does NOT touch existing ciphertext until
// `reencrypt` runs, so the workflow is: recipients add/rm  →  reencrypt.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/arenzana/arca/internal/crypto"
)

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
				fmt.Println(r)
			}
			return nil
		},
	}
	c.AddCommand(newRecipientsAdd(), newRecipientsRm())
	return c
}

func newRecipientsAdd() *cobra.Command {
	return &cobra.Command{
		Use:   "add RECIPIENT [RECIPIENT...]",
		Short: "Add age recipient(s) (run `reencrypt` to apply to existing secrets)",
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
			// Validate every recipient parses as an age recipient before mutating anything.
			if _, err := crypto.ParseRecipients(args); err != nil {
				return fmt.Errorf("invalid recipient: %w", err)
			}
			added := 0
			for _, r := range args {
				if contains(s.Recipients, r) {
					continue
				}
				s.Recipients = append(s.Recipients, r)
				added++
			}
			if added == 0 {
				fmt.Fprintln(os.Stderr, "no new recipients")
				return nil
			}
			if err := s.Save(); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "added %d recipient(s); run `arca reencrypt` to re-wrap existing secrets\n", added)
			return nil
		},
	}
}

func newRecipientsRm() *cobra.Command {
	return &cobra.Command{
		Use:   "rm RECIPIENT [RECIPIENT...]",
		Short: "Remove age recipient(s) (run `reencrypt` so they can no longer decrypt)",
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
			if err := s.Save(); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "removed %d recipient(s); run `arca reencrypt` to re-wrap existing secrets\n", removed)
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
			unlock, err := lockStore()
			if err != nil {
				return err
			}
			defer unlock()
			s, err := openStore()
			if err != nil {
				return err
			}
			ids, err := loadIDs()
			if err != nil {
				return err
			}
			recips, err := crypto.ParseRecipients(s.Recipients)
			if err != nil {
				return err
			}
			n := 0
			for _, name := range s.Names() {
				sec := s.Secrets[name]
				plain, err := crypto.Decrypt(sec.Value, ids)
				if err != nil {
					return fmt.Errorf("decrypt %s (is your identity still a recipient?): %w", name, err)
				}
				armored, err := crypto.Encrypt(plain, recips)
				if err != nil {
					return fmt.Errorf("encrypt %s: %w", name, err)
				}
				sec.Value = armored
				n++
			}
			if err := s.Save(); err != nil {
				return err
			}
			if err := logAudit("reencrypt", "*", ""); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "re-encrypted %d secret(s) to %d recipient(s)\n", n, len(recips))
			return nil
		},
	}
}
