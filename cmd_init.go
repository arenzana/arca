// The init command: creating the store and deriving its first recipient.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/arenzana/arca/internal/crypto"
	"github.com/arenzana/arca/internal/store"
	"github.com/arenzana/arca/internal/xdg"
	"github.com/spf13/cobra"
)

// newInit creates the store, deriving the recipient from the caller's existing age key (or
// generating one if none exists). It refuses to clobber an existing store without --force.
func newInit() *cobra.Command {
	var force bool
	c := &cobra.Command{
		Use:   "init",
		Short: "Initialize the store (reuses $SOPS_AGE_KEY_FILE or generates an identity)",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if _, err := os.Stat(xdg.StorePath()); err == nil && !force {
				return fmt.Errorf("store already exists at %s (use --force)", xdg.StorePath())
			}
			idPath := xdg.IdentityPath()
			var recips []string
			if fi, err := os.Stat(idPath); err == nil {
				// Reuse the existing identity (e.g. the sops age key). Warn if its file is
				// readable by group/other — the private key should be 0600.
				if fi.Mode()&0o077 != 0 {
					fmt.Fprintf(os.Stderr, "warning: identity %s is group/world-accessible (%#o); consider chmod 600\n", idPath, fi.Mode().Perm())
				}
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
				// O_EXCL: create exclusively (never follow a pre-planted symlink or clobber an
				// existing file) so the private key can't be redirected to an attacker path.
				f, err := os.OpenFile(idPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //#nosec G304 -- idPath comes from config/env (ARCA_IDENTITY / XDG), not untrusted input
				if err != nil {
					return err
				}
				if _, err := f.WriteString(idStr + "\n"); err != nil {
					f.Close()
					return err
				}
				if err := f.Close(); err != nil {
					return err
				}
				recips = []string{rec}
				fmt.Fprintf(os.Stderr, "generated new identity at %s\n", idPath)
			}
			if err := store.New(xdg.StorePath(), recips).Save(); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "initialized store at %s\nrecipients: %s\n", xdg.StorePath(), strings.Join(recips, ", "))
			return nil
		},
	}
	c.Flags().BoolVar(&force, "force", false, "overwrite an existing store")
	return c
}
