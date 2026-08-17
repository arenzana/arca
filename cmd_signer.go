// Operator store-signing key (audit H1). Distinct from the per-session audit
// signers in sign.go: this key authenticates the synced store, is operator-
// anchored, and is pinned per machine. This file is the command surface only;
// push/pull verification lands in a later slice and is not wired yet.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/arenzana/arca/internal/storesign"
)

func storeSigningKeyPath() string { return filepath.Join(storeStateDir(), "store-signing.key") }
func storeSignerPinPath() string  { return filepath.Join(storeStateDir(), "store-signer.pin") }

func newSigner() *cobra.Command {
	c := &cobra.Command{
		Use:   "signer",
		Short: "Show, pin, or rotate the operator key that will authenticate a synced store",
	}
	c.AddCommand(newSignerShow(), newSignerPin(), newSignerRotate())
	return c
}

// newSignerShow prints the local signing public key. Headless-safe: public
// material, no mutation. Generates a key on first use so a new machine can
// copy the pubkey out-of-band before any pin or push.
func newSignerShow() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print this machine's store-signing public key",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			k, err := loadOrCreateStoreKey()
			if err != nil {
				return err
			}
			fmt.Println(storesign.EncodePub(k.Pub))
			return nil
		},
	}
}

// newSignerPin records the expected signer public key for this machine.
// Terminal-anchored: pinning is what makes an unsigned or mis-signed pull a
// hard refusal, so an agent that could reach it would silence the control.
func newSignerPin() *cobra.Command {
	return &cobra.Command{
		Use:   "pin PUBKEY",
		Short: "Accept a store-signing public key as this machine's expected signer",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			pub, err := storesign.DecodePub(args[0])
			if err != nil {
				return err
			}
			shown := storesign.EncodePub(pub)
			if err := requireOperator("signer pin",
				fmt.Sprintf("Pin store signer %s on this machine? Pulls will then refuse any store not signed by this key.", shown)); err != nil {
				return err
			}
			if err := storesign.SavePin(storeSignerPinPath(), pub); err != nil {
				return err
			}
			if err := logAudit("signer-pin", shown, ""); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "pinned store signer %s — pulls will refuse a store not signed by this key\n", shown)
			return nil
		},
	}
}

// newSignerRotate mints a new key, re-pins it locally, and leaves the rest of
// the fleet needing `arca signer pin <new>`. Push/re-sign of the current store
// lands with the sync wiring; until then this is the key-and-pin half only.
func newSignerRotate() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate",
		Short: "Generate a new store-signing key and pin it on this machine",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := requireOperator("signer rotate",
				"Generate a new store-signing key and pin it on this machine? Other machines will refuse pulls until they pin the new public key."); err != nil {
				return err
			}
			k, err := storesign.Generate()
			if err != nil {
				return err
			}
			if err := storesign.Save(storeSigningKeyPath(), k); err != nil {
				return err
			}
			if err := storesign.SavePin(storeSignerPinPath(), k.Pub); err != nil {
				return err
			}
			shown := storesign.EncodePub(k.Pub)
			if err := logAudit("signer-rotate", shown, ""); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "rotated store signer; pin this on every other machine:\n  arca signer pin %s\n", shown)
			return nil
		},
	}
}

// loadOrCreateStoreKey returns the local signing key, generating one if the
// file is missing. A corrupt file is a hard error (never auto-healed).
func loadOrCreateStoreKey() (*storesign.Key, error) {
	k, err := storesign.Load(storeSigningKeyPath())
	if err == nil {
		return k, nil
	}
	if errors.Is(err, storesign.ErrCorrupt) {
		return nil, fmt.Errorf("store-signing key is corrupt; refusing to regenerate it (that would invalidate every prior signature). Restore the file or run `arca signer rotate` on a terminal: %w", err)
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	k, err = storesign.Generate()
	if err != nil {
		return nil, err
	}
	if err := storesign.Save(storeSigningKeyPath(), k); err != nil {
		return nil, err
	}
	// The machine that minted the key is pinned to it. Other machines still
	// pin out-of-band — this is not Trust-On-First-Use from the network.
	if err := storesign.SavePin(storeSignerPinPath(), k.Pub); err != nil {
		return nil, err
	}
	return k, nil
}
