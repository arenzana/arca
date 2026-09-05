// Operator store-signing key (audit H1). Distinct from the per-session audit
// signers in sign.go: this key authenticates the synced store and escrow
// segments, is operator-anchored, and is trusted per machine.
//
// Each machine holds one signing key and a SET of accepted signers. The set is
// what makes a multi-machine fleet expressible: every machine signs with its
// own key, so a fleet of N has N signers, and each machine must accept its
// peers as well as itself.
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

// storeSignerPinPath is the multi-signer set (0.12+).
func storeSignerPinPath() string { return filepath.Join(storeStateDir(), "store-signers.pin") }

// legacyStoreSignerPinPath is the pre-0.12 single-key pin. It is read when the
// set file is absent and migrated on the first write, then removed: leaving two
// files that can disagree about who is trusted is worse than one.
func legacyStoreSignerPinPath() string { return filepath.Join(storeStateDir(), "store-signer.pin") }

func newSigner() *cobra.Command {
	c := &cobra.Command{
		Use:   "signer",
		Short: "Show, trust, or rotate the operator keys that authenticate a synced store",
	}
	c.AddCommand(newSignerShow(), newSignerAdd(), newSignerList(), newSignerRm(), newSignerRotate())
	return c
}

// newSignerShow prints the local signing public key. Headless-safe: public
// material, no mutation. Generates a key on first use so a new machine can
// copy the pubkey out-of-band before any add or push.
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

// newSignerAdd accepts another machine's signing key on this machine.
// Terminal-anchored: the set is what makes an unsigned or mis-signed pull a
// hard refusal, so an agent that could reach it would silence the control.
//
// It is additive. The pre-0.12 `pin` replaced the single trusted key, which is
// why a two-machine fleet ended up cross-pinned — each `pin` of a peer evicted
// the machine's own key.
func newSignerAdd() *cobra.Command {
	var label string
	c := &cobra.Command{
		Use:     "add PUBKEY",
		Aliases: []string{"pin", "trust"},
		Short:   "Trust a store-signing public key on this machine",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			pub, err := storesign.DecodePub(args[0])
			if err != nil {
				return err
			}
			shown := storesign.EncodePub(pub)
			set, _, err := loadSignerSet()
			if err != nil {
				return err
			}
			if set.Contains(pub) {
				fmt.Fprintf(os.Stderr, "%s is already trusted on this machine\n", shown)
				return nil
			}
			if err := requireOperator("signer add",
				fmt.Sprintf("Trust store signer %s on this machine? Pulls will then accept a store signed by this key.", shown)); err != nil {
				return err
			}
			set = append(set, storesign.PinEntry{Pub: pub, Label: label})
			if err := saveSignerSet(set); err != nil {
				return err
			}
			if err := logAudit("signer-add", shown, label); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "trusting store signer %s (%d trusted signer(s) now)\n", shown, len(set))
			return nil
		},
	}
	c.Flags().StringVar(&label, "label", "", "human label for this key (e.g. the machine name)")
	return c
}

// newSignerList shows what this machine accepts, marking its own key. Read-only
// and headless-safe: the whole point is to be able to see the trust state
// without an operator ceremony.
func newSignerList() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the store signers this machine accepts",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			set, pinned, err := trustedSigners()
			if err != nil {
				return err
			}
			if len(set) == 0 {
				fmt.Fprintln(os.Stderr, "no store signers trusted on this machine (unsigned pulls are still accepted)")
				return nil
			}
			local := loadStoreKeyIfPresent()
			for _, e := range set {
				mark := " "
				if local != nil && e.Pub.Equal(local.Pub) {
					mark = "*"
				}
				fmt.Printf("%s %s\t%s\n", mark, storesign.EncodePub(e.Pub), e.Label)
			}
			if !pinned {
				fmt.Fprintln(os.Stderr, "note: no pin file yet — unsigned pulls are still accepted. `arca signer add` on a peer key closes that window.")
			}
			fmt.Fprintln(os.Stderr, "(* = this machine's own signing key)")
			return nil
		},
	}
}

// newSignerRm drops a key from the accepted set. Not operator-anchored:
// removal only ever restricts what this machine will accept, the same reasoning
// `recipients rm` uses. Removing the last key is refused — that would silently
// reopen the migration window in which an unsigned store is accepted.
func newSignerRm() *cobra.Command {
	return &cobra.Command{
		Use:     "rm PUBKEY",
		Aliases: []string{"remove", "untrust"},
		Short:   "Stop accepting a store-signing public key on this machine",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			pub, err := storesign.DecodePub(args[0])
			if err != nil {
				return err
			}
			shown := storesign.EncodePub(pub)
			set, pinned, err := loadSignerSet()
			if err != nil {
				return err
			}
			if !pinned || !set.Contains(pub) {
				return fmt.Errorf("%s is not in this machine's trusted signer set", shown)
			}
			var kept storesign.PinSet
			for _, e := range set {
				if !e.Pub.Equal(pub) {
					kept = append(kept, e)
				}
			}
			if len(kept) == 0 {
				return fmt.Errorf("refusing to remove the last trusted signer — that would reopen the window where an unsigned store is accepted. Add a replacement first")
			}
			if err := saveSignerSet(kept); err != nil {
				return err
			}
			if err := logAudit("signer-rm", shown, ""); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "no longer trusting %s (%d trusted signer(s) left)\n", shown, len(kept))
			return nil
		},
	}
}

// newSignerRotate mints a new key for this machine and trusts it, keeping the
// outgoing key in the set. The old key stays because this machine's escrow
// history is signed with it: dropping it would make its own past segments
// unverifiable. `arca signer rm <old>` retires it once that history is gone.
func newSignerRotate() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate",
		Short: "Generate a new store-signing key for this machine and trust it",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := requireOperator("signer rotate",
				"Generate a new store-signing key on this machine? Other machines will refuse its pushes until they run `arca signer add` on the new public key."); err != nil {
				return err
			}
			old := loadStoreKeyIfPresent()
			k, err := storesign.Generate()
			if err != nil {
				return err
			}
			if err := storesign.Save(storeSigningKeyPath(), k); err != nil {
				return err
			}
			set, _, err := loadSignerSet()
			if err != nil {
				return err
			}
			if old != nil && !set.Contains(old.Pub) {
				set = append(set, storesign.PinEntry{Pub: old.Pub, Label: "this machine (retired)"})
			}
			set = append(set, storesign.PinEntry{Pub: k.Pub, Label: "this machine"})
			if err := saveSignerSet(set); err != nil {
				return err
			}
			shown := storesign.EncodePub(k.Pub)
			if err := logAudit("signer-rotate", shown, ""); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "rotated this machine's store signer; run this on every other machine:\n  arca signer add %s\n", shown)
			return nil
		},
	}
}

// loadSignerSet returns the persisted set (without the implicit local key) and
// whether a pin file exists. Mutating commands use it rather than
// trustedSigners so that writing back does not persist the implicit entry —
// the local key is trusted because it is local, not because it was recorded.
func loadSignerSet() (storesign.PinSet, bool, error) {
	set, err := storesign.LoadPinSet(storeSignerPinPath())
	if err == nil {
		return set, true, nil
	}
	if errors.Is(err, storesign.ErrCorrupt) {
		return nil, false, fmt.Errorf("store-signer pin is corrupt; refusing to rewrite it. Restore the file or remove %s deliberately: %w", storeSignerPinPath(), err)
	}
	if !os.IsNotExist(err) {
		return nil, false, err
	}
	legacy, lerr := storesign.LoadPin(legacyStoreSignerPinPath())
	if lerr == nil {
		return storesign.PinSet{{Pub: legacy}}, true, nil
	}
	if errors.Is(lerr, storesign.ErrCorrupt) {
		return nil, false, fmt.Errorf("store-signer pin is corrupt; refusing to rewrite it. Restore the file or remove %s deliberately: %w", legacyStoreSignerPinPath(), lerr)
	}
	if !os.IsNotExist(lerr) {
		return nil, false, lerr
	}
	return nil, false, nil
}

// saveSignerSet writes the set and clears the superseded single-key pin, so
// exactly one file decides who is trusted.
func saveSignerSet(set storesign.PinSet) error {
	if err := storesign.SavePinSet(storeSignerPinPath(), set); err != nil {
		return err
	}
	if err := os.Remove(legacyStoreSignerPinPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// loadStoreKeyIfPresent returns the local signing key, or nil when there is
// none or it is unreadable. Unlike loadOrCreateStoreKey it never mints one:
// verification must not create key material as a side effect.
func loadStoreKeyIfPresent() *storesign.Key {
	k, err := storesign.Load(storeSigningKeyPath())
	if err != nil {
		return nil
	}
	return k
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
	// The machine that minted the key trusts it implicitly (trustedSigners adds
	// it), so nothing is written to the pin file here. Peers still add it
	// out-of-band — this is not Trust-On-First-Use from the network.
	return k, nil
}
