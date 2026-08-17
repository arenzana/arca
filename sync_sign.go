// Operator store signatures on the sync path (audit H1).
//
// signStorePayload is the push half; verifyPulledStore is the pull half.
// The signature is over the exact store bytes that were sealed, verified
// against a locally pinned public key. No Trust-On-First-Use from the
// network: a new machine must pin the key out-of-band (`arca signer pin`).
package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"

	"github.com/arenzana/arca/internal/remote"
	"github.com/arenzana/arca/internal/storesign"
)

// signStorePayload signs the exact store bytes that are about to be sealed.
// A missing key is minted so an existing fleet starts signing without a
// ceremony; a corrupt key refuses to sign (push still proceeds unsigned,
// with a warning) rather than silently regenerating.
func signStorePayload(raw []byte) remote.StoreAuth {
	k, err := loadOrCreateStoreKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "arca: warning: store will be pushed UNSIGNED (signer unavailable: %v)\n", err)
		return remote.StoreAuth{}
	}
	return remote.StoreAuth{
		Signature: storesign.Encode(storesign.Sign(k.Priv, raw)),
		Signer:    storesign.EncodePub(k.Pub),
	}
}

// verifyPulledStore enforces the pin against the fetched head. It must run
// after the envelope is opened (so we have the payload bytes) and before
// any local store write or cursor advance.
func verifyPulledStore(payload []byte, rev remote.Rev) error {
	pin, err := storesign.LoadPin(storeSignerPinPath())
	if err != nil {
		if errors.Is(err, storesign.ErrCorrupt) {
			return fmt.Errorf("store-signer pin is corrupt; refusing the pull. Restore the pin or re-run `arca signer pin <pubkey>` on a terminal: %w", err)
		}
		if !os.IsNotExist(err) {
			return err
		}
		// No pin: migration window. An unsigned head is accepted with a
		// warning; a signed head is refused so the operator pins the key
		// out-of-band rather than trusting the network.
		if rev.Signer != "" || rev.Signature != "" {
			who := rev.Signer
			if who == "" {
				who = "<missing Arca-Signer>"
			}
			return fmt.Errorf("remote store is signed by %s but this machine has no pinned signer — copy the public key out-of-band and run `arca signer pin %s`", who, who)
		}
		fmt.Fprintf(syncLog, "arca: warning: store is unsigned; run `arca signer show` on your signing machine and `arca signer pin` here. A future version will refuse unsigned pulls.\n")
		return nil
	}
	return checkPinnedSignature(payload, rev, pin)
}

func checkPinnedSignature(payload []byte, rev remote.Rev, pin ed25519.PublicKey) error {
	if rev.Signature == "" || rev.Signer == "" {
		return fmt.Errorf("remote store is unsigned (or the backend stripped Arca-Signature/Arca-Signer) and this machine has a pinned signer — refusing the pull")
	}
	got, err := storesign.DecodePub(rev.Signer)
	if err != nil {
		return fmt.Errorf("remote Arca-Signer is malformed: %w", err)
	}
	if !bytes.Equal(got, pin) {
		return fmt.Errorf("remote store is signed by %s, not the pinned signer %s — if the operator rotated the key, run `arca signer pin %s` on this machine",
			rev.Signer, storesign.EncodePub(pin), rev.Signer)
	}
	sig, err := storesign.Decode(rev.Signature)
	if err != nil {
		return fmt.Errorf("remote Arca-Signature is malformed: %w", err)
	}
	if !storesign.Verify(pin, payload, sig) {
		return fmt.Errorf("remote store signature does not verify under the pinned signer — refusing the pull")
	}
	return nil
}
