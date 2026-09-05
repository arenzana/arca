// Operator store signatures on the sync path (audit H1).
//
// signStorePayload is the push half; verifyPulledStore is the pull half.
// The signature is over the exact store bytes that were sealed, verified
// against a locally held set of accepted signers. No Trust-On-First-Use from
// the network: a peer's key must be added out-of-band (`arca signer add`).
package main

import (
	"encoding/json"
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

// trustedSigners is the set of store signers this machine accepts: every key in
// the pin file, plus this machine's own signing key.
//
// The local key is included implicitly and is the fix for the defect this
// function replaces. Every machine mints its own signing key on first push, so
// a fleet has as many signers as machines; the old single pin held one. An
// operator with two machines could only make sync work by pinning the *peer* on
// each — after which neither machine trusted its own signatures. That is
// invisible for the store head (which is usually the peer's) and fatal for
// escrow, where fetchEscrowedSegments only ever reads this machine's own prefix
// and so verifies only self-signed segments. A machine trusting what it signed
// itself is not a policy choice; it is what "trusted" already means.
//
// pinned is reported separately because an empty pin file is the migration
// window (pre-signing fleets), and that window must not be reopened just
// because a local key exists.
func trustedSigners() (set storesign.PinSet, pinned bool, err error) {
	set, err = storesign.LoadPinSet(storeSignerPinPath())
	switch {
	case err == nil:
		pinned = true
	case errors.Is(err, storesign.ErrCorrupt):
		return nil, false, err
	case !os.IsNotExist(err):
		return nil, false, err
	default:
		// No multi-signer file. Fall back to the pre-0.12 single-key pin so an
		// existing machine keeps its trust decision across the upgrade.
		legacy, lerr := storesign.LoadPin(legacyStoreSignerPinPath())
		switch {
		case lerr == nil:
			set, pinned = storesign.PinSet{{Pub: legacy}}, true
		case errors.Is(lerr, storesign.ErrCorrupt):
			return nil, false, lerr
		case !os.IsNotExist(lerr):
			return nil, false, lerr
		}
	}
	if k := loadStoreKeyIfPresent(); k != nil && !set.Contains(k.Pub) {
		set = append(set, storesign.PinEntry{Pub: k.Pub, Label: "this machine"})
	}
	return set, pinned, nil
}

// verifyPulledStore enforces the trusted signers against the fetched head. It
// must run after the envelope is opened (so we have the payload bytes) and
// before any local store write or cursor advance.
func verifyPulledStore(payload []byte, rev remote.Rev) error {
	set, _, err := trustedSigners()
	if err != nil {
		if errors.Is(err, storesign.ErrCorrupt) {
			return fmt.Errorf("store-signer pin is corrupt; refusing the pull. Restore the pin or re-run `arca signer add <pubkey>` on a terminal: %w", err)
		}
		return err
	}
	// Migration window: this machine has never signed and trusts no one, so it
	// predates signing entirely. An unsigned head is accepted with a warning; a
	// signed one is refused so the operator adds the key out-of-band rather
	// than trusting the network. Holding a signing key closes the window —
	// a machine that has pushed a signed store must never accept an unsigned
	// head back, or stripping the signature would be a downgrade attack.
	if len(set) == 0 {
		if rev.Signer == "" && rev.Signature == "" {
			fmt.Fprintf(syncLog, "arca: warning: store is unsigned; run `arca signer show` on your signing machine and `arca signer add` here. A future version will refuse unsigned pulls.\n")
			return nil
		}
		who := rev.Signer
		if who == "" {
			who = "<missing Arca-Signer>"
		}
		return fmt.Errorf("remote store is signed by %s but this machine trusts no signer — copy the public key out-of-band and run `arca signer add %s`", who, who)
	}
	return checkSignature(payload, rev, set)
}

// checkSignature verifies rev's signature over payload under the trusted set.
//
// Membership is checked BEFORE verification: the signer name travels with the
// object, so a backend can claim any key it likes. Only a key already in the
// set is ever used to verify, which makes a claimed-but-untrusted signer a
// refusal rather than a self-consistent forgery.
func checkSignature(payload []byte, rev remote.Rev, set storesign.PinSet) error {
	if rev.Signature == "" || rev.Signer == "" {
		return fmt.Errorf("remote store is unsigned (or the backend stripped Arca-Signature/Arca-Signer) and this machine has trusted signers — refusing the pull")
	}
	got, err := storesign.DecodePub(rev.Signer)
	if err != nil {
		return fmt.Errorf("remote Arca-Signer is malformed: %w", err)
	}
	if !set.Contains(got) {
		return fmt.Errorf("remote store is signed by %s, which is not one of this machine's trusted signers (%s) — if the operator added or rotated a machine, run `arca signer add %s` on this machine",
			rev.Signer, set, rev.Signer)
	}
	sig, err := storesign.Decode(rev.Signature)
	if err != nil {
		return fmt.Errorf("remote Arca-Signature is malformed: %w", err)
	}
	if !storesign.Verify(got, payload, sig) {
		return fmt.Errorf("remote store signature does not verify under %s — refusing the pull", rev.Signer)
	}
	return nil
}

// verifyEscrowSegment checks an operator signature on an escrow segment.
// Unsigned (legacy) segments are accepted — they predate signing and are still
// bound by VerifyEscrowRows. A present-but-untrusted signature is a hard
// refusal: the backend forged a segment to the public recipients.
//
// The verifying set includes this machine's own key, which is the only one that
// ever legitimately appears here: fetchEscrowedSegments lists audit/<this
// machine>/ and nothing else, so every segment it hands us is self-signed.
func verifyEscrowSegment(s segment) error {
	set, _, err := trustedSigners()
	if err != nil {
		if errors.Is(err, storesign.ErrCorrupt) {
			return fmt.Errorf("store-signer pin is corrupt; refusing escrow: %w", err)
		}
		return err
	}
	if len(set) == 0 {
		return nil // no pin and no local key: M2 rehash is the only check
	}
	if s.Signature == "" && s.Signer == "" {
		return nil // legacy unsigned segment
	}
	unsigned := s
	unsigned.Signature, unsigned.Signer = "", ""
	raw, err := json.Marshal(unsigned)
	if err != nil {
		return err
	}
	return checkSignature(raw, remote.Rev{Signature: s.Signature, Signer: s.Signer}, set)
}
