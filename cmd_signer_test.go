package main

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/arenzana/arca/internal/audit"
	"github.com/arenzana/arca/internal/remote"
	"github.com/arenzana/arca/internal/store"
	"github.com/arenzana/arca/internal/storesign"
	"github.com/arenzana/arca/internal/xdg"
)

// TestSignerShowIsHeadlessAndPublic: show prints the public key, generates the
// key file at 0600 on first use, and does not require a terminal.
func TestSignerShowIsHeadlessAndPublic(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	withNoTTY(t)
	out := strings.TrimSpace(runArca(t, "", "signer", "show"))
	if _, err := storesign.DecodePub(out); err != nil {
		t.Fatalf("signer show printed %q, not a public key: %v", out, err)
	}
	st, err := os.Stat(storeSigningKeyPath())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" { // Windows governs access by ACL, not 0600
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("store-signing.key mode = %o, want 0600", st.Mode().Perm())
		}
	}
	// Second show is the same key.
	if again := strings.TrimSpace(runArca(t, "", "signer", "show")); again != out {
		t.Fatalf("signer show is not stable: %q then %q", out, again)
	}
}

// TestSignerShowRefusesACorruptKey is the L3 invariant: a truncated key file
// must not be silently regenerated.
func TestSignerShowRefusesACorruptKey(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	if err := os.MkdirAll(storeStateDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storeSigningKeyPath(), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runArcaErr("", "signer", "show")
	if err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("corrupt key = %v, want a corrupt refusal", err)
	}
}

// TestVerifyPulledStoreCorruptPin: a garbage pin is a hard refusal, never auto-healed.
func TestVerifyPulledStoreCorruptPin(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	if err := os.MkdirAll(storeStateDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storeSignerPinPath(), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := verifyPulledStore([]byte("payload"), remote.Rev{})
	if err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("corrupt pin = %v, want a corrupt refusal", err)
	}
}

// TestSignStorePayloadCorruptKey: the push-side warning path when the key file is bad.
func TestSignStorePayloadCorruptKey(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	if err := os.MkdirAll(storeStateDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storeSigningKeyPath(), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if a := signStorePayload([]byte("x")); !a.Zero() {
		t.Fatalf("corrupt key should produce zero auth (unsigned push with warning), got %+v", a)
	}
}

// TestVerifyEscrowSegmentPaths: no pin accepts everything; a pin accepts legacy
// unsigned segments and rejects mismatched signers; a corrupt pin refuses.
func TestVerifyEscrowSegmentPaths(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	seg := segment{Seq: 1}
	// No pin: anything passes (M2 rehash is the only check).
	if err := verifyEscrowSegment(seg); err != nil {
		t.Fatalf("no pin should accept unsigned: %v", err)
	}
	// Pin present: legacy unsigned segment still passes.
	k, err := loadOrCreateStoreKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyEscrowSegment(seg); err != nil {
		t.Fatalf("pin + legacy unsigned should pass: %v", err)
	}
	// Pin present: a segment signed by a DIFFERENT key is refused.
	other, err := storesign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(seg)
	signed := seg
	signed.Signature = storesign.Encode(storesign.Sign(other.Priv, raw))
	signed.Signer = storesign.EncodePub(other.Pub)
	if err := verifyEscrowSegment(signed); err == nil || !strings.Contains(err.Error(), "not one of this machine's trusted signers") {
		t.Fatalf("foreign-signed segment = %v, want a signer refusal", err)
	}
	// A correctly-signed segment passes.
	signed.Signature = storesign.Encode(storesign.Sign(k.Priv, raw))
	signed.Signer = storesign.EncodePub(k.Pub)
	if err := verifyEscrowSegment(signed); err != nil {
		t.Fatalf("correctly-signed segment should pass: %v", err)
	}
}

// TestLogUseQuotaTranslations covers logUseQuotas' error translation branches
// directly (the concurrency-safe paths only fire under real contention).
func TestLogUseQuotaTranslations(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "API")
	// Rate cap over quota: the refusal is recorded as op=ratelimit.
	sec := &store.Secret{RateLimit: 1, RateWindow: "1h"}
	q := []audit.Quota{{Kind: "rate", Ops: []string{"read"}, Since: time.Now().Add(-time.Hour), Max: 1}}
	if err := logUseQuotas("read", "API", "", sec, q); err != nil {
		t.Fatalf("first use should pass: %v", err)
	}
	err := logUseQuotas("read", "API", "", sec, q)
	if err == nil || !strings.Contains(err.Error(), "rate limit reached") {
		t.Fatalf("second use = %v, want a rate refusal", err)
	}
	// Grant cap over quota: refusal names the grant.
	gq := []audit.Quota{{Kind: "grant", Ops: []string{"exec"}, Since: time.Now().Add(-time.Hour), Max: 1}}
	if err := logUseQuotas("exec", "DEPLOY", "true", sec, gq); err != nil {
		t.Fatalf("first exec should pass: %v", err)
	}
	err = logUseQuotas("exec", "DEPLOY", "true", sec, gq)
	if err == nil || !strings.Contains(err.Error(), "grant") {
		t.Fatalf("second exec = %v, want a grant refusal", err)
	}
}

// TestSignerPinWritesAndShowMatches pins the shown key and re-reads it.
func TestSignerPinWritesAndShowMatches(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	pub := strings.TrimSpace(runArca(t, "", "signer", "show"))
	runArca(t, "", "signer", "pin", pub)
	got, err := storesign.LoadPinSet(storeSignerPinPath())
	if err != nil {
		t.Fatal(err)
	}
	want, err := storesign.DecodePub(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Contains(want) {
		t.Fatalf("pin set = %s, want it to contain %s", got, pub)
	}
	st, err := os.Stat(storeSignerPinPath())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" { // Windows governs access by ACL, not 0600
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("pin mode = %o, want 0600", st.Mode().Perm())
		}
	}
}

func TestSignerPinRejectsGarbage(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	if err := runArcaErr("", "signer", "pin", "not-a-key"); err == nil {
		t.Fatal("signer pin accepted garbage")
	}
}

func TestSignerRotateChangesTheKey(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	before := strings.TrimSpace(runArca(t, "", "signer", "show"))
	runArca(t, "", "signer", "rotate")
	after := strings.TrimSpace(runArca(t, "", "signer", "show"))
	if before == after {
		t.Fatal("signer rotate left the public key unchanged")
	}
	set, err := storesign.LoadPinSet(storeSignerPinPath())
	if err != nil {
		t.Fatal(err)
	}
	newPub, err := storesign.DecodePub(after)
	if err != nil {
		t.Fatal(err)
	}
	if !set.Contains(newPub) {
		t.Fatalf("rotate did not trust the new key: set=%s show=%s", set, after)
	}
	// The outgoing key stays trusted: this machine's escrow history is signed
	// with it, and dropping it would make its own past segments unverifiable.
	oldPub, err := storesign.DecodePub(before)
	if err != nil {
		t.Fatal(err)
	}
	if !set.Contains(oldPub) {
		t.Fatalf("rotate dropped the retired key %s from the set (%s)", before, set)
	}
}

// TestPushSignsTheStore is H1 slice 2: a push writes Arca-Signature / Arca-Signer
// metadata that verifies against the local key over the exact store bytes.
func TestPushSignsTheStore(t *testing.T) {
	sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "API")
	runArca(t, "", "sync")

	head, err := fake.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if head.Signature == "" || head.Signer == "" {
		t.Fatalf("push left the head unsigned: %+v", head)
	}
	k, err := storesign.Load(storeSigningKeyPath())
	if err != nil {
		t.Fatal(err)
	}
	if head.Signer != storesign.EncodePub(k.Pub) {
		t.Fatalf("Arca-Signer = %s, want %s", head.Signer, storesign.EncodePub(k.Pub))
	}
	raw, err := os.ReadFile(xdg.StorePath())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := storesign.Decode(head.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if !storesign.Verify(k.Pub, raw, sig) {
		t.Fatal("head signature does not verify over the local store bytes")
	}
}

// TestPullRefusesWhenPinnedAndUnsigned: a pin makes an unsigned head a hard refusal,
// and --force must not override it (audit H1 / L8).
func TestPullRefusesWhenPinnedAndUnsigned(t *testing.T) {
	sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "API")
	runArca(t, "", "sync")
	fake.StripAuth()
	// Same generation would be "in sync" and skip the pull; drop the local
	// store so this is a bootstrap pull of an unsigned head against a pin.
	if err := os.Remove(xdg.StorePath()); err != nil {
		t.Fatal(err)
	}
	err := runArcaErr("", "sync", "--pull")
	if err == nil || !strings.Contains(err.Error(), "unsigned") {
		t.Fatalf("unsigned head with a pin = %v, want an unsigned refusal", err)
	}
	if err := runArcaErr("", "sync", "--pull", "--force"); err == nil || !strings.Contains(err.Error(), "unsigned") {
		t.Fatalf("--force overrode a missing signature: %v", err)
	}
}

func TestPullRefusesABadSignature(t *testing.T) {
	sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "API")
	runArca(t, "", "sync")
	head, _ := fake.Head(context.Background())
	fake.SetAuth(remote.StoreAuth{Signature: storesign.Encode([]byte("not-a-real-signature-at-all-pad!!")), Signer: head.Signer})
	if err := os.Remove(xdg.StorePath()); err != nil {
		t.Fatal(err)
	}
	err := runArcaErr("", "sync", "--pull")
	if err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("bad signature = %v, want a verify refusal", err)
	}
}

func TestPullRefusesADifferentSigner(t *testing.T) {
	sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "API")
	runArca(t, "", "sync")
	other, err := storesign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	fake.SetAuth(remote.StoreAuth{Signature: "x", Signer: storesign.EncodePub(other.Pub)})
	if err := os.Remove(xdg.StorePath()); err != nil {
		t.Fatal(err)
	}
	err = runArcaErr("", "sync", "--pull")
	if err == nil || !strings.Contains(err.Error(), "not one of this machine's trusted signers") {
		t.Fatalf("foreign signer = %v, want a rotation refusal", err)
	}
}

func TestPullUnsignedWithoutPinIsAWarning(t *testing.T) {
	sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "API")
	runArca(t, "", "sync")
	// The migration window is a machine that has never signed and trusts no
	// one: drop both the pin and this machine's signing key. Holding a key is
	// itself a trust decision, so leaving it would (correctly) refuse the pull.
	fake.StripAuth()
	if err := os.Remove(storeSignerPinPath()); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Remove(storeSigningKeyPath()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(xdg.StorePath()); err != nil {
		t.Fatal(err)
	}
	if err := runArcaErr("", "sync", "--pull"); err != nil {
		t.Fatalf("unsigned + no pin should still pull (migration): %v", err)
	}
}

// TestCrossPinnedMachineStillVerifiesItsOwnEscrow is the regression for the
// defect this set replaces.
//
// Every machine mints its own signing key, so a two-machine fleet has two
// signers. Under the old single pin the only way to make store sync work was
// for each machine to pin the OTHER — after which neither trusted itself.
// fetchEscrowedSegments only ever reads audit/<this machine>/, so every segment
// it verifies is self-signed: the machine refused its own escrow history,
// reconcileEscrowCursor could never complete, and a behind cursor warned on
// every invocation forever.
func TestCrossPinnedMachineStillVerifiesItsOwnEscrow(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	mine, err := loadOrCreateStoreKey()
	if err != nil {
		t.Fatal(err)
	}
	// Trust ONLY the peer — the cross-pinned state a two-machine fleet is
	// forced into.
	peer, err := storesign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	runArca(t, "", "signer", "add", storesign.EncodePub(peer.Pub))
	set, err := storesign.LoadPinSet(storeSignerPinPath())
	if err != nil {
		t.Fatal(err)
	}
	if set.Contains(mine.Pub) {
		t.Fatal("precondition: the pin file must NOT list this machine's own key")
	}

	seg := segment{Seq: 1}
	raw, _ := json.Marshal(seg)
	seg.Signature = storesign.Encode(storesign.Sign(mine.Priv, raw))
	seg.Signer = storesign.EncodePub(mine.Pub)
	if err := verifyEscrowSegment(seg); err != nil {
		t.Fatalf("machine refused its own escrow segment: %v", err)
	}
	// The peer's signature is still good, and an unrelated key is still refused.
	peerSeg := segment{Seq: 1}
	peerSeg.Signature = storesign.Encode(storesign.Sign(peer.Priv, raw))
	peerSeg.Signer = storesign.EncodePub(peer.Pub)
	if err := verifyEscrowSegment(peerSeg); err != nil {
		t.Fatalf("trusted peer's segment refused: %v", err)
	}
	stranger, err := storesign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	bad := segment{Seq: 1}
	bad.Signature = storesign.Encode(storesign.Sign(stranger.Priv, raw))
	bad.Signer = storesign.EncodePub(stranger.Pub)
	if err := verifyEscrowSegment(bad); err == nil {
		t.Fatal("an untrusted key's segment was accepted")
	}
}

// TestSignerAddIsAdditive: adding a peer must not evict what is already
// trusted. The old `pin` replaced the single key, which is exactly how a fleet
// ended up cross-pinned.
func TestSignerAddIsAdditive(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	a, err := storesign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := storesign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	runArca(t, "", "signer", "add", storesign.EncodePub(a.Pub), "--label", "daintree")
	runArca(t, "", "signer", "add", storesign.EncodePub(b.Pub), "--label", "urbis")
	set, err := storesign.LoadPinSet(storeSignerPinPath())
	if err != nil {
		t.Fatal(err)
	}
	if !set.Contains(a.Pub) || !set.Contains(b.Pub) {
		t.Fatalf("add evicted an earlier key: %s", set)
	}
	if set.Labeled(a.Pub) != "daintree" || set.Labeled(b.Pub) != "urbis" {
		t.Fatalf("labels not persisted: %s", set)
	}
	// A pull signed by EITHER trusted machine verifies.
	for _, k := range []*storesign.Key{a, b} {
		payload := []byte("store bytes")
		rev := remote.Rev{
			Signature: storesign.Encode(storesign.Sign(k.Priv, payload)),
			Signer:    storesign.EncodePub(k.Pub),
		}
		if err := verifyPulledStore(payload, rev); err != nil {
			t.Fatalf("store signed by a trusted machine was refused: %v", err)
		}
	}
}

// TestSignerRmRefusesTheLastKey: emptying the set would silently reopen the
// window in which an unsigned store is accepted.
func TestSignerRmRefusesTheLastKey(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	a, err := storesign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	runArca(t, "", "signer", "add", storesign.EncodePub(a.Pub))
	if err := runArcaErr("", "signer", "rm", storesign.EncodePub(a.Pub)); err == nil {
		t.Fatal("rm emptied the trusted signer set")
	}
	b, err := storesign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	runArca(t, "", "signer", "add", storesign.EncodePub(b.Pub))
	runArca(t, "", "signer", "rm", storesign.EncodePub(a.Pub))
	set, err := storesign.LoadPinSet(storeSignerPinPath())
	if err != nil {
		t.Fatal(err)
	}
	if set.Contains(a.Pub) || !set.Contains(b.Pub) {
		t.Fatalf("rm removed the wrong key: %s", set)
	}
}

// TestLegacySinglePinIsHonoredAndMigrated: an existing machine keeps its trust
// decision across the upgrade, and the first write leaves exactly one
// authoritative file.
func TestLegacySinglePinIsHonoredAndMigrated(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	if err := os.Remove(storeSigningKeyPath()); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	peer, err := storesign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(storeStateDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := storesign.SavePin(legacyStoreSignerPinPath(), peer.Pub); err != nil {
		t.Fatal(err)
	}
	payload := []byte("store bytes")
	rev := remote.Rev{
		Signature: storesign.Encode(storesign.Sign(peer.Priv, payload)),
		Signer:    storesign.EncodePub(peer.Pub),
	}
	if err := verifyPulledStore(payload, rev); err != nil {
		t.Fatalf("legacy single pin not honored: %v", err)
	}
	// Adding a second machine migrates the file; the superseded one is gone so
	// two files can never disagree about who is trusted.
	other, err := storesign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	runArca(t, "", "signer", "add", storesign.EncodePub(other.Pub))
	set, err := storesign.LoadPinSet(storeSignerPinPath())
	if err != nil {
		t.Fatal(err)
	}
	if !set.Contains(peer.Pub) || !set.Contains(other.Pub) {
		t.Fatalf("migration lost a key: %s", set)
	}
	if _, err := os.Stat(legacyStoreSignerPinPath()); !os.IsNotExist(err) {
		t.Fatalf("legacy pin file survived migration: %v", err)
	}
}

// TestHoldingASigningKeyClosesTheUnsignedWindow: a machine that has signed a
// push must never accept an unsigned head back — stripping the signature would
// otherwise be a silent downgrade.
func TestHoldingASigningKeyClosesTheUnsignedWindow(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	if _, err := loadOrCreateStoreKey(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(storeSignerPinPath()); !os.IsNotExist(err) {
		t.Fatalf("minting a key should not write a pin file: %v", err)
	}
	err := verifyPulledStore([]byte("store bytes"), remote.Rev{})
	if err == nil || !strings.Contains(err.Error(), "unsigned") {
		t.Fatalf("unsigned head with a local signing key = %v, want a refusal", err)
	}
}

// TestSignerListShowsTheSetAndMarksLocal keeps the read-only inspection path
// headless: seeing the trust state must not need an operator ceremony.
func TestSignerListShowsTheSetAndMarksLocal(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	withNoTTY(t)
	mine := strings.TrimSpace(runArca(t, "", "signer", "show"))
	out := runArca(t, "", "signer", "list")
	if !strings.Contains(out, "* "+mine) {
		t.Fatalf("list did not mark this machine's own key:\n%s", out)
	}
}

// TestSignerAddIsIdempotent: re-adding a trusted key is a no-op, not a second
// entry and not an operator prompt.
func TestSignerAddIsIdempotent(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	k, err := storesign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pub := storesign.EncodePub(k.Pub)
	runArca(t, "", "signer", "add", pub)
	withNoTTY(t) // a no-op must not need a terminal
	runArca(t, "", "signer", "add", pub)
	set, err := storesign.LoadPinSet(storeSignerPinPath())
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 1 {
		t.Fatalf("re-adding duplicated the entry: %s", set)
	}
}

// TestSignerRmUnknownKeyRefuses: rm must not silently succeed on a key that was
// never trusted — that would read as "it's gone" when nothing changed.
func TestSignerRmUnknownKeyRefuses(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	a, err := storesign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	runArca(t, "", "signer", "add", storesign.EncodePub(a.Pub))
	stranger, err := storesign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := runArcaErr("", "signer", "rm", storesign.EncodePub(stranger.Pub)); err == nil {
		t.Fatal("rm of an untrusted key should refuse")
	}
	if err := runArcaErr("", "signer", "rm", "not-a-key"); err == nil {
		t.Fatal("rm of a malformed key should refuse")
	}
}

// TestCorruptPinRefusesEveryPath: a corrupt pin file is never auto-healed, and
// it must fail closed on all four paths — pull, escrow, add and rm. Silently
// treating it as "no pin" would reopen the unsigned window (audit L3).
func TestCorruptPinRefusesEveryPath(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	if err := os.MkdirAll(storeStateDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storeSignerPinPath(), []byte("not-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyPulledStore([]byte("x"), remote.Rev{}); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("pull with a corrupt pin = %v, want a corruption refusal", err)
	}
	if err := verifyEscrowSegment(segment{Seq: 1, Signature: "x", Signer: "y"}); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("escrow with a corrupt pin = %v, want a corruption refusal", err)
	}
	k, err := storesign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := runArcaErr("", "signer", "add", storesign.EncodePub(k.Pub)); err == nil {
		t.Fatal("add over a corrupt pin should refuse rather than rewrite it")
	}
	if err := runArcaErr("", "signer", "rm", storesign.EncodePub(k.Pub)); err == nil {
		t.Fatal("rm over a corrupt pin should refuse rather than rewrite it")
	}
}

// TestCorruptLegacyPinRefuses: the same, for a machine still on the pre-0.12
// single-key file. The migration read must not launder corruption into "no pin".
func TestCorruptLegacyPinRefuses(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	if err := os.MkdirAll(storeStateDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyStoreSignerPinPath(), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyPulledStore([]byte("x"), remote.Rev{}); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("pull with a corrupt legacy pin = %v, want a corruption refusal", err)
	}
	k, err := storesign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := runArcaErr("", "signer", "add", storesign.EncodePub(k.Pub)); err == nil {
		t.Fatal("add over a corrupt legacy pin should refuse")
	}
}

// TestMalformedSignatureMetadataIsRefused: the signer name and signature travel
// with the object, so both are attacker-controlled strings. Neither may reach a
// verify with a claimed-but-unparseable value.
func TestMalformedSignatureMetadataIsRefused(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	k, err := loadOrCreateStoreKey()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("store bytes")
	good := storesign.Encode(storesign.Sign(k.Priv, payload))

	cases := []struct {
		name, sig, signer, want string
	}{
		{"malformed signer", good, "!!!not-base64!!!", "Arca-Signer is malformed"},
		{"malformed signature", "!!!not-base64!!!", storesign.EncodePub(k.Pub), "Arca-Signature is malformed"},
		{"wrong signature bytes", storesign.Encode(make([]byte, 64)), storesign.EncodePub(k.Pub), "does not verify"},
		{"signature only", good, "", "unsigned"},
		{"signer only", "", storesign.EncodePub(k.Pub), "unsigned"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyPulledStore(payload, remote.Rev{Signature: tc.sig, Signer: tc.signer})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("= %v, want %q", err, tc.want)
			}
		})
	}
}
