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
	if err := verifyEscrowSegment(signed); err == nil || !strings.Contains(err.Error(), "not the pinned signer") {
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
	got, err := storesign.LoadPin(storeSignerPinPath())
	if err != nil {
		t.Fatal(err)
	}
	want, err := storesign.DecodePub(pub)
	if err != nil {
		t.Fatal(err)
	}
	if storesign.EncodePub(got) != storesign.EncodePub(want) {
		t.Fatalf("pin = %s, want %s", storesign.EncodePub(got), pub)
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
	pin, err := storesign.LoadPin(storeSignerPinPath())
	if err != nil {
		t.Fatal(err)
	}
	if storesign.EncodePub(pin) != after {
		t.Fatalf("rotate did not re-pin: pin=%s show=%s", storesign.EncodePub(pin), after)
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
	if err == nil || !strings.Contains(err.Error(), "not the pinned signer") {
		t.Fatalf("foreign signer = %v, want a rotation refusal", err)
	}
}

func TestPullUnsignedWithoutPinIsAWarning(t *testing.T) {
	sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "API")
	runArca(t, "", "sync")
	// Drop the pin but leave the head unsigned — the migration window.
	fake.StripAuth()
	if err := os.Remove(storeSignerPinPath()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(xdg.StorePath()); err != nil {
		t.Fatal(err)
	}
	if err := runArcaErr("", "sync", "--pull"); err != nil {
		t.Fatalf("unsigned + no pin should still pull (migration): %v", err)
	}
}
