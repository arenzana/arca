package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/arenzana/arca/internal/remote"
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
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("store-signing.key mode = %o, want 0600", st.Mode().Perm())
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
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("pin mode = %o, want 0600", st.Mode().Perm())
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
