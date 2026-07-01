package store

import (
	"path/filepath"
	"testing"
	"time"
)

// TestStoreRoundTrip guards that every Secret field — including the newer policy flags (canary,
// require-grant, rate limiting) — survives a Save/Load cycle through JSON. A dropped json tag or a
// renamed field would regress a policy silently; this catches it.
func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "store.json")
	created := time.Now().Add(-72 * time.Hour).UTC().Truncate(time.Second)
	updated := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	rot := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)

	s := New(p, []string{"age1recipientplaceholder"})
	s.Secrets["FULL"] = &Secret{
		Value:           "armored-ciphertext",
		CreatedAt:       created,
		UpdatedAt:       updated,
		Tags:            []string{"ci", "prod"},
		Description:     "a fully-populated secret",
		RotateAfter:     &rot,
		ExpiresAt:       &exp,
		NoPrint:         true,
		RequireApproval: true,
		Canary:          true,
		RequireGrant:    true,
		RateLimit:       10,
		RateWindow:      "1h",
		Meta:            map[string]string{"team": "sre"},
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	sec := got.Secrets["FULL"]
	if sec == nil {
		t.Fatal("secret vanished on reload")
	}
	if sec.Value != "armored-ciphertext" || sec.Description != "a fully-populated secret" {
		t.Fatalf("value/description lost: %+v", sec)
	}
	if !sec.CreatedAt.Equal(created) || !sec.UpdatedAt.Equal(updated) {
		t.Fatalf("timestamps lost: created=%v updated=%v", sec.CreatedAt, sec.UpdatedAt)
	}
	if !sec.NoPrint || !sec.RequireApproval || !sec.Canary || !sec.RequireGrant {
		t.Fatalf("a policy bool was dropped: %+v", sec)
	}
	if sec.RateLimit != 10 || sec.RateWindow != "1h" {
		t.Fatalf("rate policy lost: limit=%d window=%q", sec.RateLimit, sec.RateWindow)
	}
	if len(sec.Tags) != 2 || sec.Tags[0] != "ci" || sec.Tags[1] != "prod" {
		t.Fatalf("tags lost: %v", sec.Tags)
	}
	if sec.Meta["team"] != "sre" {
		t.Fatalf("meta lost: %v", sec.Meta)
	}
	if sec.RotateAfter == nil || !sec.RotateAfter.Equal(rot) {
		t.Fatalf("rotate_after lost: %v", sec.RotateAfter)
	}
	if sec.ExpiresAt == nil || !sec.ExpiresAt.Equal(exp) {
		t.Fatalf("expires_at lost: %v", sec.ExpiresAt)
	}
}
