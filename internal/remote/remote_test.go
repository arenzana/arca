package remote

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestParseURL(t *testing.T) {
	c, err := ParseURL("s3://bucket/team/arca?endpoint=minio.local:9000&insecure=1")
	if err != nil {
		t.Fatal(err)
	}
	if c.Bucket != "bucket" || c.Prefix != "team/arca" || c.Endpoint != "minio.local:9000" || !c.Insecure || !c.PathStyle {
		t.Fatalf("parsed = %+v", c)
	}
	if c.key("store/current") != "team/arca/store/current" {
		t.Fatalf("key joining = %q", c.key("store/current"))
	}

	if _, err := ParseURL("s3://bucket"); err != nil {
		t.Fatalf("bare bucket should parse: %v", err)
	}
	for _, bad := range []string{
		"http://bucket/x",         // wrong scheme
		"s3:///prefix-only",       // no bucket
		"s3://user:pw@bucket/pfx", // credentials in URL are refused
	} {
		if _, err := ParseURL(bad); err == nil {
			t.Fatalf("ParseURL(%q) should fail", bad)
		}
	}
}

// TestFakeCASSemantics pins the contract the sync logic relies on; the S3 backend gets
// the same assertions against a real MinIO in the sync_e2e build.
func TestFakeCASSemantics(t *testing.T) {
	ctx := context.Background()
	f := NewFake()

	if _, err := f.Head(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty Head = %v, want ErrNotFound", err)
	}
	// First push requires the zero Rev.
	if _, err := f.Push(ctx, []byte("g1"), 1, Rev{Generation: 9, Tag: "stale"}); !errors.Is(err, ErrCASMismatch) {
		t.Fatal("push with a stale prev against an empty remote must fail")
	}
	r1, err := f.Push(ctx, []byte("g1"), 1, Rev{})
	if err != nil {
		t.Fatal(err)
	}
	// A second first-push (another bootstrapping machine) loses the race loudly.
	if _, err := f.Push(ctx, []byte("g1b"), 2, Rev{}); !errors.Is(err, ErrCASMismatch) {
		t.Fatal("second zero-prev push must fail")
	}
	// Normal CAS advance.
	r2, err := f.Push(ctx, []byte("g2"), 2, r1)
	if err != nil {
		t.Fatal(err)
	}
	// Pushing from the stale rev fails; nothing is overwritten.
	if _, err := f.Push(ctx, []byte("g2b"), 3, r1); !errors.Is(err, ErrCASMismatch) {
		t.Fatal("push from a stale rev must fail")
	}
	// A generation can never be re-pushed (immutable revision objects).
	if _, err := f.Push(ctx, []byte("again"), 2, r2); !errors.Is(err, ErrCASMismatch) {
		t.Fatal("re-pushing an existing generation must fail")
	}
	b, head, err := f.Fetch(ctx)
	if err != nil || string(b) != "g2" || head.Generation != 2 {
		t.Fatalf("fetch = %q gen %d err %v", b, head.Generation, err)
	}

	// Auxiliary objects are append-only.
	if err := f.PutIfAbsent(ctx, "audit/m1/000001.age", []byte("seg")); err != nil {
		t.Fatal(err)
	}
	dup := f.PutIfAbsent(ctx, "audit/m1/000001.age", []byte("evil"))
	if dup == nil {
		t.Fatal("PutIfAbsent must refuse to replace")
	}
	// The refusal must carry the ErrObjectExists sentinel (callers recover via errors.Is,
	// not by scraping the message) while still naming the key in its text.
	if !errors.Is(dup, ErrObjectExists) {
		t.Fatalf("PutIfAbsent collision must wrap ErrObjectExists, got: %v", dup)
	}
	if !strings.Contains(dup.Error(), "audit/m1/000001.age") || !strings.Contains(dup.Error(), "already exists") {
		t.Fatalf("collision message lost its detail: %v", dup)
	}
	keys, err := f.List(ctx, "audit/m1/")
	if err != nil || len(keys) != 1 || !strings.HasSuffix(keys[0], "000001.age") {
		t.Fatalf("list = %v err %v", keys, err)
	}
}

// TestFakeAuxiliaries covers the aux-object and test-hook surface in-package (Get,
// Delete, Corrupt), which the sync tests exercise only cross-package.
func TestFakeAuxiliaries(t *testing.T) {
	ctx := context.Background()
	f := NewFake()
	if _, err := f.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(missing) = %v", err)
	}
	if err := f.PutIfAbsent(ctx, "k", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if b, err := f.Get(ctx, "k"); err != nil || string(b) != "v" {
		t.Fatalf("Get = %q err %v", b, err)
	}
	f.Delete("k")
	if _, err := f.Get(ctx, "k"); !errors.Is(err, ErrNotFound) {
		t.Fatal("Delete did not remove the object")
	}
	f.Corrupt([]byte("older"), 1)
	b, head, err := f.Fetch(ctx)
	if err != nil || string(b) != "older" || head.Generation != 1 {
		t.Fatalf("after Corrupt: %q gen %d err %v", b, head.Generation, err)
	}
}

// TestKeyWithoutPrefix: a bare-bucket config joins keys without a leading slash.
func TestKeyWithoutPrefix(t *testing.T) {
	c, err := ParseURL("s3://justbucket")
	if err != nil {
		t.Fatal(err)
	}
	if got := c.key("store/current"); got != "store/current" {
		t.Fatalf("key without prefix = %q", got)
	}
	if c.Region == "" {
		t.Fatal("bare AWS URL should default a region")
	}
}
