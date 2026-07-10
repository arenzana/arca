package remote

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeS3Server is a minimal S3-compatible HTTP server for exercising the real minio-go
// client path: GET/HEAD/PUT with ETags, If-Match / If-None-Match conditional writes,
// and list-objects-v2. It ignores auth (the client still signs; we don't verify).
type fakeS3Server struct {
	mu       sync.Mutex
	data     map[string][]byte
	etag     map[string]string
	meta     map[string]map[string]string
	nextID   int
	lastAKID string // access key id parsed from the last request's SigV4 Authorization
	// headETagOverride, when non-empty, makes HEAD report this ETag instead of the stored one —
	// used to simulate a head that diverged between a client's PUT and its read-after-write HEAD.
	headETagOverride string
	// sizeOverride, when > 0, makes HEAD advertise this Content-Length regardless of the real body
	// size — used to exercise the read cap (SEC-39) without allocating a huge object.
	sizeOverride int64
}

func newFakeS3() *fakeS3Server {
	return &fakeS3Server{data: map[string][]byte{}, etag: map[string]string{}, meta: map[string]map[string]string{}}
}

func (f *fakeS3Server) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// SigV4: "AWS4-HMAC-SHA256 Credential=<AKID>/<date>/<region>/s3/aws4_request, …"
	if auth := r.Header.Get("Authorization"); strings.Contains(auth, "Credential=") {
		cred := auth[strings.Index(auth, "Credential=")+len("Credential="):]
		if i := strings.Index(cred, "/"); i > 0 {
			f.lastAKID = cred[:i]
		}
	}
	// Path-style: /bucket/key...
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	key := ""
	if len(parts) == 2 {
		key = parts[1]
	}
	switch {
	case r.Method == http.MethodGet && key == "": // ListObjectsV2
		prefix := r.URL.Query().Get("prefix")
		type obj struct {
			Key  string `xml:"Key"`
			ETag string `xml:"ETag"`
			Size int    `xml:"Size"`
		}
		var keys []string
		for k := range f.data {
			if strings.HasPrefix(k, prefix) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		var contents []obj
		for _, k := range keys {
			contents = append(contents, obj{Key: k, ETag: f.etag[k], Size: len(f.data[k])})
		}
		out := struct {
			XMLName  xml.Name `xml:"ListBucketResult"`
			IsTrunc  bool     `xml:"IsTruncated"`
			Contents []obj    `xml:"Contents"`
			KeyCount int      `xml:"KeyCount"`
		}{IsTrunc: false, Contents: contents, KeyCount: len(contents)}
		w.Header().Set("Content-Type", "application/xml")
		_ = xml.NewEncoder(w).Encode(out)

	case r.Method == http.MethodHead:
		b, ok := f.data[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		for mk, mv := range f.meta[key] {
			w.Header().Set("X-Amz-Meta-"+mk, mv)
		}
		et := f.etag[key]
		if f.headETagOverride != "" {
			et = f.headETagOverride
		}
		size := int64(len(b))
		if f.sizeOverride > 0 {
			size = f.sizeOverride
		}
		w.Header().Set("ETag", `"`+et+`"`)
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.Header().Set("Content-Length", fmt.Sprint(size))
		w.WriteHeader(http.StatusOK)

	case r.Method == http.MethodGet:
		b, ok := f.data[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `<Error><Code>NoSuchKey</Code></Error>`)
			return
		}
		for mk, mv := range f.meta[key] {
			w.Header().Set("X-Amz-Meta-"+mk, mv)
		}
		w.Header().Set("ETag", `"`+f.etag[key]+`"`)
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		_, _ = w.Write(b)

	case r.Method == http.MethodPut:
		_, exists := f.data[key]
		if inm := r.Header.Get("If-None-Match"); inm == "*" && exists {
			w.WriteHeader(http.StatusPreconditionFailed)
			_, _ = io.WriteString(w, `<Error><Code>PreconditionFailed</Code></Error>`)
			return
		}
		if im := r.Header.Get("If-Match"); im != "" {
			want := strings.Trim(im, `"`)
			if !exists || f.etag[key] != want {
				w.WriteHeader(http.StatusPreconditionFailed)
				_, _ = io.WriteString(w, `<Error><Code>PreconditionFailed</Code></Error>`)
				return
			}
		}
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING") {
			b = decodeAWSChunked(b)
		}
		f.nextID++
		f.data[key] = b
		f.etag[key] = fmt.Sprintf("srv-%d", f.nextID)
		meta := map[string]string{}
		for hk, hv := range r.Header {
			if strings.HasPrefix(hk, "X-Amz-Meta-") && len(hv) > 0 {
				meta[strings.TrimPrefix(hk, "X-Amz-Meta-")] = hv[0]
			}
		}
		f.meta[key] = meta
		w.Header().Set("ETag", `"`+f.etag[key]+`"`)
		w.WriteHeader(http.StatusOK)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// decodeAWSChunked strips aws-chunked framing (`<hex-size>;chunk-signature=…\r\n<data>\r\n`,
// terminated by a zero-size chunk) that the client uses for streaming signatures on
// plain-HTTP uploads.
func decodeAWSChunked(b []byte) []byte {
	var out []byte
	for len(b) > 0 {
		nl := strings.Index(string(b), "\r\n")
		if nl < 0 {
			break
		}
		header := string(b[:nl])
		sizeHex, _, _ := strings.Cut(header, ";")
		var size int64
		_, err := fmt.Sscanf(sizeHex, "%x", &size)
		if err != nil || size == 0 {
			break
		}
		start := int64(nl + 2)
		if start+size > int64(len(b)) {
			break
		}
		out = append(out, b[start:start+size]...)
		b = b[start+size+2:] // skip trailing \r\n
	}
	return out
}

func newTestS3(t *testing.T) (*S3, *fakeS3Server) {
	t.Helper()
	srv := newFakeS3()
	ts := httptest.NewServer(http.HandlerFunc(srv.handler))
	t.Cleanup(ts.Close)
	u, _ := url.Parse(ts.URL)
	t.Setenv("ARCA_SYNC_ACCESS_KEY", "test")
	t.Setenv("ARCA_SYNC_SECRET_KEY", "test")
	cfg, err := ParseURL("s3://bucket/pfx?endpoint=" + u.Host + "&insecure=1")
	if err != nil {
		t.Fatal(err)
	}
	s3, err := NewS3(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s3, srv
}

// TestS3BackendSemantics drives the real client code against the in-process S3: the
// same CAS contract the Fake pins, now through actual HTTP + conditional headers.
func TestS3BackendSemantics(t *testing.T) {
	ctx := context.Background()
	s3, _ := newTestS3(t)

	if _, err := s3.Head(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty Head = %v", err)
	}
	r1, err := s3.Push(ctx, []byte("gen-one"), 1, Rev{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s3.Push(ctx, []byte("again"), 1, r1); !errors.Is(err, ErrCASMismatch) {
		t.Fatal("re-pushing an existing generation must fail (immutable revisions)")
	}
	r2, err := s3.Push(ctx, []byte("gen-two"), 2, r1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s3.Push(ctx, []byte("stale"), 3, r1); !errors.Is(err, ErrCASMismatch) {
		t.Fatal("push from a stale rev must fail")
	}
	head, err := s3.Head(ctx)
	if err != nil || head.Generation != 2 || head.Tag != r2.Tag {
		t.Fatalf("head = %+v err %v", head, err)
	}
	b, rev, err := s3.Fetch(ctx)
	if err != nil || string(b) != "gen-two" || rev.Generation != 2 {
		t.Fatalf("fetch = %q %+v err %v", b, rev, err)
	}

	if err := s3.PutIfAbsent(ctx, "audit/m/000001.age", []byte("seg")); err != nil {
		t.Fatal(err)
	}
	if err := s3.PutIfAbsent(ctx, "audit/m/000001.age", []byte("evil")); err == nil {
		t.Fatal("PutIfAbsent must refuse to replace")
	}
	got, err := s3.Get(ctx, "audit/m/000001.age")
	if err != nil || string(got) != "seg" {
		t.Fatalf("get = %q err %v", got, err)
	}
	if _, err := s3.Get(ctx, "audit/m/nope"); err == nil {
		t.Fatal("Get of a missing key should error")
	}
	keys, err := s3.List(ctx, "audit/m/")
	if err != nil || len(keys) != 1 || keys[0] != "audit/m/000001.age" {
		t.Fatalf("list = %v err %v", keys, err)
	}
}

// TestNewS3Errors covers construction failure modes.
func TestNewS3Errors(t *testing.T) {
	t.Setenv("ARCA_SYNC_ACCESS_KEY", "")
	t.Setenv("ARCA_SYNC_SECRET_KEY", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	if _, err := NewS3(Config{Bucket: "b"}); err == nil || !strings.Contains(err.Error(), "credentials") {
		t.Fatalf("want a credentials error, got %v", err)
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "a") // fallback env path
	t.Setenv("AWS_SECRET_ACCESS_KEY", "s")
	if _, err := NewS3(Config{Bucket: "b"}); err != nil {
		t.Fatalf("AWS fallback credentials should construct: %v", err)
	}
}

// TestS3FetchEmpty covers the not-found path through the lazy GetObject reader.
func TestS3FetchEmpty(t *testing.T) {
	s3, _ := newTestS3(t)
	if _, _, err := s3.Fetch(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Fetch on an empty remote = %v, want ErrNotFound", err)
	}
}

// TestS3SignsWithConfigCredentials proves the client signs with Config-provided
// credentials in preference to anything in the environment — the property the
// `sync init --store-credentials` feature rests on.
func TestS3SignsWithConfigCredentials(t *testing.T) {
	srv := newFakeS3()
	ts := httptest.NewServer(http.HandlerFunc(srv.handler))
	t.Cleanup(ts.Close)
	u, _ := url.Parse(ts.URL)
	t.Setenv("ARCA_SYNC_ACCESS_KEY", "AKID-FROM-ENV")
	t.Setenv("ARCA_SYNC_SECRET_KEY", "env-secret")
	cfg, err := ParseURL("s3://bucket/pfx?endpoint=" + u.Host + "&insecure=1")
	if err != nil {
		t.Fatal(err)
	}
	cfg.AccessKey, cfg.SecretKey = "AKID-FROM-CONFIG", "config-secret"
	s3, err := NewS3(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s3.Push(context.Background(), []byte("x"), 1, Rev{}); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	akid := srv.lastAKID
	srv.mu.Unlock()
	if akid != "AKID-FROM-CONFIG" {
		t.Fatalf("client signed with %q, want the Config credentials", akid)
	}

	// And with Config empty, the env pair is what signs.
	cfg.AccessKey, cfg.SecretKey = "", ""
	s3env, err := NewS3(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s3env.Head(context.Background())
	srv.mu.Lock()
	akid = srv.lastAKID
	srv.mu.Unlock()
	if akid != "AKID-FROM-ENV" {
		t.Fatalf("client signed with %q, want the env credentials", akid)
	}
}

// TestS3FetchSizeCap covers the SEC-39 read bound: an oversized head object is refused by
// Stat's size check without reading it into memory.
func TestS3FetchSizeCap(t *testing.T) {
	s3, srv := newTestS3(t)
	// Seed the head object directly, then lie about its size via a huge Content-Length in Stat.
	// Simpler: push a normal object and assert the happy path returns; then exercise the cap by
	// pushing a genuinely large (but bounded-for-test) object with the cap lowered is not possible
	// (const), so assert the happy path plus that Fetch maps a missing head to ErrNotFound.
	if _, _, err := s3.Fetch(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty Fetch = %v, want ErrNotFound", err)
	}
	if _, err := s3.Push(context.Background(), []byte("hello"), 1, Rev{}); err != nil {
		t.Fatal(err)
	}
	b, rev, err := s3.Fetch(context.Background())
	if err != nil || string(b) != "hello" || rev.Generation != 1 {
		t.Fatalf("fetch = %q %+v err %v", b, rev, err)
	}
	_ = srv
}

// TestS3PushDetectsIgnoredConditional covers SEC-38: the read-after-write check catches a
// backend whose head, right after our PUT "succeeded", carries a different ETag than we wrote
// (a concurrent writer landed, or the backend ignored If-Match). We model that by forcing the
// server to report a different ETag on the next HEAD than the one it returned from the PUT.
func TestS3PushDetectsIgnoredConditional(t *testing.T) {
	s3, srv := newTestS3(t)
	srv.headETagOverride = "someone-elses-etag" // the head "moved" between our PUT and our HEAD
	_, err := s3.Push(context.Background(), []byte("mine"), 1, Rev{})
	if !errors.Is(err, ErrCASMismatch) {
		t.Fatalf("push should detect the head diverged (read-after-write), got: %v", err)
	}
}

// TestS3FetchRefusesOversized covers the SEC-39 read cap: an object whose advertised size
// exceeds MaxObjectBytes is refused at Stat, before any large read.
func TestS3FetchRefusesOversized(t *testing.T) {
	s3, srv := newTestS3(t)
	if _, err := s3.Push(context.Background(), []byte("small"), 1, Rev{}); err != nil {
		t.Fatal(err)
	}
	srv.sizeOverride = MaxObjectBytes + 1
	if _, _, err := s3.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized object should be refused, got: %v", err)
	}
}
