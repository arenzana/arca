// Package remote replicates opaque store envelopes to an untrusted network backend.
//
// The backend stores bytes and nothing else: envelopes are age-encrypted before they
// leave the machine (values AND metadata — a backend learns only sizes and timing),
// and every integrity property is checked client-side. Lost updates are prevented
// with compare-and-swap conditional writes; history is kept as immutable, create-only
// revision objects so a rollback of the remote head is both detectable and forensically
// recoverable. See docs/SYNC.md and the design note in the KB.
package remote

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Rev identifies one remote revision of the store envelope.
type Rev struct {
	Generation int    // store generation inside the envelope (client-asserted, re-checked on fetch)
	Tag        string // backend-native CAS token: S3 ETag, Postgres row id, …
}

// Zero reports whether r is the zero revision ("nothing known").
func (r Rev) Zero() bool { return r.Generation == 0 && r.Tag == "" }

// ErrCASMismatch is returned by Push when the remote head is not the revision the
// caller last saw — another machine pushed in between. Nothing was overwritten.
var ErrCASMismatch = errors.New("remote changed since last sync (concurrent push)")

// ErrNotFound is returned by Head/Fetch when the backend holds no envelope yet.
var ErrNotFound = errors.New("no store on the remote yet")

// Backend replicates envelopes. Implementations must be safe for sequential use by
// one process; arca is a short-lived single command and never shares a Backend.
type Backend interface {
	// Head returns the newest remote revision without fetching the envelope.
	Head(ctx context.Context) (Rev, error)
	// Fetch returns the newest envelope and its revision.
	Fetch(ctx context.Context) ([]byte, Rev, error)
	// Push uploads envelope as generation gen. prev is the CAS precondition: the
	// revision this client last saw (zero for a first-ever push). A concurrent
	// writer makes Push fail with ErrCASMismatch and nothing is lost — the
	// conflicting revision objects both survive for inspection.
	Push(ctx context.Context, envelope []byte, gen int, prev Rev) (Rev, error)
	// PutIfAbsent writes an auxiliary object (audit segments, escrowed anchors)
	// create-only: it fails if the key already exists. Keys are namespaced under
	// the backend's configured prefix.
	PutIfAbsent(ctx context.Context, key string, data []byte) error
	// Get reads an auxiliary object. ErrNotFound when absent.
	Get(ctx context.Context, key string) ([]byte, error)
	// List returns auxiliary object keys under a key prefix, lexically sorted.
	List(ctx context.Context, keyPrefix string) ([]string, error)
}

// Config is a parsed ARCA_SYNC_URL.
type Config struct {
	Scheme    string // "s3"
	Bucket    string
	Prefix    string // key prefix inside the bucket, no leading/trailing slash
	Endpoint  string // host[:port] for S3-compatible services (empty = AWS)
	Region    string
	Insecure  bool // plain HTTP (local MinIO/dev only)
	PathStyle bool // path-style addressing (MinIO default)

	// Credentials, when resolved by the caller (env or the 0600 state-dir sync
	// config). When empty, NewS3 falls back to the environment directly.
	AccessKey string
	SecretKey string
}

// ParseURL parses an arca sync URL:
//
//	s3://BUCKET[/PREFIX]?endpoint=HOST[:PORT]&region=R&insecure=1&pathstyle=1
//
// Credentials never appear in the URL; they come from the environment
// (ARCA_SYNC_ACCESS_KEY / ARCA_SYNC_SECRET_KEY, falling back to the standard
// AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY).
func ParseURL(raw string) (Config, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Config{}, fmt.Errorf("sync URL: %w", err)
	}
	if u.Scheme != "s3" {
		return Config{}, fmt.Errorf("sync URL: unsupported scheme %q (supported: s3)", u.Scheme)
	}
	if u.User != nil {
		return Config{}, errors.New("sync URL must not carry credentials; use ARCA_SYNC_ACCESS_KEY / ARCA_SYNC_SECRET_KEY")
	}
	c := Config{
		Scheme: u.Scheme,
		Bucket: u.Host,
		Prefix: strings.Trim(u.Path, "/"),
	}
	if c.Bucket == "" {
		return Config{}, errors.New("sync URL: missing bucket")
	}
	q := u.Query()
	c.Endpoint = q.Get("endpoint")
	c.Region = q.Get("region")
	c.Insecure, _ = strconv.ParseBool(q.Get("insecure"))
	c.PathStyle, _ = strconv.ParseBool(q.Get("pathstyle"))
	if c.Endpoint == "" && c.Region == "" {
		c.Region = "us-east-1"
	}
	// Path-style is what MinIO and most self-hosted S3 implementations expect.
	if c.Endpoint != "" {
		c.PathStyle = true
	}
	return c, nil
}

// key joins the configured prefix with a relative object key.
func (c Config) key(rel string) string {
	if c.Prefix == "" {
		return rel
	}
	return c.Prefix + "/" + rel
}

// Object keys under the prefix. Revision objects are immutable + create-only, so the
// mutable head can be re-derived and any conflict leaves both writers' work intact.
const (
	keyCurrent = "store/current"      // mutable head: the newest envelope (CAS target)
	keyRevs    = "store/revs/"        // keyRevs + <generation, zero-padded> + ".age"
	KeyAudit   = "audit/"             // audit/<machine-id>/<seq>.age (phase 1b)
	KeyAnchor  = "anchor/latest.json" // escrowed anchor token (non-secret)
)

// revKey renders the immutable revision key for a generation, zero-padded so
// lexical listing equals numeric ordering.
func revKey(gen int) string { return fmt.Sprintf("%s%012d.age", keyRevs, gen) }
