package remote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// S3 implements Backend against any S3-compatible service (AWS, R2, MinIO, Garage).
//
// CAS relies on conditional writes: `If-Match: <etag>` when replacing the head and
// `If-None-Match: *` when creating objects. AWS S3, Cloudflare R2, and MinIO honor
// them; a service that silently ignores conditional headers degrades to last-writer-
// wins on the head object only — the immutable revision objects still make any
// conflict visible and recoverable, never silent data loss of a pushed revision.
type S3 struct {
	cfg    Config
	client *minio.Client
	// metaGen mirrors the envelope generation into object user-metadata so Head
	// can answer without downloading the (small, but still) envelope.
}

const metaGen = "X-Amz-Meta-Arca-Generation"

// NewS3 builds the client. Credentials: ARCA_SYNC_ACCESS_KEY / ARCA_SYNC_SECRET_KEY,
// falling back to AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY.
func NewS3(cfg Config) (*S3, error) {
	access := firstEnv("ARCA_SYNC_ACCESS_KEY", "AWS_ACCESS_KEY_ID")
	secret := firstEnv("ARCA_SYNC_SECRET_KEY", "AWS_SECRET_ACCESS_KEY")
	if access == "" || secret == "" {
		return nil, errors.New("sync credentials missing: set ARCA_SYNC_ACCESS_KEY and ARCA_SYNC_SECRET_KEY (or the AWS_* equivalents)")
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "s3.amazonaws.com"
	}
	cl, err := minio.New(endpoint, &minio.Options{
		Creds:        credentials.NewStaticV4(access, secret, ""),
		Secure:       !cfg.Insecure,
		Region:       cfg.Region,
		BucketLookup: lookupStyle(cfg),
	})
	if err != nil {
		return nil, fmt.Errorf("sync backend: %w", err)
	}
	return &S3{cfg: cfg, client: cl}, nil
}

func lookupStyle(cfg Config) minio.BucketLookupType {
	if cfg.PathStyle {
		return minio.BucketLookupPath
	}
	return minio.BucketLookupAuto
}

func firstEnv(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

func (s *S3) Head(ctx context.Context) (Rev, error) {
	st, err := s.client.StatObject(ctx, s.cfg.Bucket, s.cfg.key(keyCurrent), minio.StatObjectOptions{})
	if err != nil {
		if isNoSuchKey(err) {
			return Rev{}, ErrNotFound
		}
		return Rev{}, fmt.Errorf("sync head: %w", err)
	}
	gen, _ := strconv.Atoi(st.UserMetadata["Arca-Generation"])
	return Rev{Generation: gen, Tag: st.ETag}, nil
}

func (s *S3) Fetch(ctx context.Context) ([]byte, Rev, error) {
	obj, err := s.client.GetObject(ctx, s.cfg.Bucket, s.cfg.key(keyCurrent), minio.GetObjectOptions{})
	if err != nil {
		return nil, Rev{}, fmt.Errorf("sync fetch: %w", err)
	}
	defer obj.Close()
	b, err := io.ReadAll(obj)
	if err != nil {
		if isNoSuchKey(err) {
			return nil, Rev{}, ErrNotFound
		}
		return nil, Rev{}, fmt.Errorf("sync fetch: %w", err)
	}
	st, err := obj.Stat()
	if err != nil {
		return nil, Rev{}, fmt.Errorf("sync fetch: %w", err)
	}
	gen, _ := strconv.Atoi(st.UserMetadata["Arca-Generation"])
	return b, Rev{Generation: gen, Tag: st.ETag}, nil
}

func (s *S3) Push(ctx context.Context, envelope []byte, gen int, prev Rev) (Rev, error) {
	// 1. The immutable revision object, create-only. If another machine already
	//    pushed this generation, this is the first (and loud) place the race shows.
	revOpts := minio.PutObjectOptions{ContentType: "application/age"}
	revOpts.SetMatchETagExcept("*") // If-None-Match: * — create, never replace
	if _, err := s.client.PutObject(ctx, s.cfg.Bucket, s.cfg.key(revKey(gen)),
		bytes.NewReader(envelope), int64(len(envelope)), revOpts); err != nil {
		if isPreconditionFailed(err) {
			return Rev{}, fmt.Errorf("%w: generation %d already exists on the remote", ErrCASMismatch, gen)
		}
		return Rev{}, fmt.Errorf("sync push (revision): %w", err)
	}
	// 2. Flip the head, conditional on the revision this client last saw.
	opts := minio.PutObjectOptions{
		ContentType:  "application/age",
		UserMetadata: map[string]string{"Arca-Generation": strconv.Itoa(gen)},
	}
	if prev.Zero() {
		opts.SetMatchETagExcept("*") // first-ever push: the head must not exist
	} else {
		opts.SetMatchETag(prev.Tag)
	}
	info, err := s.client.PutObject(ctx, s.cfg.Bucket, s.cfg.key(keyCurrent),
		bytes.NewReader(envelope), int64(len(envelope)), opts)
	if err != nil {
		if isPreconditionFailed(err) {
			return Rev{}, ErrCASMismatch
		}
		return Rev{}, fmt.Errorf("sync push: %w", err)
	}
	return Rev{Generation: gen, Tag: info.ETag}, nil
}

func (s *S3) PutIfAbsent(ctx context.Context, key string, data []byte) error {
	opts := minio.PutObjectOptions{ContentType: "application/age"}
	opts.SetMatchETagExcept("*")
	if _, err := s.client.PutObject(ctx, s.cfg.Bucket, s.cfg.key(key),
		bytes.NewReader(data), int64(len(data)), opts); err != nil {
		if isPreconditionFailed(err) {
			return fmt.Errorf("remote object %s already exists (append-only)", key)
		}
		return err
	}
	return nil
}

func (s *S3) Get(ctx context.Context, key string) ([]byte, error) {
	obj, err := s.client.GetObject(ctx, s.cfg.Bucket, s.cfg.key(key), minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer obj.Close()
	b, err := io.ReadAll(obj)
	if err != nil {
		if isNoSuchKey(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return b, nil
}

func (s *S3) List(ctx context.Context, keyPrefix string) ([]string, error) {
	var out []string
	full := s.cfg.key(keyPrefix)
	for obj := range s.client.ListObjects(ctx, s.cfg.Bucket, minio.ListObjectsOptions{Prefix: full, Recursive: true}) {
		if obj.Err != nil {
			return nil, obj.Err
		}
		out = append(out, strings.TrimPrefix(obj.Key, s.cfg.Prefix+"/"))
	}
	return out, nil
}

func isNoSuchKey(err error) bool {
	resp := minio.ToErrorResponse(err)
	return resp.Code == "NoSuchKey" || resp.StatusCode == 404
}

func isPreconditionFailed(err error) bool {
	resp := minio.ToErrorResponse(err)
	return resp.StatusCode == 412 || resp.Code == "PreconditionFailed"
}
