//go:build sync_e2e

package main

// End-to-end sync tests against a REAL MinIO (see the sync-e2e job in ci.yml). The fake
// backend proves the client logic; this proves the S3 conditional-write headers actually
// hold on a real service — the property CAS safety rests on.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func minioEnv(t *testing.T) (endpoint, access, secret string) {
	t.Helper()
	endpoint = os.Getenv("ARCA_SYNC_E2E_ENDPOINT")
	if endpoint == "" {
		t.Skip("set ARCA_SYNC_E2E_ENDPOINT (host:port of a MinIO) to run sync e2e")
	}
	return endpoint, os.Getenv("ARCA_SYNC_ACCESS_KEY"), os.Getenv("ARCA_SYNC_SECRET_KEY")
}

// TestSyncE2EMinIO drives the real S3 backend: bootstrap push, second-machine pull,
// CAS conflict on divergence — all against live conditional PUTs.
func TestSyncE2EMinIO(t *testing.T) {
	endpoint, access, secret := minioEnv(t)
	dir := sandbox(t)

	// A unique bucket per run keeps retries hermetic.
	bucket := fmt.Sprintf("arca-e2e-%d", time.Now().UnixNano())
	cl, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(access, secret, ""),
		Secure: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.MakeBucket(context.Background(), bucket, minio.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARCA_SYNC_URL", fmt.Sprintf("s3://%s/e2e?endpoint=%s&insecure=1", bucket, endpoint))

	runArca(t, "", "init")
	runArca(t, "hunter2", "set", "API")
	runArca(t, "", "sync")

	// Second machine: same identity, fresh store/state — bootstrap pull.
	aStore, aAudit, aState := os.Getenv("ARCA_STORE"), os.Getenv("ARCA_AUDIT"), os.Getenv("XDG_STATE_HOME")
	switchMachine(t, dir)
	runArca(t, "", "sync")
	if out := runArca(t, "", "get", "API"); out != "hunter2" {
		t.Fatalf("pulled store: get API = %q", out)
	}
	runArca(t, "b-wins", "rotate", "API")
	runArca(t, "", "sync")

	// Machine A diverges from its stale base; the real conditional PUT must refuse it.
	t.Setenv("ARCA_STORE", aStore)
	t.Setenv("ARCA_AUDIT", aAudit)
	t.Setenv("XDG_STATE_HOME", aState)
	runArca(t, "a-loses", "rotate", "API")
	err = runArcaErr("", "sync")
	if err == nil {
		t.Fatal("divergent push accepted by a real MinIO — conditional writes are not holding")
	}
	if !strings.Contains(err.Error(), "CONFLICT") && !strings.Contains(err.Error(), "concurrent push") {
		t.Fatalf("want CAS refusal, got: %v", err)
	}
	runArca(t, "", "sync", "--pull")
	if out := runArca(t, "", "get", "API"); out != "b-wins" {
		t.Fatalf("after pull: get API = %q", out)
	}
}
