package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGitRoot(t *testing.T) {
	dir := t.TempDir()
	if got := gitRoot(dir); got != "" {
		t.Fatalf("gitRoot on a non-repo = %q, want empty", got)
	}
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "a", "b")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := gitRoot(sub); got != dir {
		t.Fatalf("gitRoot from a subdir = %q, want %q", got, dir)
	}
}

func TestDoctorIdentityPermsHighAndFix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits aren't Windows' access-control mechanism; checkIdentity skips the perm check there")
	}
	dir := sandbox(t)
	runArca(t, "", "init")
	idPath := filepath.Join(dir, "id.txt")
	if err := os.Chmod(idPath, 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := execArca("", "doctor")
	if !errors.Is(err, errDoctorHigh) {
		t.Fatalf("loose identity perms should yield a HIGH exit, got err=%v", err)
	}
	if !strings.Contains(out, "mode 644") || !strings.Contains(out, "HIGH") {
		t.Fatalf("doctor should flag the mode:\n%s", out)
	}

	// --fix tightens it, and doctor then has no HIGH (other findings are LOW/MED).
	if _, err := execArca("", "doctor", "--fix"); errors.Is(err, errDoctorHigh) {
		t.Fatalf("after --fix there should be no HIGH finding, err=%v", err)
	}
	fi, err := os.Stat(idPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("--fix left perms %o, want 600", fi.Mode().Perm())
	}
}

func TestDoctorIdentityInGitIsHigh(t *testing.T) {
	dir := sandbox(t)
	runArca(t, "", "init")
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	out, err := execArca("", "doctor")
	if !errors.Is(err, errDoctorHigh) {
		t.Fatalf("identity inside a git repo should be HIGH, err=%v", err)
	}
	if !strings.Contains(out, "git repository") {
		t.Fatalf("doctor should flag identity-in-git:\n%s", out)
	}
}

func TestDoctorReportsSensitiveAndAgent(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "B2_MASTER_KEY")
	runArca(t, "v", "set", "DB_PASSWORD")

	out, _ := execArca("", "doctor")
	for _, want := range []string{"high-privilege", "B2_MASTER_KEY", "MCP agent exposure", "blast radius"} {
		if !strings.Contains(out, want) {
			t.Fatalf("doctor output missing %q:\n%s", want, out)
		}
	}
	// DB_PASSWORD is benign and must not appear in the high-privilege line.
	if strings.Contains(out, "DB_PASSWORD") {
		t.Fatalf("benign secret should not be flagged high-privilege:\n%s", out)
	}
}

func TestDoctorJSON(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "API")

	out, _ := execArca("", "doctor", "--json")
	if !strings.HasPrefix(strings.TrimSpace(out), "[") {
		t.Fatalf("--json should emit a JSON array:\n%s", out)
	}
	for _, want := range []string{`"severity"`, `"check"`, `"title"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("--json missing field %q:\n%s", want, out)
		}
	}
}
