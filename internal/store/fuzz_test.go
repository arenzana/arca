package store

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoad ensures Load never panics on an arbitrary store file — malformed JSON, a null secret
// entry, an unsupported version, or garbage must all come back as an error, never a crash.
func FuzzLoad(f *testing.F) {
	for _, seed := range []string{
		`{"version":1,"recipients":[],"secrets":{"A":{"value":"x"}}}`,
		`{"secrets":{"A":null}}`,
		`{"version":999}`,
		`{"version":0}`,
		`not json`,
		``,
		`{"secrets":{}}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		dir := t.TempDir()
		p := filepath.Join(dir, "store.json")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := Load(p)
		if err == nil {
			if s == nil {
				t.Fatal("Load returned a nil store with a nil error")
			}
			if s.Secrets == nil {
				t.Fatal("a loaded store must have a non-nil Secrets map")
			}
			for name, sec := range s.Secrets {
				if sec == nil {
					t.Fatalf("loaded a nil secret %q without an error", name)
				}
			}
		}
	})
}
