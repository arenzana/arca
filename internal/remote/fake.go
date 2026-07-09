package remote

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Fake is an in-memory Backend with the same CAS semantics as S3, for tests (of this
// package and of the sync command). It deliberately implements the strict conditional
// behavior so tests prove the client logic, not a particular provider.
type Fake struct {
	mu      sync.Mutex
	objects map[string][]byte
	etags   map[string]string
	gens    map[string]int // generation metadata for keyCurrent
	seq     int
}

// NewFake returns an empty in-memory backend.
func NewFake() *Fake {
	return &Fake{objects: map[string][]byte{}, etags: map[string]string{}, gens: map[string]int{}}
}

func (f *Fake) nextTag() string { f.seq++; return fmt.Sprintf("etag-%d", f.seq) }

func (f *Fake) Head(_ context.Context) (Rev, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.objects[keyCurrent]; !ok {
		return Rev{}, ErrNotFound
	}
	return Rev{Generation: f.gens[keyCurrent], Tag: f.etags[keyCurrent]}, nil
}

func (f *Fake) Fetch(_ context.Context) ([]byte, Rev, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.objects[keyCurrent]
	if !ok {
		return nil, Rev{}, ErrNotFound
	}
	return append([]byte(nil), b...), Rev{Generation: f.gens[keyCurrent], Tag: f.etags[keyCurrent]}, nil
}

func (f *Fake) Push(_ context.Context, envelope []byte, gen int, prev Rev) (Rev, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rk := revKey(gen)
	if _, exists := f.objects[rk]; exists {
		return Rev{}, fmt.Errorf("%w: generation %d already exists on the remote", ErrCASMismatch, gen)
	}
	cur, exists := f.etags[keyCurrent]
	if prev.Zero() {
		if exists {
			return Rev{}, ErrCASMismatch
		}
	} else if !exists || cur != prev.Tag {
		return Rev{}, ErrCASMismatch
	}
	f.objects[rk] = append([]byte(nil), envelope...)
	f.etags[rk] = f.nextTag()
	f.objects[keyCurrent] = append([]byte(nil), envelope...)
	f.etags[keyCurrent] = f.nextTag()
	f.gens[keyCurrent] = gen
	return Rev{Generation: gen, Tag: f.etags[keyCurrent]}, nil
}

func (f *Fake) PutIfAbsent(_ context.Context, key string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.objects[key]; exists {
		return fmt.Errorf("remote object %s already exists (append-only)", key)
	}
	f.objects[key] = append([]byte(nil), data...)
	f.etags[key] = f.nextTag()
	return nil
}

func (f *Fake) Get(_ context.Context, key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.objects[key]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), b...), nil
}

func (f *Fake) List(_ context.Context, keyPrefix string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for k := range f.objects {
		if strings.HasPrefix(k, keyPrefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Corrupt replaces the head object out-of-band, simulating remote tampering or a
// provider that ignored a conditional header. Tests only.
func (f *Fake) Corrupt(envelope []byte, gen int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[keyCurrent] = append([]byte(nil), envelope...)
	f.etags[keyCurrent] = f.nextTag()
	f.gens[keyCurrent] = gen
}
