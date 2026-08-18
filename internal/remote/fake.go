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
	auths   map[string]StoreAuth
	seq     int
}

// NewFake returns an empty in-memory backend.
func NewFake() *Fake {
	return &Fake{objects: map[string][]byte{}, etags: map[string]string{}, gens: map[string]int{}, auths: map[string]StoreAuth{}}
}

func (f *Fake) nextTag() string { f.seq++; return fmt.Sprintf("etag-%d", f.seq) }

func (f *Fake) Head(_ context.Context) (Rev, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.objects[keyCurrent]; !ok {
		return Rev{}, ErrNotFound
	}
	a := f.auths[keyCurrent]
	return Rev{Generation: f.gens[keyCurrent], Tag: f.etags[keyCurrent], Signature: a.Signature, Signer: a.Signer}, nil
}

func (f *Fake) Fetch(_ context.Context) ([]byte, Rev, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.objects[keyCurrent]
	if !ok {
		return nil, Rev{}, ErrNotFound
	}
	a := f.auths[keyCurrent]
	return append([]byte(nil), b...), Rev{Generation: f.gens[keyCurrent], Tag: f.etags[keyCurrent], Signature: a.Signature, Signer: a.Signer}, nil
}

func (f *Fake) Push(_ context.Context, envelope []byte, gen int, prev Rev, auth StoreAuth) (Rev, error) {
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
	f.auths[rk] = auth
	f.objects[keyCurrent] = append([]byte(nil), envelope...)
	f.etags[keyCurrent] = f.nextTag()
	f.gens[keyCurrent] = gen
	f.auths[keyCurrent] = auth
	return Rev{Generation: gen, Tag: f.etags[keyCurrent], Signature: auth.Signature, Signer: auth.Signer}, nil
}

func (f *Fake) PutIfAbsent(_ context.Context, key string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.objects[key]; exists {
		return fmt.Errorf("remote object %s %w", key, ErrObjectExists)
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

// Delete removes an object out-of-band, simulating storage-side violation of the
// append-only contract. Tests only.
func (f *Fake) Delete(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, key)
	delete(f.etags, key)
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

// StripAuth removes store-auth metadata from the head, simulating a backend
// that dropped user-metadata or an unsigned legacy object. Tests only.
func (f *Fake) StripAuth() {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.auths, keyCurrent)
}

// SetAuth replaces the head's store-auth metadata without touching the
// envelope. Tests only (forged signer / bad signature).
func (f *Fake) SetAuth(auth StoreAuth) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auths[keyCurrent] = auth
}
