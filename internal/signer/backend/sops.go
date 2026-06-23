// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package backend

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"

	"github.com/blinklabs-io/bursa"
)

// SecretSource fetches raw (SOPS-encrypted) secret blobs by name.
// Production impl wraps GCP Secret Manager (gcp.GetGoogleWallet / Secret Manager API);
// tests supply a fake.
type SecretSource interface {
	List(ctx context.Context) ([]string, error)
	Get(ctx context.Context, name string) ([]byte, error)
}

// DecryptFunc decrypts a SOPS-encrypted blob. Production passes sops.Decrypt.
type DecryptFunc func(data []byte) ([]byte, error)

type registered struct {
	name string
	typ  KeyType
}

// SopsBackend loads software keys from a SecretSource, decrypting each with SOPS.
type SopsBackend struct {
	name    string
	source  SecretSource
	decrypt DecryptFunc

	mu         sync.RWMutex
	registered []registered
	keys       map[KeyHash]*softwareKey
}

// NewSopsBackend builds a SOPS-backed backend. decrypt may be sops.Decrypt.
func NewSopsBackend(name string, source SecretSource, decrypt DecryptFunc) *SopsBackend {
	return &SopsBackend{
		name:    name,
		source:  source,
		decrypt: decrypt,
		keys:    map[KeyHash]*softwareKey{},
	}
}

// Register declares a secret name to load and the key type it holds. An empty
// typ means the type is derived from the decrypted cardano-cli envelope at
// Load time (see KeyTypeFromEnvelope).
func (b *SopsBackend) Register(secretName string, typ KeyType) {
	b.mu.Lock()
	b.registered = append(b.registered, registered{name: secretName, typ: typ})
	b.mu.Unlock()
}

// Load fetches, decrypts, and parses every registered secret into a key.
// All network I/O and crypto work is done outside any lock; the write lock
// is taken only at the end to publish the completed map atomically.
func (b *SopsBackend) Load(ctx context.Context) error {
	if b == nil {
		return errors.New("sops backend is nil")
	}
	if b.source == nil {
		return errors.New("sops backend source is nil")
	}
	if b.decrypt == nil {
		return errors.New("sops backend decrypt function is nil")
	}

	// Snapshot registered list under read lock so Register can proceed concurrently.
	b.mu.RLock()
	snap := make([]registered, len(b.registered))
	copy(snap, b.registered)
	b.mu.RUnlock()

	// Build a fresh map with no lock held (I/O + crypto happens here).
	newKeys := make(map[KeyHash]*softwareKey, len(snap))
	for _, r := range snap {
		enc, err := b.source.Get(ctx, r.name)
		if err != nil {
			return fmt.Errorf("fetch secret %q: %w", r.name, err)
		}
		dec, err := b.decrypt(enc)
		if err != nil {
			return fmt.Errorf("decrypt secret %q: %w", r.name, err)
		}
		lk, err := bursa.LoadKeyFromBytes(dec)
		if err != nil {
			return fmt.Errorf("parse key %q: %w", r.name, err)
		}
		pub, err := bursa.PublicKeyOf(lk)
		if err != nil {
			return fmt.Errorf("derive pubkey %q: %w", r.name, err)
		}
		// Empty registered type => infer from the envelope.
		typ := r.typ
		if typ == "" {
			typ = KeyTypeFromEnvelope(lk.Type)
		}
		hash := HashPublicKey(pub)
		newKeys[hash] = &softwareKey{
			lk:          lk,
			pub:         ed25519.PublicKey(pub),
			hash:        hash,
			typ:         typ,
			extended:    len(lk.SKey) == 96,
			backendName: b.name,
		}
	}

	// Publish atomically: all-or-nothing (on error above, b.keys is untouched).
	b.mu.Lock()
	b.keys = newKeys
	b.mu.Unlock()
	return nil
}

// Name returns the configured backend name.
func (b *SopsBackend) Name() string { return b.name }

// GetKey resolves a key by its blake2b-224 hash. Returns ErrKeyNotFound if absent.
func (b *SopsBackend) GetKey(_ context.Context, hash KeyHash) (KeyRef, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	k, ok := b.keys[hash]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return k, nil
}

// ListKeys enumerates the keys this backend can sign with.
func (b *SopsBackend) ListKeys(_ context.Context) ([]KeyRef, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]KeyRef, 0, len(b.keys))
	for _, k := range b.keys {
		out = append(out, k)
	}
	return out, nil
}
