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
	"fmt"
	"sync"

	"github.com/blinklabs-io/bursa"
)

// softwareKey is a KeyRef backed by an in-process bursa.LoadedKey.
type softwareKey struct {
	lk          *bursa.LoadedKey
	pub         ed25519.PublicKey
	hash        KeyHash
	typ         KeyType
	extended    bool
	backendName string
}

func (k *softwareKey) Hash() KeyHash                { return k.hash }
func (k *softwareKey) PublicKey() ed25519.PublicKey { return k.pub }
func (k *softwareKey) Type() KeyType                { return k.typ }
func (k *softwareKey) Extended() bool               { return k.extended }
func (k *softwareKey) Backend() string              { return k.backendName }
func (k *softwareKey) LoadedKey() *bursa.LoadedKey  { return k.lk }

func (k *softwareKey) Sign(_ context.Context, digest []byte) ([]byte, error) {
	return bursa.SignDigest(k.lk, digest)
}

// SoftwareBackend holds Ed25519 keys (standard or extended) in process.
type SoftwareBackend struct {
	name string
	mu   sync.RWMutex
	keys map[KeyHash]*softwareKey
}

// NewSoftwareBackend creates an empty software backend with the given name.
func NewSoftwareBackend(name string) *SoftwareBackend {
	return &SoftwareBackend{name: name, keys: map[KeyHash]*softwareKey{}}
}

// AddKey registers a loaded key and returns its key hash. Extended keys are
// detected by a 96-byte signing key.
func (b *SoftwareBackend) AddKey(lk *bursa.LoadedKey, typ KeyType) (KeyHash, error) {
	if !typ.Valid() {
		return KeyHash{}, fmt.Errorf("invalid key type %q", typ)
	}
	pub, err := bursa.PublicKeyOf(lk)
	if err != nil {
		return KeyHash{}, fmt.Errorf("failed to derive public key: %w", err)
	}
	if len(pub) != 32 {
		return KeyHash{}, fmt.Errorf("expected 32-byte public key, got %d", len(pub))
	}
	hash := HashPublicKey(pub)
	k := &softwareKey{
		lk:          lk,
		pub:         ed25519.PublicKey(pub),
		hash:        hash,
		typ:         typ,
		extended:    len(lk.SKey) == 96,
		backendName: b.name,
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.keys[hash]; exists {
		return KeyHash{}, fmt.Errorf("key hash %s already exists in backend %q", hash, b.name)
	}
	b.keys[hash] = k
	return hash, nil
}

func (b *SoftwareBackend) Name() string { return b.name }

func (b *SoftwareBackend) GetKey(_ context.Context, hash KeyHash) (KeyRef, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	k, ok := b.keys[hash]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return k, nil
}

func (b *SoftwareBackend) ListKeys(_ context.Context) ([]KeyRef, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]KeyRef, 0, len(b.keys))
	for _, k := range b.keys {
		out = append(out, k)
	}
	return out, nil
}
