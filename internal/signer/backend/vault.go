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
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
)

// TransitSignFunc signs a digest with a named Transit key and returns Vault's
// "vault:v<n>:<base64-signature>" response string. Production wraps the Vault
// API client (transit/sign/<key> with prehashed=false, marshaling_algorithm of
// the raw input); tests inject a stub.
type TransitSignFunc func(ctx context.Context, keyName string, digest []byte) (string, error)

type vaultKey struct {
	keyName     string
	pub         ed25519.PublicKey
	hash        KeyHash
	typ         KeyType
	backendName string
	sign        TransitSignFunc
}

func (k *vaultKey) Hash() KeyHash                { return k.hash }
func (k *vaultKey) PublicKey() ed25519.PublicKey { return k.pub }
func (k *vaultKey) Type() KeyType                { return k.typ }
func (k *vaultKey) Extended() bool               { return false }
func (k *vaultKey) Backend() string              { return k.backendName }

func (k *vaultKey) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	resp, err := k.sign(ctx, k.keyName, digest)
	if err != nil {
		return nil, fmt.Errorf("vault transit sign: %w", err)
	}
	sig, err := parseTransitSignature(resp)
	if err != nil {
		return nil, fmt.Errorf("vault transit parse: %w", err)
	}
	return sig, nil
}

// parseTransitSignature extracts the raw signature bytes from "vault:vN:<b64>".
func parseTransitSignature(s string) ([]byte, error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 || parts[0] != "vault" {
		return nil, fmt.Errorf("unexpected transit signature format %q", s)
	}
	if !strings.HasPrefix(parts[1], "v") {
		return nil, fmt.Errorf("unexpected transit signature format %q", s)
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode transit signature: %w", err)
	}
	if len(raw) != ed25519.SignatureSize {
		return nil, fmt.Errorf("transit signature: expected %d bytes, got %d", ed25519.SignatureSize, len(raw))
	}
	return raw, nil
}

// VaultBackend signs standard Ed25519 keys via Vault Transit.
type VaultBackend struct {
	name string
	sign TransitSignFunc
	mu   sync.RWMutex
	keys map[KeyHash]*vaultKey
}

// NewVaultBackend builds a Vault Transit backend over the given sign function.
func NewVaultBackend(name string, sign TransitSignFunc) *VaultBackend {
	return &VaultBackend{name: name, sign: sign, keys: map[KeyHash]*vaultKey{}}
}

// AddKey registers a Transit key by name with its known 32-byte public key.
func (b *VaultBackend) AddKey(keyName string, pub []byte, typ KeyType) (KeyHash, error) {
	if !typ.Valid() {
		return KeyHash{}, fmt.Errorf("invalid key type %q", typ)
	}
	if len(pub) != 32 {
		return KeyHash{}, fmt.Errorf("vault backend requires a 32-byte Ed25519 public key, got %d", len(pub))
	}
	hash := HashPublicKey(pub)
	b.mu.Lock()
	b.keys[hash] = &vaultKey{
		keyName:     keyName,
		pub:         ed25519.PublicKey(pub),
		hash:        hash,
		typ:         typ,
		backendName: b.name,
		sign:        b.sign,
	}
	b.mu.Unlock()
	return hash, nil
}

func (b *VaultBackend) Name() string { return b.name }

func (b *VaultBackend) GetKey(_ context.Context, hash KeyHash) (KeyRef, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	k, ok := b.keys[hash]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return k, nil
}

func (b *VaultBackend) ListKeys(_ context.Context) ([]KeyRef, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]KeyRef, 0, len(b.keys))
	for _, k := range b.keys {
		out = append(out, k)
	}
	return out, nil
}
