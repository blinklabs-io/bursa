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

	"github.com/blinklabs-io/bursa"
)

// ErrKeyNotFound is returned when a backend has no key matching a hash.
var ErrKeyNotFound = errors.New("key not found")

// ErrUnsupportedExtended is returned when an extended BIP32-Ed25519 key is
// routed to a backend that only supports standard Ed25519 (e.g. Vault, PKCS#11).
var ErrUnsupportedExtended = errors.New("extended (BIP32-Ed25519) keys are not supported by this backend")

// Backend is a key-custody provider.
type Backend interface {
	// Name returns the configured backend name.
	Name() string
	// ListKeys enumerates the keys this backend can sign with.
	ListKeys(ctx context.Context) ([]KeyRef, error)
	// GetKey resolves a key by its blake2b-224 hash. Returns ErrKeyNotFound if absent.
	GetKey(ctx context.Context, hash KeyHash) (KeyRef, error)
}

// KeyRef is a resolved, signable key handle.
type KeyRef interface {
	Hash() KeyHash
	PublicKey() ed25519.PublicKey
	Type() KeyType
	Extended() bool
	Backend() string
	// Sign produces a 64-byte Ed25519 signature over digest.
	Sign(ctx context.Context, digest []byte) ([]byte, error)
}

// LoadedKeyProvider is implemented by KeyRefs whose private key is available
// in-process (software/SOPS backends). The CIP-8 path requires it because
// bursa.SignData needs a *bursa.LoadedKey. Backends that custody keys remotely
// (Vault) do not implement it.
type LoadedKeyProvider interface {
	LoadedKey() *bursa.LoadedKey
}
