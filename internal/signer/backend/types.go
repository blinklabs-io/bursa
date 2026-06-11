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
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

// KeyHash is the blake2b-224 hash of an Ed25519 public key — the canonical
// cross-backend key identifier (the same value Cardano uses in addresses and
// witnesses).
type KeyHash [28]byte

// String returns the lower-case hex encoding (56 chars).
func (h KeyHash) String() string { return hex.EncodeToString(h[:]) }

// ParseKeyHash decodes a 56-char hex string into a KeyHash.
func ParseKeyHash(s string) (KeyHash, error) {
	var h KeyHash
	raw, err := hex.DecodeString(s)
	if err != nil {
		return h, fmt.Errorf("invalid key hash hex: %w", err)
	}
	if len(raw) != 28 {
		return h, fmt.Errorf("key hash must be 28 bytes (56 hex chars), got %d", len(raw))
	}
	copy(h[:], raw)
	return h, nil
}

// HashPublicKey computes the blake2b-224 hash of a 32-byte Ed25519 public key.
func HashPublicKey(pub []byte) KeyHash {
	if len(pub) != ed25519.PublicKeySize {
		panic(fmt.Sprintf("HashPublicKey: expected 32-byte Ed25519 public key, got %d bytes", len(pub)))
	}
	hasher, err := blake2b.New(28, nil)
	if err != nil {
		panic(fmt.Sprintf("create blake2b-224 hasher: %v", err))
	}
	hasher.Write(pub)
	var h KeyHash
	copy(h[:], hasher.Sum(nil))
	return h
}

// KeyType identifies the role of a key.
type KeyType string

const (
	KeyTypePayment KeyType = "payment"
	KeyTypeStake   KeyType = "stake"
	KeyTypeDRep    KeyType = "drep"
	KeyTypeCCHot   KeyType = "cc-hot"
	KeyTypeCCCold  KeyType = "cc-cold"
	KeyTypePool    KeyType = "pool"
	KeyTypePolicy  KeyType = "policy"
)

// Valid reports whether t is a recognized key type.
func (t KeyType) Valid() bool {
	switch t {
	case KeyTypePayment, KeyTypeStake, KeyTypeDRep, KeyTypeCCHot, KeyTypeCCCold, KeyTypePool, KeyTypePolicy:
		return true
	default:
		return false
	}
}
