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
	"testing"
)

func TestArmoryVerifier(t *testing.T) {
	t.Parallel()
	identity, priv, _ := ed25519.GenerateKey(nil)
	_, other, _ := ed25519.GenerateKey(nil)
	pool, _, _ := ed25519.GenerateKey(nil)
	stake, _, _ := ed25519.GenerateKey(nil)

	nonce := []byte("0123456789abcdef0123456789abcdef")
	keys := []AttestedKeyInfo{{Role: KeyTypePool, PublicKey: pool}, {Role: KeyTypeStake, PublicKey: stake}}
	binding := InventoryBinding(nonce, keys)

	v, err := NewArmoryVerifier(identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(t.Context(), ed25519.Sign(priv, binding), binding); err != nil {
		t.Fatalf("valid evidence refused: %v", err)
	}

	for name, tc := range map[string]struct{ evidence, binding []byte }{
		"signed by another key": {ed25519.Sign(other, binding), binding},
		"another nonce":         {ed25519.Sign(priv, InventoryBinding([]byte("another nonce"), keys)), binding},
		"another key list":      {ed25519.Sign(priv, InventoryBinding(nonce, keys[:1])), binding},
		"truncated evidence":    {ed25519.Sign(priv, binding)[:32], binding},
		"empty evidence":        {nil, binding},
	} {
		if err := v.Verify(t.Context(), tc.evidence, tc.binding); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestNewArmoryVerifierRejectsBadKey(t *testing.T) {
	t.Parallel()
	for name, key := range map[string]ed25519.PublicKey{
		"empty":    nil,
		"short":    make(ed25519.PublicKey, 31),
		"long":     make(ed25519.PublicKey, 33),
		"all zero": make(ed25519.PublicKey, ed25519.PublicKeySize),
	} {
		if _, err := NewArmoryVerifier(key); err == nil {
			t.Errorf("%s identity key accepted", name)
		}
	}
}
