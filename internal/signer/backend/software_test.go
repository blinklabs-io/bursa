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
	"testing"

	"github.com/blinklabs-io/bursa"
)

// compile-time assertions
var _ Backend = (*SoftwareBackend)(nil)
var _ LoadedKeyProvider = (*softwareKey)(nil)

func TestSoftwareBackend_AddSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	lk := &bursa.LoadedKey{SKey: []byte(priv), VKey: pub}

	b := NewSoftwareBackend("software")
	hash, err := b.AddKey(lk, KeyTypePayment)
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	ref, err := b.GetKey(context.Background(), hash)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if ref.Backend() != "software" || ref.Type() != KeyTypePayment || ref.Extended() {
		t.Fatalf("unexpected key metadata: %+v", ref)
	}

	digest := make([]byte, 32)
	sig, err := ref.Sign(context.Background(), digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(ref.PublicKey(), digest, sig) {
		t.Fatalf("signature does not verify")
	}
}

func TestSoftwareBackend_GetKey_NotFound(t *testing.T) {
	b := NewSoftwareBackend("software")
	var missing KeyHash
	if _, err := b.GetKey(context.Background(), missing); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestSoftwareBackend_AddKey_Duplicate(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	b := NewSoftwareBackend("software")
	lk := &bursa.LoadedKey{SKey: []byte(priv), VKey: pub}
	if _, err := b.AddKey(lk, KeyTypePayment); err != nil {
		t.Fatalf("first AddKey: %v", err)
	}
	if _, err := b.AddKey(lk, KeyTypePayment); err == nil {
		t.Fatal("second AddKey: expected duplicate error, got nil")
	}
}

func TestSoftwareBackend_ListKeys(t *testing.T) {
	b := NewSoftwareBackend("software")
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if _, err := b.AddKey(&bursa.LoadedKey{SKey: []byte(priv), VKey: pub}, KeyTypeStake); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	keys, err := b.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
}
