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

func mkSoftware(t *testing.T, name string) (*SoftwareBackend, KeyHash) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	b := NewSoftwareBackend(name)
	h, err := b.AddKey(&bursa.LoadedKey{SKey: []byte(priv), VKey: priv.Public().(ed25519.PublicKey)}, KeyTypePayment)
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	return b, h
}

func TestResolver_Resolve(t *testing.T) {
	b1, h1 := mkSoftware(t, "a")
	b2, h2 := mkSoftware(t, "b")
	r := NewResolver(b1, b2)

	ref, err := r.Resolve(context.Background(), h2)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ref.Backend() != "b" {
		t.Fatalf("expected backend b, got %s", ref.Backend())
	}
	if _, err := r.Resolve(context.Background(), h1); err != nil {
		t.Fatalf("Resolve h1: %v", err)
	}

	var missing KeyHash
	if _, err := r.Resolve(context.Background(), missing); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestResolver_ListKeys(t *testing.T) {
	b1, _ := mkSoftware(t, "a")
	b2, _ := mkSoftware(t, "b")
	r := NewResolver(b1, b2)
	keys, err := r.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
}

// TestCheckAmbiguous verifies that the same key hash present in two backends
// is detected as a config error at startup.
func TestCheckAmbiguous(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	lk := &bursa.LoadedKey{SKey: []byte(priv), VKey: priv.Public().(ed25519.PublicKey)}

	b1 := NewSoftwareBackend("primary")
	b2 := NewSoftwareBackend("secondary")
	if _, err := b1.AddKey(lk, KeyTypePayment); err != nil {
		t.Fatalf("AddKey b1: %v", err)
	}
	if _, err := b2.AddKey(lk, KeyTypePayment); err != nil {
		t.Fatalf("AddKey b2: %v", err)
	}

	// Two distinct backends with unique keys — no conflict.
	bUniq1, _ := mkSoftware(t, "u1")
	bUniq2, _ := mkSoftware(t, "u2")
	if err := NewResolver(bUniq1, bUniq2).CheckAmbiguous(context.Background()); err != nil {
		t.Errorf("expected no error for distinct keys, got: %v", err)
	}

	// Same key in both backends — must be rejected.
	if err := NewResolver(b1, b2).CheckAmbiguous(context.Background()); err == nil {
		t.Error("expected error for duplicate key hash across backends, got nil")
	}
}
