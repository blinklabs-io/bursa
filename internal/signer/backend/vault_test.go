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
	"errors"
	"fmt"
	"testing"
)

// compile-time assertion
var _ Backend = (*VaultBackend)(nil)

func TestVaultBackend_Sign(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	// transitSign stub: signs locally and returns Vault's "vault:v1:<b64>" form.
	// Also asserts the expected key name to catch plumbing regressions.
	stub := func(_ context.Context, keyName string, digest []byte) (string, error) {
		if keyName != "payment-1" {
			return "", fmt.Errorf("stub: unexpected keyName %q", keyName)
		}
		sig := ed25519.Sign(priv, digest)
		return "vault:v1:" + base64.StdEncoding.EncodeToString(sig), nil
	}

	b := NewVaultBackend("vault", stub)
	hash, err := b.AddKey("payment-1", pub, KeyTypePool)
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	ref, err := b.GetKey(context.Background(), hash)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if ref.Extended() {
		t.Fatalf("vault keys are never extended")
	}
	digest := make([]byte, 32)
	sig, err := ref.Sign(context.Background(), digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(pub, digest, sig) {
		t.Fatalf("signature does not verify")
	}
	if _, ok := ref.(LoadedKeyProvider); ok {
		t.Fatalf("vault key must NOT expose LoadedKeyProvider")
	}
}

func TestVaultBackend_RejectsExtendedPubkeyLength(t *testing.T) {
	b := NewVaultBackend("vault", func(context.Context, string, []byte) (string, error) { return "", nil })
	// A 64-byte "public key" (extended xpub-like) is invalid for a standard ed25519 vault key.
	if _, err := b.AddKey("bad", make([]byte, 64), KeyTypePool); err == nil {
		t.Fatalf("expected error adding non-32-byte public key")
	}
}

func TestVaultBackend_GetKey_NotFound(t *testing.T) {
	b := NewVaultBackend("vault", func(context.Context, string, []byte) (string, error) { return "", nil })
	_, err := b.GetKey(context.Background(), KeyHash{})
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestParseTransitSignature_Malformed(t *testing.T) {
	// A valid-b64-but-32-byte payload (too short for ed25519).
	short32 := base64.StdEncoding.EncodeToString(make([]byte, 32))

	cases := []struct {
		name  string
		input string
	}{
		{"garbage", "garbage"},
		{"empty_sig", "vault:v1:"},
		{"missing_version_prefix", "vault::AAAA"},
		{"bad_b64", "vault:v1:!!!notb64"},
		{"32_byte_sig", "vault:v1:" + short32},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseTransitSignature(tc.input)
			if err == nil {
				t.Fatalf("parseTransitSignature(%q): expected error, got nil", tc.input)
			}
		})
	}
}
