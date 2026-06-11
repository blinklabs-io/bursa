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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/blinklabs-io/gouroboros/cbor"
)

// Compile-time assertion: SopsBackend must satisfy Backend.
var _ Backend = (*SopsBackend)(nil)

// fakeSecretSource returns canned (already-decrypted) key envelopes, and a noop
// decrypt so the test does not require real SOPS material.
type fakeSecretSource struct{ secrets map[string][]byte }

func (f *fakeSecretSource) List(ctx context.Context) ([]string, error) {
	names := make([]string, 0, len(f.secrets))
	for n := range f.secrets {
		names = append(names, n)
	}
	return names, nil
}
func (f *fakeSecretSource) Get(ctx context.Context, name string) ([]byte, error) {
	if b, ok := f.secrets[name]; ok {
		return b, nil
	}
	return nil, fmt.Errorf("secret %q not found", name)
}

// mkKeyEnvelope builds a cardano-cli-style signing key envelope.
// decodeNonExtendedCborKey expects cborHex to decode as a 32-byte seed,
// so we CBOR-encode the seed bytes and hex-encode the result.
func mkKeyEnvelope(t *testing.T, priv ed25519.PrivateKey) []byte {
	t.Helper()
	// ed25519.PrivateKey is seed (32 bytes) || pubkey (32 bytes); seed is first 32
	seed := []byte(priv)[:32]
	cborEncoded, err := cbor.Encode(seed)
	if err != nil {
		t.Fatalf("cbor.Encode seed: %v", err)
	}
	env := map[string]string{
		"type":        "PaymentSigningKeyShelley_ed25519",
		"description": "",
		"cborHex":     hex.EncodeToString(cborEncoded),
	}
	b, _ := json.Marshal(env)
	return b
}

func TestSopsBackend_LoadAndSign(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	src := &fakeSecretSource{secrets: map[string][]byte{
		"signer-payment-1": mkKeyEnvelope(t, priv),
	}}
	// identity decrypt for the test
	b := NewSopsBackend("gcp", src, func(data []byte) ([]byte, error) { return data, nil })
	b.Register("signer-payment-1", KeyTypePayment)

	if err := b.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	keys, err := b.ListKeys(context.Background())
	if err != nil || len(keys) != 1 {
		t.Fatalf("ListKeys: %v len=%d", err, len(keys))
	}
	ref := keys[0]
	digest := make([]byte, 32)
	sig, err := ref.Sign(context.Background(), digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(pub, digest, sig) {
		t.Fatalf("signature does not verify")
	}
	if _, ok := ref.(LoadedKeyProvider); !ok {
		t.Fatalf("sops key must expose LoadedKeyProvider for CIP-8")
	}
}

func TestSopsBackend_Load_FetchError(t *testing.T) {
	// fakeSecretSource has no secrets, so fetching "missing-key" must fail.
	src := &fakeSecretSource{secrets: map[string][]byte{}}
	b := NewSopsBackend("gcp", src, func(data []byte) ([]byte, error) { return data, nil })
	b.Register("missing-key", KeyTypePayment)

	err := b.Load(context.Background())
	if err == nil {
		t.Fatal("Load: expected error for unknown secret, got nil")
	}
}

func TestSopsBackend_Load_NilDependencies(t *testing.T) {
	if err := (*SopsBackend)(nil).Load(context.Background()); err == nil || err.Error() != "sops backend is nil" {
		t.Fatalf("nil backend: got %v", err)
	}
	if err := NewSopsBackend("gcp", nil, func(data []byte) ([]byte, error) { return data, nil }).Load(context.Background()); err == nil || err.Error() != "sops backend source is nil" {
		t.Fatalf("nil source: got %v", err)
	}
	src := &fakeSecretSource{secrets: map[string][]byte{}}
	if err := NewSopsBackend("gcp", src, nil).Load(context.Background()); err == nil || err.Error() != "sops backend decrypt function is nil" {
		t.Fatalf("nil decrypt: got %v", err)
	}
}
