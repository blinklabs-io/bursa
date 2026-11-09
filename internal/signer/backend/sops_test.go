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
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa"
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

func (f *fakeSecretSource) Get(
	ctx context.Context,
	name string,
) ([]byte, error) {
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
	b := NewSopsBackend(
		"gcp",
		src,
		func(data []byte) ([]byte, error) { return data, nil },
	)
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
	b := NewSopsBackend(
		"gcp",
		src,
		func(data []byte) ([]byte, error) { return data, nil },
	)
	b.Register("missing-key", KeyTypePayment)

	err := b.Load(context.Background())
	if err == nil {
		t.Fatal("Load: expected error for unknown secret, got nil")
	}
}

func TestSopsBackend_Load_NilDependencies(t *testing.T) {
	if err := (*SopsBackend)(nil).Load(context.Background()); err == nil ||
		err.Error() != "sops backend is nil" {
		t.Fatalf("nil backend: got %v", err)
	}
	if err := NewSopsBackend("gcp", nil, func(data []byte) ([]byte, error) { return data, nil }).Load(context.Background()); err == nil ||
		err.Error() != "sops backend source is nil" {
		t.Fatalf("nil source: got %v", err)
	}
	src := &fakeSecretSource{secrets: map[string][]byte{}}
	if err := NewSopsBackend("gcp", src, nil).Load(context.Background()); err == nil ||
		err.Error() != "sops backend decrypt function is nil" {
		t.Fatalf("nil decrypt: got %v", err)
	}
}

func TestSopsBackend_DerivesPolicyTypeFromPaymentEnvelope(t *testing.T) {
	root, err := bursa.GetRootKeyFromMnemonic(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"",
	)
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	policy, err := bursa.GetPolicyKey(root, 0)
	if err != nil {
		t.Fatalf("policy key: %v", err)
	}
	key, err := bursa.GetPolicySKey(policy)
	if err != nil {
		t.Fatalf("policy signing key: %v", err)
	}
	envelope, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("marshal policy key: %v", err)
	}
	src := &fakeSecretSource{secrets: map[string][]byte{
		"policy-1": envelope,
	}}
	b := NewSopsBackend(
		"sops",
		src,
		func(d []byte) ([]byte, error) { return d, nil },
	)
	b.Register("policy-1", "")
	if err := b.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	keys, err := b.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].Type() != KeyTypePolicy {
		t.Fatalf("expected derived type policy, got %q", keys[0].Type())
	}
}

func TestSopsBackend_DerivesTypeFromEnvelope(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	seed := []byte(priv)[:32]
	cborEncoded, err := cbor.Encode(seed)
	if err != nil {
		t.Fatalf("cbor.Encode seed: %v", err)
	}
	envelope := fmt.Sprintf(
		`{"type":"StakeSigningKeyShelley_ed25519","description":"","cborHex":"%s"}`,
		hex.EncodeToString(cborEncoded),
	)
	src := &fakeSecretSource{secrets: map[string][]byte{
		"stake-1": []byte(envelope),
	}}
	b := NewSopsBackend(
		"sops",
		src,
		func(d []byte) ([]byte, error) { return d, nil },
	)
	b.Register("stake-1", "")
	if err := b.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	keys, _ := b.ListKeys(context.Background())
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].Type() != KeyTypeStake {
		t.Fatalf("expected derived type stake, got %q", keys[0].Type())
	}
}

// profiledSops builds a loaded sops backend holding the key of priv under
// profile ("" for an unprofiled backend).
func profiledSops(
	t *testing.T,
	name, profile string,
	priv ed25519.PrivateKey,
) *SopsBackend {
	t.Helper()
	src := &fakeSecretSource{secrets: map[string][]byte{
		"cold.skey.json": mkKeyEnvelope(t, priv),
	}}
	b := NewProfiledSopsBackend(
		name,
		profile,
		src,
		func(data []byte) ([]byte, error) { return data, nil },
	)
	b.Register("cold.skey.json", KeyTypePool)
	if err := b.Load(context.Background()); err != nil {
		t.Fatalf("Load %s: %v", name, err)
	}
	return b
}

func TestSopsBackend_ProfiledKeysImplementProfiled(t *testing.T) {
	t.Parallel()
	_, priv, _ := ed25519.GenerateKey(nil)
	b := profiledSops(t, "cold-preview", "otg@preview", priv)
	if got := profileOf(b); got != "otg@preview" {
		t.Fatalf("backend profile = %q, want otg@preview", got)
	}
	keys, err := b.ListKeys(context.Background())
	if err != nil || len(keys) != 1 {
		t.Fatalf("ListKeys: %v len=%d", err, len(keys))
	}
	p, ok := keys[0].(Profiled)
	if !ok || p.Profile() != "otg@preview" {
		t.Fatalf("listed key is not Profiled under otg@preview: %v", keys[0])
	}
	ref, err := b.GetKey(context.Background(), keys[0].Hash())
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if p, ok := ref.(Profiled); !ok || p.Profile() != "otg@preview" {
		t.Fatalf("GetKey ref is not Profiled under otg@preview: %v", ref)
	}
	if _, ok := ref.(LoadedKeyProvider); !ok {
		t.Fatalf("profiled sops key must keep LoadedKeyProvider for CIP-8")
	}
	if ref.Backend() != "cold-preview" {
		t.Fatalf("Backend() = %q", ref.Backend())
	}
}

func TestSopsBackend_UnprofiledKeysAreNotProfiled(t *testing.T) {
	t.Parallel()
	_, priv, _ := ed25519.GenerateKey(nil)
	b := profiledSops(t, "cold", "", priv)
	if got := profileOf(b); got != "" {
		t.Fatalf("backend profile = %q, want none", got)
	}
	keys, _ := b.ListKeys(context.Background())
	if _, ok := keys[0].(Profiled); ok {
		t.Fatalf("unprofiled sops key must not implement Profiled")
	}
}

func TestSopsBackend_ProfiledResolve(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(nil)
	preview := profiledSops(t, "cold-preview", "otg@preview", priv)
	keys, _ := preview.ListKeys(ctx)
	hash := keys[0].Hash()

	t.Run("refuses another profile", func(t *testing.T) {
		t.Parallel()
		r := NewResolver(preview)
		_, err := r.Resolve(ctx, hash, "otg@musashi")
		if !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("err = %v, want ErrKeyNotFound", err)
		}
	})
	t.Run("serves its own profile", func(t *testing.T) {
		t.Parallel()
		ref, err := NewResolver(preview).Resolve(ctx, hash, "otg@preview")
		if err != nil || ref.Backend() != "cold-preview" {
			t.Fatalf("ref=%v err=%v", ref, err)
		}
	})
	t.Run("serves a profile-less request as the only holder", func(t *testing.T) {
		t.Parallel()
		ref, err := NewResolver(preview).Resolve(ctx, hash, "")
		if err != nil || ref.Backend() != "cold-preview" {
			t.Fatalf("ref=%v err=%v", ref, err)
		}
	})
	t.Run("selects the holder by profile", func(t *testing.T) {
		t.Parallel()
		musashi := profiledSops(t, "cold-musashi", "otg@musashi", priv)
		r := NewResolver(preview, musashi)
		ref, err := r.Resolve(ctx, hash, "otg@musashi")
		if err != nil || ref.Backend() != "cold-musashi" {
			t.Fatalf("ref=%v err=%v", ref, err)
		}
		if _, err = r.Resolve(ctx, hash, ""); !errors.Is(err, ErrProfileRequired) {
			t.Fatalf("profile-less err = %v, want ErrProfileRequired", err)
		}
	})
}

func TestSopsBackend_CheckAmbiguousWithProfiles(t *testing.T) {
	t.Parallel()
	_, priv, _ := ed25519.GenerateKey(nil)
	tests := []struct {
		name     string
		profiles [2]string
		wantErr  string
	}{
		{"distinct profiles", [2]string{"otg@preview", "otg@musashi"}, ""},
		{"same profile", [2]string{"otg@preview", "otg@preview"}, "under the same profile"},
		{"profiled and unprofiled", [2]string{"otg@preview", ""}, "distinct profile"},
		{"unprofiled and profiled", [2]string{"", "otg@preview"}, "distinct profile"},
		{"both unprofiled", [2]string{"", ""}, "distinct profile"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := NewResolver(
				profiledSops(t, "a", tc.profiles[0], priv),
				profiledSops(t, "b", tc.profiles[1], priv),
			)
			err := r.CheckAmbiguous(context.Background())
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("CheckAmbiguous: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}
