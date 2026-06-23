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

package signer

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/policy"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// loadedBackend wraps a single KeyRef that also implements LoadedKeyProvider.
type loadedBackend struct{ key backend.KeyRef }

func (b loadedBackend) Name() string { return "loaded-fake" }
func (b loadedBackend) ListKeys(context.Context) ([]backend.KeyRef, error) {
	return []backend.KeyRef{b.key}, nil
}
func (b loadedBackend) GetKey(_ context.Context, h backend.KeyHash) (backend.KeyRef, error) {
	if h == b.key.Hash() {
		return b.key, nil
	}
	return nil, backend.ErrKeyNotFound
}

// addrForKey builds a mainnet enterprise address from a raw Ed25519 public key.
// The payment-key hash is blake2b-224(pub), matching what backend.HashPublicKey returns.
func addrForKey(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	h := backend.HashPublicKey(pub)
	addr, err := lcommon.NewAddressFromParts(
		lcommon.AddressTypeKeyNone,
		lcommon.AddressNetworkMainnet,
		h[:],
		nil,
	)
	if err != nil {
		t.Fatalf("addrForKey: NewAddressFromParts: %v", err)
	}
	return addr.String()
}

// softwareLoadedKey is a fakeKey that also provides a real bursa.LoadedKey.
type loadedFakeKey struct {
	*fakeKey
	lk *bursa.LoadedKey
}

func (k *loadedFakeKey) LoadedKey() *bursa.LoadedKey { return k.lk }

// fakeKey does NOT implement LoadedKeyProvider, so it stands in for a remote
// (Vault) key: CIP-8 must be rejected as unsupported.
func TestSignCIP8_UnsupportedOnRemoteKey(t *testing.T) {
	k := newFakeKey(t)
	c, _ := newCoordinator(t, k,
		policy.KeyPolicy{AllowedRequests: []string{"cip8"}, CIP8: &policy.CIP8Policy{}},
		watermark.NewMemWatermark(), fakeCardano{})
	_, code, err := c.SignCIP8(context.Background(), []byte("hi"), "addr1xyz", k.hash.String())
	if err == nil || code != CodeUnsupported {
		t.Fatalf("expected unsupported for remote key, got code=%s err=%v", code, err)
	}
}

func TestSignCIP8_HappyPath(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	base := &fakeKey{pub: pub, priv: priv, hash: backend.HashPublicKey(pub)}
	k := &loadedFakeKey{fakeKey: base, lk: &bursa.LoadedKey{SKey: []byte(priv), VKey: pub}}

	pol := policy.KeyPolicy{Hash: base.hash.String(), AllowedRequests: []string{"cip8"}, CIP8: &policy.CIP8Policy{MaxPayloadBytes: 64}}
	eng, _ := policy.NewEngine([]policy.KeyPolicy{pol})
	// Use a resolver that returns the loaded key.
	c := New(Deps{Resolver: backend.NewResolver(loadedBackend{k}), Policy: eng, Watermark: watermark.NewMemWatermark(), Cardano: fakeCardano{}})
	res, code, err := c.SignCIP8(context.Background(), []byte("hello"), addrForKey(t, pub), base.hash.String())
	if err != nil {
		t.Fatalf("SignCIP8: code=%s err=%v", code, err)
	}
	if res.SignatureHex == "" || res.KeyHex == "" {
		t.Fatalf("empty COSE result")
	}
}
