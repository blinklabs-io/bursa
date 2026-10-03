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
	"errors"
	"sync"
	"testing"
)

// fakeEnclave is a key-holding workload. Its attestation evidence is
// "evidence:" + hex(binding), which stubVerifier accepts, so tests can tamper
// with the inventory, the evidence, or any response independently.
type fakeEnclave struct {
	mu   sync.Mutex
	keys []fakeEnclaveKey
	// seen holds request nonces already served; a repeat is refused, as a
	// real enclave must.
	seen        map[string]bool
	signCalls   int
	tamperInv   func(nonce []byte, inv *AttestedInventory)
	tamperResp  func(req AttestedRequest, resp *AttestedResponse)
	inventoryFn func(ctx context.Context, nonce []byte) (AttestedInventory, error)
}

type fakeEnclaveKey struct {
	priv ed25519.PrivateKey
	role KeyType
}

func newFakeEnclave(t *testing.T, roles ...KeyType) *fakeEnclave {
	t.Helper()
	e := &fakeEnclave{seen: map[string]bool{}}
	for _, r := range roles {
		_, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		e.keys = append(e.keys, fakeEnclaveKey{priv: priv, role: r})
	}
	return e
}

func (e *fakeEnclave) infos() []AttestedKeyInfo {
	var out []AttestedKeyInfo
	for _, k := range e.keys {
		out = append(out, AttestedKeyInfo{Role: k.role, PublicKey: k.priv.Public().(ed25519.PublicKey)})
	}
	return out
}

func (e *fakeEnclave) hashOf(i int) KeyHash {
	return HashPublicKey(e.keys[i].priv.Public().(ed25519.PublicKey))
}

func (e *fakeEnclave) Inventory(ctx context.Context, nonce []byte) (AttestedInventory, error) {
	if e.inventoryFn != nil {
		return e.inventoryFn(ctx, nonce)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	keys := e.infos()
	inv := AttestedInventory{
		Version:     AttestedProtocol,
		Keys:        keys,
		Attestation: []byte("evidence:" + hex.EncodeToString(InventoryBinding(nonce, keys))),
	}
	if e.tamperInv != nil {
		e.tamperInv(nonce, &inv)
	}
	return inv, nil
}

func (e *fakeEnclave) Sign(_ context.Context, req AttestedRequest) (AttestedResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.signCalls++
	resp := AttestedResponse{Version: AttestedProtocol, Nonce: req.Nonce}
	switch {
	case e.seen[string(req.Nonce)]:
		resp.Error = "replayed nonce"
	default:
		e.seen[string(req.Nonce)] = true
		resp = e.signLocked(req, resp)
	}
	if e.tamperResp != nil {
		e.tamperResp(req, &resp)
	}
	return resp, nil
}

func (e *fakeEnclave) signLocked(req AttestedRequest, resp AttestedResponse) AttestedResponse {
	for _, k := range e.keys {
		pub := k.priv.Public().(ed25519.PublicKey)
		if HashPublicKey(pub).String() != req.KeyHash {
			continue
		}
		if k.role != req.Role {
			resp.Error = "role mismatch"
			return resp
		}
		if req.Purpose == PurposeOpCert && k.role != KeyTypePool {
			resp.Error = "opcert requires a pool key"
			return resp
		}
		resp.Signature = ed25519.Sign(k.priv, req.Payload)
		return resp
	}
	resp.Error = "unknown key"
	return resp
}

// stubVerifier accepts evidence minted by fakeEnclave.Inventory for exactly
// the binding it is asked about.
type stubVerifier struct{ reject error }

func (v stubVerifier) Verify(_ context.Context, evidence, binding []byte) error {
	if v.reject != nil {
		return v.reject
	}
	if string(evidence) != "evidence:"+hex.EncodeToString(binding) {
		return errors.New("evidence does not match binding")
	}
	return nil
}

func loadAttested(t *testing.T, e *fakeEnclave) *AttestedBackend {
	t.Helper()
	b := NewAttestedBackend("enclave", e, stubVerifier{})
	if err := b.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	return b
}

func TestAttestedBackendResolvesByHashAndRole(t *testing.T) {
	t.Parallel()
	e := newFakeEnclave(t, KeyTypePool, KeyTypePayment)
	b := loadAttested(t, e)

	for i, want := range []KeyType{KeyTypePool, KeyTypePayment} {
		ref, err := b.GetKey(context.Background(), e.hashOf(i))
		if err != nil {
			t.Fatalf("GetKey %d: %v", i, err)
		}
		if ref.Type() != want || ref.Hash() != e.hashOf(i) || ref.Backend() != "enclave" || ref.Extended() {
			t.Fatalf("key %d: type=%s hash=%s backend=%s", i, ref.Type(), ref.Hash(), ref.Backend())
		}
		if _, ok := ref.(LoadedKeyProvider); ok {
			t.Fatalf("attested key must not expose private key material in process")
		}
	}
	if _, err := b.GetKey(context.Background(), KeyHash{1}); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("unknown hash: got %v, want ErrKeyNotFound", err)
	}
	refs, err := b.ListKeys(context.Background())
	if err != nil || len(refs) != 2 {
		t.Fatalf("ListKeys: %d keys, err %v", len(refs), err)
	}
}

func TestAttestedBackendLoadFailsClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tests := []struct {
		name     string
		mutate   func(e *fakeEnclave)
		verifier AttestationVerifier
		wantErr  error
	}{
		{"verifier rejects", func(*fakeEnclave) {}, stubVerifier{reject: errors.New("debug enclave")}, ErrAttestation},
		{"missing evidence", func(e *fakeEnclave) {
			e.tamperInv = func(_ []byte, inv *AttestedInventory) { inv.Attestation = nil }
		}, stubVerifier{}, ErrAttestation},
		{"evidence for another nonce", func(e *fakeEnclave) {
			e.tamperInv = func(_ []byte, inv *AttestedInventory) {
				inv.Attestation = []byte("evidence:" + hex.EncodeToString(InventoryBinding(make([]byte, attestedNonceSize), inv.Keys)))
			}
		}, stubVerifier{}, ErrAttestation},
		{"key list swapped after attestation", func(e *fakeEnclave) {
			e.tamperInv = func(_ []byte, inv *AttestedInventory) {
				other := newFakeEnclave(t, KeyTypePool)
				inv.Keys = other.infos()
			}
		}, stubVerifier{}, ErrAttestation},
		{"wrong protocol version", func(e *fakeEnclave) {
			e.tamperInv = func(_ []byte, inv *AttestedInventory) { inv.Version = "bursa-attested-signer/0" }
		}, stubVerifier{}, ErrAttestedProtocol},
		{"unknown role", func(e *fakeEnclave) { e.keys[0].role = "root" }, stubVerifier{}, ErrAttestedProtocol},
		{"short public key", func(e *fakeEnclave) {
			e.inventoryFn = func(_ context.Context, nonce []byte) (AttestedInventory, error) {
				keys := []AttestedKeyInfo{{Role: KeyTypePool, PublicKey: []byte{1, 2, 3}}}
				return AttestedInventory{
					Version:     AttestedProtocol,
					Keys:        keys,
					Attestation: []byte("evidence:" + hex.EncodeToString(InventoryBinding(nonce, keys))),
				}, nil
			}
		}, stubVerifier{}, ErrAttestedProtocol},
		{"duplicate key", func(e *fakeEnclave) { e.keys = append(e.keys, e.keys[0]) }, stubVerifier{}, ErrAttestedProtocol},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newFakeEnclave(t, KeyTypePool)
			tc.mutate(e)
			b := NewAttestedBackend("enclave", e, tc.verifier)
			if err := b.Load(ctx); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Load: got %v, want %v", err, tc.wantErr)
			}
			if refs, _ := b.ListKeys(ctx); len(refs) != 0 {
				t.Fatalf("failed attestation left %d keys in service", len(refs))
			}
		})
	}
}

func TestAttestedBackendReloadReplacesKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newFakeEnclave(t, KeyTypePool)
	old := e.hashOf(0)
	b := loadAttested(t, e)

	// The enclave restarts with a different key set.
	fresh := newFakeEnclave(t, KeyTypePayment)
	e.keys = fresh.keys
	if err := b.Load(ctx); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, err := b.GetKey(ctx, old); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("stale key still served after reload: %v", err)
	}
	if _, err := b.GetKey(ctx, e.hashOf(0)); err != nil {
		t.Fatalf("new key missing after reload: %v", err)
	}

	// A reload whose attestation fails must drop what was served.
	e.tamperInv = func(_ []byte, inv *AttestedInventory) { inv.Attestation = []byte("forged") }
	if err := b.Load(ctx); !errors.Is(err, ErrAttestation) {
		t.Fatalf("reload with forged evidence: %v", err)
	}
	if _, err := b.GetKey(ctx, e.hashOf(0)); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("key still served after failed re-attestation: %v", err)
	}
}

func TestAttestedKeySignPurpose(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newFakeEnclave(t, KeyTypePool, KeyTypePayment)
	b := loadAttested(t, e)
	pool, _ := b.GetKey(ctx, e.hashOf(0))
	pay, _ := b.GetKey(ctx, e.hashOf(1))
	ps := func(k KeyRef) PurposeSigner { return k.(PurposeSigner) }

	txHash := make([]byte, 32)
	opcert := make([]byte, 48)
	for _, tc := range []struct {
		name    string
		key     KeyRef
		purpose Purpose
		payload []byte
	}{
		{"tx-hash", pay, PurposeTxHash, txHash},
		{"opcert", pool, PurposeOpCert, opcert},
		{"cip8", pay, PurposeCIP8, []byte("sig-structure")},
	} {
		sig, err := ps(tc.key).SignPurpose(ctx, tc.purpose, tc.payload)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !ed25519.Verify(tc.key.PublicKey(), tc.payload, sig) {
			t.Fatalf("%s: signature does not verify", tc.name)
		}
	}

	if _, err := pool.Sign(ctx, txHash); !errors.Is(err, ErrPurposeRequired) {
		t.Fatalf("plain Sign: got %v, want ErrPurposeRequired", err)
	}
}

func TestAttestedKeyRefusesBeforeContactingEnclave(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newFakeEnclave(t, KeyTypePool, KeyTypePayment)
	b := loadAttested(t, e)
	pool, _ := b.GetKey(ctx, e.hashOf(0))
	pay, _ := b.GetKey(ctx, e.hashOf(1))

	for _, tc := range []struct {
		name    string
		key     KeyRef
		purpose Purpose
		payload []byte
	}{
		{"opcert for payment key", pay, PurposeOpCert, make([]byte, 48)},
		{"opcert short payload", pool, PurposeOpCert, make([]byte, 47)},
		{"tx-hash short payload", pay, PurposeTxHash, make([]byte, 31)},
		{"tx-hash long payload", pay, PurposeTxHash, make([]byte, 33)},
		{"cip8 empty payload", pay, PurposeCIP8, nil},
		{"unknown purpose", pay, "kes", make([]byte, 32)},
	} {
		if _, err := tc.key.(PurposeSigner).SignPurpose(ctx, tc.purpose, tc.payload); !errors.Is(err, ErrAttestedProtocol) {
			t.Fatalf("%s: got %v, want ErrAttestedProtocol", tc.name, err)
		}
	}
	if e.signCalls != 0 {
		t.Fatalf("enclave was contacted %d times for refused requests", e.signCalls)
	}
}

func TestAttestedKeyRejectsBadEnclaveResponses(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		tamper func(req AttestedRequest, resp *AttestedResponse)
		want   error
	}{
		{"stale response replayed", func(_ AttestedRequest, r *AttestedResponse) { r.Nonce = make([]byte, attestedNonceSize) }, ErrAttestedProtocol},
		{"missing nonce", func(_ AttestedRequest, r *AttestedResponse) { r.Nonce = nil }, ErrAttestedProtocol},
		{"wrong version", func(_ AttestedRequest, r *AttestedResponse) { r.Version = "other/1" }, ErrAttestedProtocol},
		{"short signature", func(_ AttestedRequest, r *AttestedResponse) { r.Signature = r.Signature[:63] }, ErrAttestedProtocol},
		{"empty signature", func(_ AttestedRequest, r *AttestedResponse) { r.Signature = nil }, ErrAttestedProtocol},
		{"enclave refusal", func(_ AttestedRequest, r *AttestedResponse) { r.Error = "policy denied"; r.Signature = nil }, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newFakeEnclave(t, KeyTypePayment)
			e.tamperResp = tc.tamper
			ref, _ := loadAttested(t, e).GetKey(ctx, e.hashOf(0))
			_, err := ref.(PurposeSigner).SignPurpose(ctx, PurposeTxHash, make([]byte, 32))
			if err == nil {
				t.Fatal("expected an error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAttestedKeyNonceIsFreshPerRequest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newFakeEnclave(t, KeyTypePayment)
	ref, _ := loadAttested(t, e).GetKey(ctx, e.hashOf(0))
	// The enclave refuses a repeated nonce, so two identical requests only
	// both succeed when the signer draws a new nonce for each.
	for i := range 3 {
		if _, err := ref.(PurposeSigner).SignPurpose(ctx, PurposeTxHash, make([]byte, 32)); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
}

func TestSignFor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newFakeEnclave(t, KeyTypePayment)
	ref, _ := loadAttested(t, e).GetKey(ctx, e.hashOf(0))
	sig, err := SignFor(ctx, ref, PurposeTxHash, make([]byte, 32))
	if err != nil || len(sig) != ed25519.SignatureSize {
		t.Fatalf("SignFor attested: sig=%d err=%v", len(sig), err)
	}

	plain := &plainKey{}
	if _, err := SignFor(ctx, plain, PurposeTxHash, []byte("x")); err != nil || !plain.signed {
		t.Fatalf("SignFor plain key did not fall back to Sign: %v", err)
	}
}

type plainKey struct {
	KeyRef
	signed bool
}

func (k *plainKey) Sign(context.Context, []byte) ([]byte, error) {
	k.signed = true
	return []byte("sig"), nil
}
