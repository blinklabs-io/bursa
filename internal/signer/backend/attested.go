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
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"strconv"
	"sync"
)

// AttestedProtocol is the version string every attested-signer message
// carries. A peer speaking a different version is refused.
const AttestedProtocol = "bursa-attested-signer/1"

// attestedNonceSize is the length in bytes of the attestation and per-request
// nonces.
const attestedNonceSize = 32

var (
	// ErrAttestation is returned when an enclave's attestation evidence is
	// missing, malformed, unauthentic, or does not match the expected
	// measurements. A backend that fails attestation serves no keys.
	ErrAttestation = errors.New("attestation failed")
	// ErrPurposeRequired is returned by a plain Sign on an attested key: every
	// attested signature must be bound to a purpose.
	ErrPurposeRequired = errors.New("attested keys sign only through SignPurpose")
	// ErrAttestedProtocol is returned for a malformed, mismatched, or replayed
	// enclave message.
	ErrAttestedProtocol = errors.New("attested protocol violation")
)

// Purpose binds a signature request to the Cardano operation it authorizes.
// The enclave signs a payload only when its shape matches the purpose and the
// key's role may perform it.
type Purpose string

const (
	// PurposeTxHash signs a 32-byte transaction body hash.
	PurposeTxHash Purpose = "tx-hash"
	// PurposeOpCert signs the 48-byte OCertSignable bytes
	// (kes_vkey || issue_counter || kes_period). Pool cold keys only.
	PurposeOpCert Purpose = "opcert"
	// PurposeCIP8 signs a COSE Sig_structure built for CIP-8 data signing.
	PurposeCIP8 Purpose = "cip8"
)

const (
	txHashSize = 32
	// opCertSignableSize is kes_vkey (32) + issue counter (8) + KES period (8).
	opCertSignableSize = 48
)

// validate checks payload shape and key role for the purpose.
func (p Purpose) validate(role KeyType, payload []byte) error {
	switch p {
	case PurposeTxHash:
		if len(payload) != txHashSize {
			return fmt.Errorf("%w: tx-hash payload must be %d bytes, got %d", ErrAttestedProtocol, txHashSize, len(payload))
		}
	case PurposeOpCert:
		if len(payload) != opCertSignableSize {
			return fmt.Errorf("%w: opcert payload must be %d bytes, got %d", ErrAttestedProtocol, opCertSignableSize, len(payload))
		}
		if role != KeyTypePool {
			return fmt.Errorf("%w: opcert requires a %q key, got %q", ErrAttestedProtocol, KeyTypePool, role)
		}
	case PurposeCIP8:
		if len(payload) == 0 {
			return fmt.Errorf("%w: cip8 payload is empty", ErrAttestedProtocol)
		}
	default:
		return fmt.Errorf("%w: unknown purpose %q", ErrAttestedProtocol, p)
	}
	return nil
}

// PurposeSigner is implemented by KeyRefs that bind every signature to a
// purpose (attested remote keys).
type PurposeSigner interface {
	SignPurpose(ctx context.Context, purpose Purpose, payload []byte) ([]byte, error)
}

// SignFor signs payload for purpose, using the purpose-bound path when the key
// offers one and a plain Sign otherwise.
func SignFor(ctx context.Context, ref KeyRef, purpose Purpose, payload []byte) ([]byte, error) {
	if ps, ok := ref.(PurposeSigner); ok {
		return ps.SignPurpose(ctx, purpose, payload)
	}
	return ref.Sign(ctx, payload)
}

// AttestedKeyInfo is one key an enclave reports holding.
type AttestedKeyInfo struct {
	Role      KeyType `json:"role"`
	PublicKey []byte  `json:"public_key"`
}

// AttestedInventory lists the keys an enclave holds, with attestation evidence
// that binds the list to a verified workload and to the caller's nonce.
type AttestedInventory struct {
	Version     string            `json:"version"`
	Keys        []AttestedKeyInfo `json:"keys"`
	Attestation []byte            `json:"attestation"`
}

// AttestedRequest asks the enclave to sign Payload with the key KeyHash in
// the stated Role. Nonce is fresh per request and must be echoed.
type AttestedRequest struct {
	Version string  `json:"version"`
	Purpose Purpose `json:"purpose"`
	KeyHash string  `json:"key_hash"`
	Role    KeyType `json:"role"`
	Nonce   []byte  `json:"nonce"`
	Payload []byte  `json:"payload"`
}

// AttestedResponse is the enclave's answer to an AttestedRequest. A non-empty
// Error means the enclave refused.
type AttestedResponse struct {
	Version   string `json:"version"`
	Nonce     []byte `json:"nonce"`
	Signature []byte `json:"signature,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Enclave is the host-side view of a workload that custodies keys inside a
// trusted execution environment. Implementations carry the messages over a
// host proxy that is NOT trusted: authenticity comes from the attestation
// evidence and from verifying signatures, never from the channel.
type Enclave interface {
	// Inventory returns the held keys and attestation evidence bound to nonce
	// (see InventoryBinding).
	Inventory(ctx context.Context, nonce []byte) (AttestedInventory, error)
	// Sign performs one purpose-bound signature.
	Sign(ctx context.Context, req AttestedRequest) (AttestedResponse, error)
}

// AttestationVerifier validates attestation evidence from a specific
// platform. It must fail unless the evidence is authentic, comes from the
// expected non-debug workload, and commits to binding.
type AttestationVerifier interface {
	Verify(ctx context.Context, evidence, binding []byte) error
}

// InventoryBinding is the digest an enclave commits to in its attestation
// evidence: the protocol version, the caller's nonce, and every key's role and
// public key in order. A verifier checks the evidence carries this value, so
// evidence cannot be replayed for another nonce or paired with another key list.
func InventoryBinding(nonce []byte, keys []AttestedKeyInfo) []byte {
	h := sha256.New()
	h.Write([]byte(AttestedProtocol))
	h.Write(nonce)
	for _, k := range keys {
		h.Write([]byte(strconv.Itoa(len(k.Role)) + ":" + string(k.Role)))
		h.Write(k.PublicKey)
	}
	return h.Sum(nil)
}

type attestedKey struct {
	owner       *AttestedBackend
	enclave     Enclave
	pub         ed25519.PublicKey
	hash        KeyHash
	typ         KeyType
	backendName string
}

func (k *attestedKey) Hash() KeyHash                { return k.hash }
func (k *attestedKey) PublicKey() ed25519.PublicKey { return k.pub }
func (k *attestedKey) Type() KeyType                { return k.typ }
func (k *attestedKey) Extended() bool               { return false }
func (k *attestedKey) Backend() string              { return k.backendName }

func (k *attestedKey) Sign(context.Context, []byte) ([]byte, error) {
	return nil, ErrPurposeRequired
}

// SignPurpose refuses unless k is still in the owner's served set, both before
// contacting the enclave and after it answers: a handle resolved before a
// reload must not outlive the attestation that admitted it.
func (k *attestedKey) SignPurpose(ctx context.Context, purpose Purpose, payload []byte) ([]byte, error) {
	if err := purpose.validate(k.typ, payload); err != nil {
		return nil, err
	}
	if !k.owner.serves(k) {
		return nil, ErrKeyNotFound
	}
	nonce := make([]byte, attestedNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("attested nonce: %w", err)
	}
	resp, err := k.enclave.Sign(ctx, AttestedRequest{
		Version: AttestedProtocol,
		Purpose: purpose,
		KeyHash: k.hash.String(),
		Role:    k.typ,
		Nonce:   nonce,
		Payload: payload,
	})
	if err != nil {
		return nil, fmt.Errorf("attested sign: %w", err)
	}
	if resp.Version != AttestedProtocol {
		return nil, fmt.Errorf("%w: response version %q", ErrAttestedProtocol, resp.Version)
	}
	if subtle.ConstantTimeCompare(resp.Nonce, nonce) != 1 {
		return nil, fmt.Errorf("%w: response nonce does not match request", ErrAttestedProtocol)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("attested sign: enclave refused: %s", resp.Error)
	}
	if len(resp.Signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: signature must be %d bytes, got %d", ErrAttestedProtocol, ed25519.SignatureSize, len(resp.Signature))
	}
	if !k.owner.serves(k) {
		return nil, ErrKeyNotFound
	}
	return resp.Signature, nil
}

// AttestedBackend serves keys held by an attested enclave. Keys are resolved
// by Cardano key hash with the role the attested inventory declares. Until
// Load succeeds, and after any Load fails, the backend holds no keys.
type AttestedBackend struct {
	name     string
	enclave  Enclave
	verifier AttestationVerifier
	mu       sync.RWMutex
	keys     map[KeyHash]*attestedKey
}

// NewAttestedBackend builds a backend over enclave, trusting only keys whose
// inventory passes verifier.
func NewAttestedBackend(name string, enclave Enclave, verifier AttestationVerifier) *AttestedBackend {
	return &AttestedBackend{name: name, enclave: enclave, verifier: verifier, keys: map[KeyHash]*attestedKey{}}
}

// Load attests the enclave and replaces the served key set with its verified
// inventory. It drops every key first, so a failed or repeated attestation
// (for example after an enclave restart) never leaves stale keys in service.
func (b *AttestedBackend) Load(ctx context.Context) error {
	b.mu.Lock()
	b.keys = map[KeyHash]*attestedKey{}
	b.mu.Unlock()

	nonce := make([]byte, attestedNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("attested nonce: %w", err)
	}
	inv, err := b.enclave.Inventory(ctx, nonce)
	if err != nil {
		return fmt.Errorf("attested inventory: %w", err)
	}
	if inv.Version != AttestedProtocol {
		return fmt.Errorf("%w: inventory version %q", ErrAttestedProtocol, inv.Version)
	}
	if len(inv.Attestation) == 0 {
		return fmt.Errorf("%w: missing attestation evidence", ErrAttestation)
	}
	if err := b.verifier.Verify(ctx, inv.Attestation, InventoryBinding(nonce, inv.Keys)); err != nil {
		return fmt.Errorf("%w: %w", ErrAttestation, err)
	}
	keys := make(map[KeyHash]*attestedKey, len(inv.Keys))
	for _, ki := range inv.Keys {
		if !ki.Role.Valid() {
			return fmt.Errorf("%w: invalid key role %q", ErrAttestedProtocol, ki.Role)
		}
		if len(ki.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: public key must be %d bytes, got %d", ErrAttestedProtocol, ed25519.PublicKeySize, len(ki.PublicKey))
		}
		hash := HashPublicKey(ki.PublicKey)
		if _, dup := keys[hash]; dup {
			return fmt.Errorf("%w: duplicate key %s in inventory", ErrAttestedProtocol, hash)
		}
		keys[hash] = &attestedKey{
			owner:       b,
			enclave:     b.enclave,
			pub:         ed25519.PublicKey(append([]byte(nil), ki.PublicKey...)),
			hash:        hash,
			typ:         ki.Role,
			backendName: b.name,
		}
	}
	b.mu.Lock()
	b.keys = keys
	b.mu.Unlock()
	return nil
}

// serves reports whether k is the handle the current attested load issued.
func (b *AttestedBackend) serves(k *attestedKey) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.keys[k.hash] == k
}

// Name returns the configured backend name.
func (b *AttestedBackend) Name() string { return b.name }

// GetKey resolves an attested key by hash.
func (b *AttestedBackend) GetKey(_ context.Context, hash KeyHash) (KeyRef, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	k, ok := b.keys[hash]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return k, nil
}

// ListKeys enumerates the attested keys.
func (b *AttestedBackend) ListKeys(_ context.Context) ([]KeyRef, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]KeyRef, 0, len(b.keys))
	for _, k := range b.keys {
		out = append(out, k)
	}
	return out, nil
}
