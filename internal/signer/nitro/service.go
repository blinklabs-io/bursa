// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package nitro

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

const (
	requestNonceSize = 32
	maxSeenNonces    = 65536
)

// Service owns the active plaintext key and performs every cryptographic
// operation. It is intended to run only in the measured enclave image.
type Service struct {
	initMu             sync.Mutex
	mu                 sync.Mutex
	recipient          Recipient
	kms                KMSFactory
	provisionAuthority ed25519.PublicKey
	key                ed25519.PrivateKey
	pub                ed25519.PublicKey
	seen               map[[requestNonceSize]byte]struct{}
	counter            uint64
	hasCounter         bool
}

// NewService constructs an enclave service from the NSM recipient, an
// enclave-side KMS client factory, and a measured provisioning authority.
func NewService(recipient Recipient, kms KMSFactory, provisionAuthority ed25519.PublicKey) (*Service, error) {
	if recipient == nil || kms == nil || len(provisionAuthority) != ed25519.PublicKeySize ||
		bytes.Equal(provisionAuthority, make([]byte, ed25519.PublicKeySize)) {
		return nil, errors.New("nitro recipient, KMS factory, and provisioning authority are required")
	}
	return &Service{
		recipient: recipient, kms: kms,
		provisionAuthority: bytes.Clone(provisionAuthority),
		seen:               make(map[[requestNonceSize]byte]struct{}),
	}, nil
}

func validateKMSRequest(region, keyID string, credentials Credentials) error {
	if region == "" {
		return errors.New("AWS region is required")
	}
	if err := credentials.validate(); err != nil {
		return err
	}
	parsed, err := arn.Parse(keyID)
	if err != nil {
		return fmt.Errorf("KMS key ID must be an ARN: %w", err)
	}
	if parsed.Partition != "aws" || parsed.Service != "kms" || parsed.Region != region || parsed.Resource == "" {
		return errors.New("KMS key ARN must be an AWS KMS resource in the configured region")
	}
	// The envelope authenticates the key ID, so an alias that is later
	// repointed would make the stored data key undecryptable.
	if !strings.HasPrefix(parsed.Resource, "key/") || len(parsed.Resource) == len("key/") {
		return errors.New("KMS key ID must be a key ARN, not an alias")
	}
	return nil
}

// Provision generates a pool cold seed, envelope-encrypts it, installs it,
// and returns only the wrapped envelope.
func (s *Service) Provision(ctx context.Context, req *ProvisionRequest) (*ProvisionResponse, error) {
	s.initMu.Lock()
	defer s.initMu.Unlock()
	if req == nil || req.Version != Protocol {
		return nil, fmt.Errorf("%w: invalid provision version", ErrProtocol)
	}
	if req.Role != backend.KeyTypePool {
		return nil, fmt.Errorf("%w: Nitro custody initially supports only %q keys", ErrProtocol, backend.KeyTypePool)
	}
	if err := validateKMSRequest(req.Region, req.KMSKeyID, req.Credentials); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProtocol, err)
	}
	if len(req.Authorization) != ed25519.SignatureSize ||
		!ed25519.Verify(s.provisionAuthority, ProvisionAuthorizationBinding(*req), req.Authorization) {
		return nil, fmt.Errorf("%w: provisioning authorization invalid", ErrProtocol)
	}
	kms, err := s.kms(req.Region, req.Credentials)
	if err != nil {
		return nil, fmt.Errorf("create KMS client: %w", err)
	}
	evidence, err := s.recipient.KMSAttestation()
	if err != nil {
		return nil, fmt.Errorf("KMS recipient attestation: %w", err)
	}
	if err := requireProductionEvidence(evidence); err != nil {
		return nil, err
	}
	kmsCiphertext, recipientCiphertext, err := kms.GenerateDataKey(ctx, req.KMSKeyID, evidence)
	if err != nil {
		return nil, fmt.Errorf("KMS generate data key: %w", err)
	}
	dataKey, err := decryptRecipient(s.recipient, recipientCiphertext)
	if err != nil {
		return nil, err
	}
	defer clear(dataKey)
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("generate pool cold key: %w", err)
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	pub := bytes.Clone(key.Public().(ed25519.PublicKey))
	env := Envelope{
		Version:          EnvelopeVersion,
		Role:             backend.KeyTypePool,
		KMSKeyID:         req.KMSKeyID,
		PublicKey:        pub,
		EncryptedDataKey: bytes.Clone(kmsCiphertext),
	}
	env.Ciphertext, env.Nonce, err = sealSeed(dataKey, seed, env)
	if err != nil {
		clear(key)
		return nil, fmt.Errorf("wrap pool cold key: %w", err)
	}
	s.install(key, pub)
	clear(key)
	return &ProvisionResponse{Version: Protocol, Envelope: env}, nil
}

// Reload recovers a wrapped key through recipient-attested KMS and atomically
// replaces the active key. Failed reloads preserve the active key and its
// replay and counter state.
func (s *Service) Reload(ctx context.Context, req *ReloadRequest) (*ReloadResponse, error) {
	s.initMu.Lock()
	defer s.initMu.Unlock()
	if req == nil || req.Version != Protocol {
		return nil, fmt.Errorf("%w: invalid reload version", ErrProtocol)
	}
	if err := validateEnvelope(req.Envelope); err != nil {
		return nil, err
	}
	if err := validateKMSRequest(req.Region, req.Envelope.KMSKeyID, req.Credentials); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProtocol, err)
	}
	kms, err := s.kms(req.Region, req.Credentials)
	if err != nil {
		return nil, fmt.Errorf("create KMS client: %w", err)
	}
	evidence, err := s.recipient.KMSAttestation()
	if err != nil {
		return nil, fmt.Errorf("KMS recipient attestation: %w", err)
	}
	if err := requireProductionEvidence(evidence); err != nil {
		return nil, err
	}
	recipientCiphertext, err := kms.Decrypt(ctx, req.Envelope.KMSKeyID, req.Envelope.EncryptedDataKey, evidence)
	if err != nil {
		return nil, fmt.Errorf("KMS decrypt data key: %w", err)
	}
	dataKey, err := decryptRecipient(s.recipient, recipientCiphertext)
	if err != nil {
		return nil, err
	}
	defer clear(dataKey)
	seed, err := openSeed(dataKey, req.Envelope)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	pub := key.Public().(ed25519.PublicKey)
	if !bytes.Equal(pub, req.Envelope.PublicKey) {
		clear(key)
		return nil, fmt.Errorf("%w: public key does not match plaintext", ErrEnvelope)
	}
	s.install(key, pub)
	clear(key)
	return &ReloadResponse{Version: Protocol, PublicKey: bytes.Clone(pub)}, nil
}

// Inventory returns the active public key and NSM evidence bound to the
// caller's fresh nonce and exact inventory.
func (s *Service) Inventory(_ context.Context, req *InventoryRequest) (*backend.AttestedInventory, error) {
	if req == nil || req.Version != Protocol || len(req.Nonce) != requestNonceSize {
		return nil, fmt.Errorf("%w: invalid inventory request", ErrProtocol)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pub) != ed25519.PublicKeySize {
		return nil, ErrNotLoaded
	}
	keys := []backend.AttestedKeyInfo{{Role: backend.KeyTypePool, PublicKey: bytes.Clone(s.pub)}}
	binding := backend.InventoryBinding(req.Nonce, keys)
	evidence, err := s.recipient.Attest(binding)
	if err != nil {
		return nil, fmt.Errorf("inventory attestation: %w", err)
	}
	if err := requireProductionEvidence(evidence); err != nil {
		return nil, err
	}
	return &backend.AttestedInventory{Version: backend.AttestedProtocol, Keys: keys, Attestation: evidence}, nil
}

// Sign accepts only canonical pool-cold operational-certificate signables.
func (s *Service) Sign(_ context.Context, req *backend.AttestedRequest) (*backend.AttestedResponse, error) {
	if req == nil || req.Version != backend.AttestedProtocol || req.Purpose != backend.PurposeOpCert ||
		req.Role != backend.KeyTypePool || len(req.Payload) != 48 || len(req.Nonce) != requestNonceSize {
		return nil, fmt.Errorf("%w: invalid opcert request", ErrProtocol)
	}
	var nonce [requestNonceSize]byte
	copy(nonce[:], req.Nonce)
	issueCounter := binary.BigEndian.Uint64(req.Payload[32:40])

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.key) != ed25519.PrivateKeySize {
		return nil, ErrNotLoaded
	}
	if req.KeyHash != backend.HashPublicKey(s.pub).String() {
		return nil, fmt.Errorf("%w: key hash mismatch", ErrProtocol)
	}
	if _, exists := s.seen[nonce]; exists {
		return nil, fmt.Errorf("%w: request nonce replay", ErrProtocol)
	}
	if len(s.seen) >= maxSeenNonces {
		return nil, fmt.Errorf("%w: replay cache is full", ErrProtocol)
	}
	if s.hasCounter && issueCounter <= s.counter {
		return nil, fmt.Errorf("%w: opcert issue counter is not increasing", ErrProtocol)
	}
	s.seen[nonce] = struct{}{}
	s.counter = issueCounter
	s.hasCounter = true
	sig := ed25519.Sign(s.key, req.Payload)
	return &backend.AttestedResponse{Version: backend.AttestedProtocol, Nonce: bytes.Clone(req.Nonce), Signature: sig}, nil
}

func (s *Service) install(key ed25519.PrivateKey, pub ed25519.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sameKey := bytes.Equal(s.pub, pub)
	clear(s.key)
	s.key = bytes.Clone(key)
	s.pub = bytes.Clone(pub)
	if !sameKey {
		s.seen = make(map[[requestNonceSize]byte]struct{})
		s.counter = 0
		s.hasCounter = false
	}
}
