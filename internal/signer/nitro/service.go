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
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

const (
	requestNonceSize = 32
	maxSeenNonces    = 65536
	// challengeTTL bounds how long an unused challenge occupies the cache.
	// Challenge is reachable without signer authorization, so a host that
	// requests challenges and never signs must not exhaust capacity forever.
	challengeTTL = time.Minute
)

// Service owns the active plaintext key and performs every cryptographic
// operation. It is intended to run only in the measured enclave image.
type Service struct {
	initMu              sync.Mutex
	mu                  sync.Mutex
	recipient           Recipient
	kms                 KMSFactory
	provisionAuthority  ed25519.PublicKey
	signerAuthority     ed25519.PublicKey
	key                 ed25519.PrivateKey
	pub                 ed25519.PublicKey
	envelope            Envelope
	challenges          map[[requestNonceSize]byte]time.Time
	challengeNextExpiry time.Time
	now                 func() time.Time
	seen                map[[requestNonceSize]byte]struct{}
	counter             uint64
	hasCounter          bool
	// payloadHash is the SHA-256 of the payload signed at counter. It is nil
	// when the counter came from a state that holds none, which allows no
	// re-sign at that counter.
	payloadHash []byte
	// sealKey seals the counter state. It is derived from the KMS data key,
	// which never leaves Provision and Reload, and it is cleared when the
	// loaded key changes.
	sealKey []byte
}

// NewService constructs an enclave service from the NSM recipient, an
// enclave-side KMS client factory, and measured provisioning and signer
// authorities.
func NewService(
	recipient Recipient,
	kms KMSFactory,
	provisionAuthority, signerAuthority ed25519.PublicKey,
) (*Service, error) {
	if recipient == nil || kms == nil ||
		len(provisionAuthority) != ed25519.PublicKeySize ||
		bytes.Equal(provisionAuthority, make([]byte, ed25519.PublicKeySize)) ||
		len(signerAuthority) != ed25519.PublicKeySize ||
		bytes.Equal(signerAuthority, make([]byte, ed25519.PublicKeySize)) {
		return nil, errors.New(
			"nitro recipient, KMS factory, provisioning authority, and signer authority are required",
		)
	}
	if bytes.Equal(provisionAuthority, signerAuthority) {
		return nil, errors.New(
			"provisioning and signer authorities must differ",
		)
	}
	return &Service{
		recipient: recipient, kms: kms,
		provisionAuthority: bytes.Clone(provisionAuthority),
		signerAuthority:    bytes.Clone(signerAuthority),
		challenges:         make(map[[requestNonceSize]byte]time.Time),
		now:                time.Now,
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
	if parsed.Partition != "aws" || parsed.Service != "kms" ||
		parsed.Region != region ||
		parsed.Resource == "" {
		return errors.New(
			"KMS key ARN must be an AWS KMS resource in the configured region",
		)
	}
	// The envelope authenticates the key ID, so an alias that is later
	// repointed would make the stored data key undecryptable.
	if !strings.HasPrefix(parsed.Resource, "key/") ||
		len(parsed.Resource) == len("key/") {
		return errors.New("KMS key ID must be a key ARN, not an alias")
	}
	return nil
}

// Provision generates a pool cold seed, envelope-encrypts it, installs it,
// and returns only the wrapped envelope.
func (s *Service) Provision(
	ctx context.Context,
	req *ProvisionRequest,
) (*ProvisionResponse, error) {
	s.initMu.Lock()
	defer s.initMu.Unlock()
	if req == nil || req.Version != Protocol {
		return nil, fmt.Errorf("%w: invalid provision version", ErrProtocol)
	}
	if req.Role != backend.KeyTypePool {
		return nil, fmt.Errorf(
			"%w: Nitro custody initially supports only %q keys",
			ErrProtocol,
			backend.KeyTypePool,
		)
	}
	if err := validateKMSRequest(req.Region, req.KMSKeyID, req.Credentials); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProtocol, err)
	}
	if len(req.Authorization) != ed25519.SignatureSize ||
		!ed25519.Verify(
			s.provisionAuthority,
			ProvisionAuthorizationBinding(*req),
			req.Authorization,
		) {
		return nil, fmt.Errorf(
			"%w: provisioning authorization invalid",
			ErrProtocol,
		)
	}
	s.mu.Lock()
	if len(s.key) != 0 || len(s.pub) != 0 {
		env := cloneEnvelope(s.envelope)
		matches := env.KMSKeyID == req.KMSKeyID && env.Role == req.Role
		s.mu.Unlock()
		if !matches {
			return nil, fmt.Errorf(
				"%w: pool cold key is already loaded",
				ErrProtocol,
			)
		}
		return &ProvisionResponse{Version: Protocol, Envelope: env}, nil
	}
	s.mu.Unlock()
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
	kmsCiphertext, recipientCiphertext, err := kms.GenerateDataKey(
		ctx,
		req.KMSKeyID,
		evidence,
	)
	if err != nil {
		return nil, fmt.Errorf("KMS generate data key: %w", err)
	}
	dataKey, err := decryptRecipient(s.recipient, recipientCiphertext)
	if err != nil {
		return nil, err
	}
	defer clear(dataKey)
	sealKey, err := deriveSealKey(dataKey)
	if err != nil {
		return nil, fmt.Errorf("derive counter sealing key: %w", err)
	}
	defer clear(sealKey)
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
	s.install(key, pub, env, sealKey, nil)
	clear(key)
	return &ProvisionResponse{Version: Protocol, Envelope: env}, nil
}

// Reload recovers a wrapped key through recipient-attested KMS and restores
// the highest issued counter from the sealed state the host stored with the
// last released signature. A tampered state, or one sealed for another pool
// key or KMS key, refuses the reload. An absent state starts with no known
// counter, which is no weaker than the host restoring an older secret
// version. An already loaded service accepts only the same public key,
// preserving its replay state, and never lowers its counter to a stored one;
// the payload hash of the winning counter is kept with it.
func (s *Service) Reload(
	ctx context.Context,
	req *ReloadRequest,
) (*ReloadResponse, error) {
	s.initMu.Lock()
	defer s.initMu.Unlock()
	if req == nil || req.Version != Protocol {
		return nil, fmt.Errorf("%w: invalid reload version", ErrProtocol)
	}
	if err := validateEnvelope(req.Envelope); err != nil {
		return nil, err
	}
	if len(req.SealedState) > maxSealedStateSize {
		return nil, fmt.Errorf(
			"%w: state exceeds %d bytes",
			ErrCounterState,
			maxSealedStateSize,
		)
	}
	s.mu.Lock()
	activePublicKey := bytes.Clone(s.pub)
	s.mu.Unlock()
	if len(activePublicKey) != 0 &&
		!bytes.Equal(activePublicKey, req.Envelope.PublicKey) {
		return nil, fmt.Errorf(
			"%w: a different pool cold key is already loaded",
			ErrProtocol,
		)
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
	recipientCiphertext, err := kms.Decrypt(
		ctx,
		req.Envelope.KMSKeyID,
		req.Envelope.EncryptedDataKey,
		evidence,
	)
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
		return nil, fmt.Errorf(
			"%w: public key does not match plaintext",
			ErrEnvelope,
		)
	}
	sealKey, err := deriveSealKey(dataKey)
	if err != nil {
		clear(key)
		return nil, fmt.Errorf("derive counter sealing key: %w", err)
	}
	defer clear(sealKey)
	// Authenticate the state before installing anything, so a refused reload
	// leaves a loaded service untouched. No state is a legacy start.
	var restored *counterRecord
	if len(req.SealedState) != 0 {
		record, err := openCounterState(
			sealKey,
			pub,
			req.Envelope.KMSKeyID,
			req.SealedState,
		)
		if err != nil {
			clear(key)
			return nil, err
		}
		restored = &record
	}
	s.install(key, pub, req.Envelope, sealKey, restored)
	clear(key)
	return &ReloadResponse{Version: Protocol, PublicKey: bytes.Clone(pub)}, nil
}

// Inventory returns the active public key and NSM evidence bound to the
// caller's fresh nonce and exact inventory.
func (s *Service) Inventory(
	_ context.Context,
	req *InventoryRequest,
) (*backend.AttestedInventory, error) {
	if req == nil || req.Version != Protocol ||
		len(req.Nonce) != requestNonceSize {
		return nil, fmt.Errorf("%w: invalid inventory request", ErrProtocol)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pub) != ed25519.PublicKeySize {
		return nil, ErrNotLoaded
	}
	keys := []backend.AttestedKeyInfo{
		{Role: backend.KeyTypePool, PublicKey: bytes.Clone(s.pub)},
	}
	binding := backend.InventoryBinding(req.Nonce, keys)
	evidence, err := s.recipient.Attest(binding)
	if err != nil {
		return nil, fmt.Errorf("inventory attestation: %w", err)
	}
	if err := requireProductionEvidence(evidence); err != nil {
		return nil, err
	}
	return &backend.AttestedInventory{
		Version:     backend.AttestedProtocol,
		Keys:        keys,
		Attestation: evidence,
	}, nil
}

// Challenge returns a one-time value that binds the next signing request to
// the separately authorized signer process rather than the untrusted proxy.
func (s *Service) Challenge(
	_ context.Context,
	req *ChallengeRequest,
) (*ChallengeResponse, error) {
	if req == nil || req.Version != Protocol {
		return nil, fmt.Errorf("%w: invalid challenge request", ErrProtocol)
	}
	var challenge [requestNonceSize]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return nil, fmt.Errorf("generate signer challenge: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if len(s.challenges) >= maxSeenNonces {
		if s.challengeNextExpiry.IsZero() ||
			!now.Before(s.challengeNextExpiry) {
			s.purgeExpiredChallenges(now)
		}
	}
	if len(s.challenges) >= maxSeenNonces {
		return nil, fmt.Errorf("%w: challenge cache is full", ErrProtocol)
	}
	expires := now.Add(challengeTTL)
	s.challenges[challenge] = expires
	if s.challengeNextExpiry.IsZero() ||
		expires.Before(s.challengeNextExpiry) {
		s.challengeNextExpiry = expires
	}
	return &ChallengeResponse{
		Version:   backend.AttestedProtocol,
		Challenge: bytes.Clone(challenge[:]),
	}, nil
}

// Sign accepts only canonical pool-cold operational-certificate signables with
// an explicit issue counter. The counter must rise, except that a payload
// identical to the one last signed at the stored counter is signed again. It
// refuses opcert-next, which would let the host re-issue an existing number
// for a new KES key, and profiled requests, whose binding signature this
// enclave does not produce.
func (s *Service) Sign(
	_ context.Context,
	req *backend.AttestedRequest,
) (*SignResponse, error) {
	if req == nil || req.Version != backend.AttestedProtocol ||
		req.Purpose != backend.PurposeOpCert ||
		req.Profile != "" || req.Era != nil ||
		req.Role != backend.KeyTypePool ||
		len(req.Payload) != 48 ||
		len(req.Nonce) != requestNonceSize {
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
	var challenge [requestNonceSize]byte
	if len(req.Challenge) != requestNonceSize {
		return nil, fmt.Errorf("%w: signer challenge is required", ErrProtocol)
	}
	copy(challenge[:], req.Challenge)
	expires, exists := s.challenges[challenge]
	if !exists {
		return nil, fmt.Errorf(
			"%w: signer challenge is unknown or used",
			ErrProtocol,
		)
	}
	if !s.now().Before(expires) {
		s.deleteChallenge(challenge, expires)
		return nil, fmt.Errorf("%w: signer challenge expired", ErrProtocol)
	}
	if !bytes.Equal(req.HostKey, s.signerAuthority) ||
		len(req.HostSignature) != ed25519.SignatureSize ||
		!ed25519.Verify(s.signerAuthority, backend.AttestedRequestBinding(*req), req.HostSignature) {
		return nil, fmt.Errorf("%w: signer authorization invalid", ErrProtocol)
	}
	s.deleteChallenge(challenge, expires)
	if _, exists := s.seen[nonce]; exists {
		return nil, fmt.Errorf("%w: request nonce replay", ErrProtocol)
	}
	if len(s.seen) >= maxSeenNonces {
		return nil, fmt.Errorf("%w: replay cache is full", ErrProtocol)
	}
	payloadHash := hashPayload(req.Payload)
	if s.hasCounter && issueCounter <= s.counter {
		// A request whose payload is identical to the one signed at the
		// stored counter is signed again. Ed25519 is deterministic, so the
		// signature is the one already issued and nothing new exists. It
		// recovers a response that was lost after the state was saved.
		if issueCounter < s.counter || s.payloadHash == nil {
			return nil, fmt.Errorf(
				"%w: opcert issue counter is not increasing",
				ErrProtocol,
			)
		}
		if subtle.ConstantTimeCompare(s.payloadHash, payloadHash) != 1 {
			return nil, fmt.Errorf(
				"%w: opcert issue counter already signed for a different payload",
				ErrProtocol,
			)
		}
	}
	// Seal before consuming the nonce or advancing the counter, so a sealing
	// failure releases nothing and changes nothing.
	sealed, err := sealCounterState(
		s.sealKey,
		s.pub,
		s.envelope.KMSKeyID,
		issueCounter,
		payloadHash,
	)
	if err != nil {
		return nil, fmt.Errorf("seal counter state: %w", err)
	}
	s.seen[nonce] = struct{}{}
	s.counter = issueCounter
	s.hasCounter = true
	s.payloadHash = payloadHash
	sig := ed25519.Sign(s.key, req.Payload)
	return &SignResponse{AttestedResponse: backend.AttestedResponse{
		Version:   backend.AttestedProtocol,
		Nonce:     bytes.Clone(req.Nonce),
		Signature: sig,
	}, SealedState: sealed}, nil
}

func (s *Service) install(
	key ed25519.PrivateKey,
	pub ed25519.PublicKey,
	env Envelope,
	sealKey []byte,
	restored *counterRecord,
) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sameKey := bytes.Equal(s.pub, pub)
	clear(s.key)
	clear(s.sealKey)
	s.sealKey = bytes.Clone(sealKey)
	s.key = bytes.Clone(key)
	s.pub = bytes.Clone(pub)
	s.envelope = cloneEnvelope(env)
	if !sameKey {
		s.challenges = make(map[[requestNonceSize]byte]time.Time)
		s.challengeNextExpiry = time.Time{}
		s.seen = make(map[[requestNonceSize]byte]struct{})
		s.counter = 0
		s.hasCounter = false
		s.payloadHash = nil
	}
	// Restore under the same lock as the install, so no Sign can run between
	// them. The counter only ever rises, and its payload hash travels with
	// it: when the stored counter wins, so does its hash. At an equal
	// counter the hash already held stays, and a stored one fills a gap.
	if restored != nil {
		switch {
		case !s.hasCounter || restored.LastIssued > s.counter:
			s.counter = restored.LastIssued
			s.hasCounter = true
			s.payloadHash = bytes.Clone(restored.PayloadHash)
		case restored.LastIssued == s.counter && s.payloadHash == nil:
			s.payloadHash = bytes.Clone(restored.PayloadHash)
		}
	}
}

func (s *Service) deleteChallenge(
	challenge [requestNonceSize]byte,
	expires time.Time,
) {
	delete(s.challenges, challenge)
	if expires.Equal(s.challengeNextExpiry) {
		s.recalculateChallengeNextExpiry()
	}
}

func (s *Service) recalculateChallengeNextExpiry() {
	nextExpiry := time.Time{}
	for _, expires := range s.challenges {
		if nextExpiry.IsZero() || expires.Before(nextExpiry) {
			nextExpiry = expires
		}
	}
	s.challengeNextExpiry = nextExpiry
}

func (s *Service) purgeExpiredChallenges(now time.Time) {
	nextExpiry := time.Time{}
	for challenge, expires := range s.challenges {
		if !now.Before(expires) {
			delete(s.challenges, challenge)
			continue
		}
		if nextExpiry.IsZero() || expires.Before(nextExpiry) {
			nextExpiry = expires
		}
	}
	s.challengeNextExpiry = nextExpiry
}
