// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package nitro

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

const (
	// counterStateVersion names the sealed counter record. It is bound into
	// the AEAD additional data, so a record of another version is refused.
	// Version 2 adds the hash of the payload last signed at the counter;
	// version 1 records still load through counterStateVersionV1.
	counterStateVersion = "bursa-nitro-counter/2"
	// counterStateVersionV1 is the previous record, which holds no payload
	// hash. It still loads, and allows no re-sign at its counter.
	counterStateVersionV1 = "bursa-nitro-counter/1"
	// counterSealLabel separates the sealing key from the envelope's data key
	// use of the same KMS data key.
	counterSealLabel = "bursa-nitro-counter-seal/1"
	// maxSealedStateSize bounds a sealed counter state, as the Confidential
	// Space counter object is bounded.
	maxSealedStateSize = 4096
)

// counterState is the plaintext of the sealed counter record. A record exists
// only once a signature was issued, so its presence means a counter is known.
type counterState struct {
	Version string `json:"version"`
	KeyHash string `json:"key_hash"`
	// LastIssued is the highest issue counter the enclave signed.
	LastIssued uint64 `json:"last_issued"`
	// PayloadHash is the SHA-256 of the exact 48-byte payload signed at
	// LastIssued. A version 1 record has none.
	PayloadHash []byte `json:"payload_hash,omitempty"`
}

// payloadHashSize is the length of a SHA-256 digest.
const payloadHashSize = sha256.Size

// hashPayload returns the SHA-256 of an opcert payload. SHA-256 is already
// the enclave's hash for the sealing key and the additional data, so it adds
// no dependency, and the digest only has to be collision resistant: it sits
// inside the AEAD-sealed record, where the host can neither read nor forge it.
func hashPayload(payload []byte) []byte {
	sum := sha256.Sum256(payload)
	return sum[:]
}

// counterRecord is an authenticated counter state.
type counterRecord struct {
	LastIssued uint64
	// PayloadHash is nil for a version 1 record.
	PayloadHash []byte
}

// deriveSealKey derives the counter sealing key from the KMS data key. Only
// the enclave holds the data key, so only the enclave can seal or open state.
func deriveSealKey(dataKey []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, dataKey, nil, counterSealLabel, dataKeySize)
}

// counterAAD binds a sealed state to one pool key and KMS key.
func counterAAD(version string, pub []byte, kmsKeyID string) []byte {
	h := sha256.New()
	writeField := func(value []byte) {
		var size [4]byte
		binary.BigEndian.PutUint32(
			size[:],
			uint32(len(value)),
		) // #nosec G115 -- fields are memory-bounded
		h.Write(size[:])
		h.Write(value)
	}
	writeField([]byte(version))
	writeField(pub)
	writeField([]byte(kmsKeyID))
	return h.Sum(nil)
}

func counterGCM(sealKey []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(sealKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealCounterState returns nonce || AES-256-GCM(state) for the pool key.
func sealCounterState(
	sealKey, pub []byte,
	kmsKeyID string,
	lastIssued uint64,
	payloadHash []byte,
) ([]byte, error) {
	if len(payloadHash) != payloadHashSize {
		return nil, errors.New("counter state needs a payload hash")
	}
	gcm, err := counterGCM(sealKey)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(counterState{
		Version:     counterStateVersion,
		KeyHash:     backend.HashPublicKey(pub).String(),
		LastIssued:  lastIssued,
		PayloadHash: payloadHash,
	})
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate counter nonce: %w", err)
	}
	aad := counterAAD(counterStateVersion, pub, kmsKeyID)
	return gcm.Seal(nonce, nonce, plain, aad), nil
}

// openCounterState authenticates sealed and returns the record. The version
// is inside the ciphertext but bound into the additional data, so each known
// version is tried and the one that authenticates must match the record's own
// version field. Any failure wraps ErrCounterState.
func openCounterState(
	sealKey, pub []byte,
	kmsKeyID string,
	sealed []byte,
) (counterRecord, error) {
	if len(sealed) > maxSealedStateSize {
		return counterRecord{}, fmt.Errorf(
			"%w: state exceeds %d bytes",
			ErrCounterState,
			maxSealedStateSize,
		)
	}
	gcm, err := counterGCM(sealKey)
	if err != nil {
		return counterRecord{}, ErrCounterState
	}
	if len(sealed) < gcm.NonceSize() {
		return counterRecord{}, fmt.Errorf(
			"%w: state is truncated",
			ErrCounterState,
		)
	}
	nonce, ciphertext := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	var plain []byte
	var version string
	for _, candidate := range []string{counterStateVersion, counterStateVersionV1} {
		opened, err := gcm.Open(
			nil,
			nonce,
			ciphertext,
			counterAAD(candidate, pub, kmsKeyID),
		)
		if err == nil {
			plain, version = opened, candidate
			break
		}
	}
	if plain == nil {
		return counterRecord{}, fmt.Errorf(
			"%w: state is not authentic for this key",
			ErrCounterState,
		)
	}
	var state counterState
	if err := json.Unmarshal(plain, &state); err != nil {
		return counterRecord{}, fmt.Errorf("%w: %w", ErrCounterState, err)
	}
	if state.Version != version ||
		state.KeyHash != backend.HashPublicKey(pub).String() {
		return counterRecord{}, errors.Join(
			ErrCounterState,
			errors.New("state identity mismatch"),
		)
	}
	record := counterRecord{LastIssued: state.LastIssued}
	switch version {
	case counterStateVersion:
		if len(state.PayloadHash) != payloadHashSize {
			return counterRecord{}, fmt.Errorf(
				"%w: payload hash must be %d bytes",
				ErrCounterState,
				payloadHashSize,
			)
		}
		record.PayloadHash = state.PayloadHash
	case counterStateVersionV1:
		if len(state.PayloadHash) != 0 {
			return counterRecord{}, fmt.Errorf(
				"%w: version 1 state holds a payload hash",
				ErrCounterState,
			)
		}
	}
	return record, nil
}
