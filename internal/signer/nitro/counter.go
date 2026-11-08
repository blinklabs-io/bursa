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
	counterStateVersion = "bursa-nitro-counter/1"
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
}

// deriveSealKey derives the counter sealing key from the KMS data key. Only
// the enclave holds the data key, so only the enclave can seal or open state.
func deriveSealKey(dataKey []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, dataKey, nil, counterSealLabel, dataKeySize)
}

// counterAAD binds a sealed state to one pool key and KMS key.
func counterAAD(pub []byte, kmsKeyID string) []byte {
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
	writeField([]byte(counterStateVersion))
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
) ([]byte, error) {
	gcm, err := counterGCM(sealKey)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(counterState{
		Version:    counterStateVersion,
		KeyHash:    backend.HashPublicKey(pub).String(),
		LastIssued: lastIssued,
	})
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate counter nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plain, counterAAD(pub, kmsKeyID)), nil
}

// openCounterState authenticates sealed and returns the highest issued
// counter. Any failure wraps ErrCounterState.
func openCounterState(
	sealKey, pub []byte,
	kmsKeyID string,
	sealed []byte,
) (uint64, error) {
	if len(sealed) > maxSealedStateSize {
		return 0, fmt.Errorf(
			"%w: state exceeds %d bytes",
			ErrCounterState,
			maxSealedStateSize,
		)
	}
	gcm, err := counterGCM(sealKey)
	if err != nil {
		return 0, ErrCounterState
	}
	if len(sealed) < gcm.NonceSize() {
		return 0, fmt.Errorf("%w: state is truncated", ErrCounterState)
	}
	nonce, ciphertext := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, counterAAD(pub, kmsKeyID))
	if err != nil {
		return 0, fmt.Errorf(
			"%w: state is not authentic for this key",
			ErrCounterState,
		)
	}
	var state counterState
	if err := json.Unmarshal(plain, &state); err != nil {
		return 0, fmt.Errorf("%w: %w", ErrCounterState, err)
	}
	if state.Version != counterStateVersion ||
		state.KeyHash != backend.HashPublicKey(pub).String() {
		return 0, errors.Join(ErrCounterState, errors.New("state identity mismatch"))
	}
	return state.LastIssued, nil
}
