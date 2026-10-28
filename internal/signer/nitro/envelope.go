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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

const dataKeySize = 32

func validateEnvelope(env Envelope) error {
	switch {
	case env.Version != EnvelopeVersion:
		return fmt.Errorf("%w: unsupported version %d", ErrEnvelope, env.Version)
	case env.Role != backend.KeyTypePool:
		return fmt.Errorf("%w: role must be %q", ErrEnvelope, backend.KeyTypePool)
	case env.KMSKeyID == "":
		return fmt.Errorf("%w: missing KMS key ID", ErrEnvelope)
	case len(env.PublicKey) != ed25519.PublicKeySize:
		return fmt.Errorf("%w: public key must be %d bytes", ErrEnvelope, ed25519.PublicKeySize)
	case len(env.EncryptedDataKey) == 0:
		return fmt.Errorf("%w: missing encrypted data key", ErrEnvelope)
	case len(env.Ciphertext) == 0:
		return fmt.Errorf("%w: missing private-key ciphertext", ErrEnvelope)
	case len(env.Nonce) != 12:
		return fmt.Errorf("%w: nonce must be 12 bytes", ErrEnvelope)
	}
	return nil
}

func envelopeAAD(env Envelope) []byte {
	h := sha256.New()
	writeField := func(value []byte) {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value))) // #nosec G115 -- envelope fields are memory-bounded
		h.Write(size[:])
		h.Write(value)
	}
	var version [8]byte
	binary.BigEndian.PutUint64(version[:], uint64(env.Version))
	writeField(version[:])
	writeField([]byte(env.Role))
	writeField([]byte(env.KMSKeyID))
	writeField(env.PublicKey)
	return h.Sum(nil)
}

func sealSeed(dataKey, seed []byte, env Envelope) (ciphertext, nonce []byte, err error) {
	if len(dataKey) != dataKeySize || len(seed) != ed25519.SeedSize {
		return nil, nil, ErrEnvelope
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("generate envelope nonce: %w", err)
	}
	return gcm.Seal(nil, nonce, seed, envelopeAAD(env)), nonce, nil
}

func openSeed(dataKey []byte, env Envelope) ([]byte, error) {
	if len(dataKey) != dataKeySize {
		return nil, ErrEnvelope
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, ErrEnvelope
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrEnvelope
	}
	seed, err := gcm.Open(nil, env.Nonce, env.Ciphertext, envelopeAAD(env))
	if err != nil {
		return nil, ErrEnvelope
	}
	if len(seed) != ed25519.SeedSize {
		clear(seed)
		return nil, ErrEnvelope
	}
	return seed, nil
}

func decryptRecipient(recipient Recipient, ciphertext []byte) ([]byte, error) {
	plaintext, err := recipient.DecryptKMSRecipient(ciphertext)
	if err != nil || len(plaintext) != dataKeySize {
		clear(plaintext)
		return nil, errors.Join(ErrEnvelope, err)
	}
	return plaintext, nil
}
