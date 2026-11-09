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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/stretchr/testify/require"
)

// opcertPayload builds a 48-byte payload: a KES key byte, then the issue
// counter and the KES period.
func opcertPayload(kes byte, counter, period uint64) []byte {
	payload := bytes.Repeat([]byte{kes}, 48)
	binary.BigEndian.PutUint64(payload[32:40], counter)
	binary.BigEndian.PutUint64(payload[40:48], period)
	return payload
}

// sealRawState seals a record under an explicit version and optional payload
// hash, independently of the production sealer, so tests can pin the on-disk
// formats and forge malformed ones.
func sealRawState(
	t *testing.T,
	sealKey, pub []byte,
	kmsKeyID, version string,
	lastIssued uint64,
	payloadHash []byte,
) []byte {
	t.Helper()
	h := sha256.New()
	for _, field := range [][]byte{[]byte(version), pub, []byte(kmsKeyID)} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		h.Write(size[:])
		h.Write(field)
	}
	record := map[string]any{
		"version":     version,
		"key_hash":    backend.HashPublicKey(pub).String(),
		"last_issued": lastIssued,
	}
	if payloadHash != nil {
		record["payload_hash"] = payloadHash
	}
	plain, err := json.Marshal(record)
	require.NoError(t, err)
	block, err := aes.NewCipher(sealKey)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	return gcm.Seal(nonce, nonce, plain, h.Sum(nil))
}

// sealV1State seals a record in the previous on-disk format, which carries no
// payload hash.
func sealV1State(
	t *testing.T,
	sealKey, pub []byte,
	kmsKeyID string,
	lastIssued uint64,
) []byte {
	t.Helper()
	return sealRawState(
		t, sealKey, pub, kmsKeyID, "bursa-nitro-counter/1", lastIssued, nil,
	)
}

func TestSignRepeatsIdenticalPayloadAtEqualCounter(t *testing.T) {
	t.Parallel()
	evidence := testEvidence(t, 6)
	service, _, _ := newTestService(t, evidence)
	env := provisionTestKey(t, service)
	payload := opcertPayload(0x11, 5, 120)

	first, err := signPayload(service, env.PublicKey, payload, 1)
	require.NoError(t, err)
	// the response was lost; the same request arrives with a fresh nonce
	// and challenge
	again, err := signPayload(service, env.PublicKey, payload, 2)
	require.NoError(t, err)
	require.Equal(t, first.Signature, again.Signature)
	require.NotEmpty(t, again.SealedState)

	// after a restart that reloads the saved state
	restarted, _, _ := newTestService(t, evidence)
	require.NoError(t, reloadWithState(restarted, env, again.SealedState))
	afterRestart, err := signPayload(restarted, env.PublicKey, payload, 3)
	require.NoError(t, err)
	require.Equal(t, first.Signature, afterRestart.Signature)

	// the re-sign opens no way back to lower counters
	_, err = signCounter(restarted, env.PublicKey, 4, 4)
	require.ErrorContains(t, err, "issue counter is not increasing")
}

func TestSignRefusesOtherPayloadAtEqualCounter(t *testing.T) {
	t.Parallel()
	evidence := testEvidence(t, 6)
	service, _, _ := newTestService(t, evidence)
	env := provisionTestKey(t, service)
	_, err := signPayload(service, env.PublicKey, opcertPayload(0x11, 5, 120), 1)
	require.NoError(t, err)

	// a different KES key, and a different KES period, at the same counter
	_, err = signPayload(service, env.PublicKey, opcertPayload(0x22, 5, 120), 2)
	require.ErrorContains(t, err, "different payload")
	_, err = signPayload(service, env.PublicKey, opcertPayload(0x11, 5, 121), 3)
	require.ErrorContains(t, err, "different payload")

	restarted, _, _ := newTestService(t, evidence)
	signed, err := signPayload(service, env.PublicKey, opcertPayload(0x11, 5, 120), 4)
	require.NoError(t, err)
	require.NoError(t, reloadWithState(restarted, env, signed.SealedState))
	_, err = signPayload(restarted, env.PublicKey, opcertPayload(0x22, 5, 120), 5)
	require.ErrorContains(t, err, "different payload")
}

func TestReloadOfV1StateAllowsNoEqualCounterSign(t *testing.T) {
	t.Parallel()
	evidence := testEvidence(t, 6)
	first, _, _ := newTestService(t, evidence)
	env := provisionTestKey(t, first)
	v1 := sealV1State(t, testSealKey(t), env.PublicKey, env.KMSKeyID, 5)

	restarted, _, _ := newTestService(t, evidence)
	require.NoError(t, reloadWithState(restarted, env, v1))
	_, err := signPayload(restarted, env.PublicKey, opcertPayload(0x11, 5, 120), 1)
	require.ErrorContains(t, err, "issue counter is not increasing")
	_, err = signCounter(restarted, env.PublicKey, 4, 2)
	require.ErrorContains(t, err, "issue counter is not increasing")
	_, err = signCounter(restarted, env.PublicKey, 6, 3)
	require.NoError(t, err)
}

func TestReloadOfLowerStateKeepsHigherCounterAndHash(t *testing.T) {
	t.Parallel()
	evidence := testEvidence(t, 6)
	service, _, _ := newTestService(t, evidence)
	env := provisionTestKey(t, service)
	low, err := signPayload(service, env.PublicKey, opcertPayload(0x11, 5, 120), 1)
	require.NoError(t, err)
	high, err := signPayload(service, env.PublicKey, opcertPayload(0x22, 7, 130), 2)
	require.NoError(t, err)

	require.NoError(t, reloadWithState(service, env, low.SealedState))
	again, err := signPayload(service, env.PublicKey, opcertPayload(0x22, 7, 130), 3)
	require.NoError(t, err)
	require.Equal(t, high.Signature, again.Signature)
	_, err = signPayload(service, env.PublicKey, opcertPayload(0x11, 5, 120), 4)
	require.ErrorContains(t, err, "issue counter is not increasing")
	_, err = signPayload(service, env.PublicKey, opcertPayload(0x33, 7, 130), 5)
	require.ErrorContains(t, err, "different payload")
}

func TestOpenCounterStateRefusesMalformedHash(t *testing.T) {
	t.Parallel()
	evidence := testEvidence(t, 6)
	first, _, _ := newTestService(t, evidence)
	env := provisionTestKey(t, first)
	sealKey := testSealKey(t)
	for name, hash := range map[string][]byte{
		"absent": nil, "short": bytes.Repeat([]byte{1}, 31),
		"long": bytes.Repeat([]byte{1}, 33),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			state := sealRawState(t, sealKey, env.PublicKey, env.KMSKeyID, "bursa-nitro-counter/2", 5, hash)
			restarted, _, _ := newTestService(t, evidence)
			require.ErrorIs(t, reloadWithState(restarted, env, state), ErrCounterState)
		})
	}
}

func TestOpenCounterStateRefusesUnknownVersion(t *testing.T) {
	t.Parallel()
	evidence := testEvidence(t, 6)
	first, _, _ := newTestService(t, evidence)
	env := provisionTestKey(t, first)
	state := sealRawState(
		t, testSealKey(t), env.PublicKey, env.KMSKeyID,
		"bursa-nitro-counter/3", 5, bytes.Repeat([]byte{1}, 32),
	)
	restarted, _, _ := newTestService(t, evidence)
	require.ErrorIs(t, reloadWithState(restarted, env, state), ErrCounterState)
}

func TestReloadAtEqualCounterMergesPayloadHash(t *testing.T) {
	t.Parallel()
	evidence := testEvidence(t, 6)
	sealKey := testSealKey(t)
	original := opcertPayload(0x11, 5, 120)
	other := opcertPayload(0x22, 5, 120)

	// a loaded hash stays when a stored state at the same counter holds
	// another
	service, _, _ := newTestService(t, evidence)
	env := provisionTestKey(t, service)
	_, err := signPayload(service, env.PublicKey, original, 1)
	require.NoError(t, err)
	foreign, err := sealCounterState(
		sealKey, env.PublicKey, env.KMSKeyID, 5, hashPayload(other),
	)
	require.NoError(t, err)
	require.NoError(t, reloadWithState(service, env, foreign))
	_, err = signPayload(service, env.PublicKey, other, 2)
	require.ErrorContains(t, err, "different payload")
	_, err = signPayload(service, env.PublicKey, original, 3)
	require.NoError(t, err)

	// a stored hash fills a counter loaded from a version 1 state
	restarted, _, _ := newTestService(t, evidence)
	require.NoError(t, reloadWithState(
		restarted, env, sealV1State(t, sealKey, env.PublicKey, env.KMSKeyID, 5),
	))
	stored, err := sealCounterState(
		sealKey, env.PublicKey, env.KMSKeyID, 5, hashPayload(original),
	)
	require.NoError(t, err)
	require.NoError(t, reloadWithState(restarted, env, stored))
	_, err = signPayload(restarted, env.PublicKey, other, 4)
	require.ErrorContains(t, err, "different payload")
	_, err = signPayload(restarted, env.PublicKey, original, 5)
	require.NoError(t, err)
}
