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
	"encoding/binary"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/stretchr/testify/require"
)

const testForeignKMSKey = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000002"

// signCounter signs an opcert at the issue counter and returns the sealed
// state released with the signature.
func signCounter(
	service *Service,
	pub []byte,
	counter uint64,
	nonce byte,
) (*SignResponse, error) {
	payload := make([]byte, 48)
	binary.BigEndian.PutUint64(payload[32:40], counter)
	request := &backend.AttestedRequest{
		Version: backend.AttestedProtocol, Purpose: backend.PurposeOpCert,
		KeyHash: backend.HashPublicKey(pub).String(),
		Role:    backend.KeyTypePool,
		Nonce:   bytes.Repeat([]byte{nonce}, requestNonceSize),
		Payload: payload,
	}
	challenge, err := service.Challenge(
		context.Background(),
		&ChallengeRequest{Version: Protocol},
	)
	if err != nil {
		return nil, err
	}
	request.Challenge = challenge.Challenge
	request.HostKey = testSignerAuthority.Public().(ed25519.PublicKey)
	request.HostSignature = ed25519.Sign(
		testSignerAuthority,
		backend.AttestedRequestBinding(*request),
	)
	return service.Sign(context.Background(), request)
}

func reloadWithState(
	service *Service,
	env Envelope,
	state []byte,
) error {
	_, err := service.Reload(context.Background(), &ReloadRequest{
		Version: Protocol, Region: "us-east-1", Credentials: testCredentials,
		Envelope: env, SealedState: state,
	})
	return err
}

func testSealKey(t *testing.T) []byte {
	t.Helper()
	key, err := deriveSealKey(bytes.Repeat([]byte{0x5a}, dataKeySize))
	require.NoError(t, err)
	return key
}

func TestSealedCounterSurvivesRestart(t *testing.T) {
	t.Parallel()
	evidence := testEvidence(t, 3)
	first, _, _ := newTestService(t, evidence)
	env := provisionTestKey(t, first)
	signed, err := signCounter(first, env.PublicKey, 5, 1)
	require.NoError(t, err)
	require.NotEmpty(t, signed.SealedState, "signature released without state")

	restarted, _, _ := newTestService(t, evidence)
	require.NoError(t, reloadWithState(restarted, env, signed.SealedState))
	_, err = signCounter(restarted, env.PublicKey, 5, 2)
	require.ErrorContains(t, err, "issue counter is not increasing")
	_, err = signCounter(restarted, env.PublicKey, 4, 3)
	require.ErrorContains(t, err, "issue counter is not increasing")
	_, err = signCounter(restarted, env.PublicKey, 6, 4)
	require.NoError(t, err)
}

func TestSealedCounterAbsentStateIsLegacyStart(t *testing.T) {
	t.Parallel()
	evidence := testEvidence(t, 3)
	first, _, _ := newTestService(t, evidence)
	env := provisionTestKey(t, first)
	restarted, _, _ := newTestService(t, evidence)
	require.NoError(t, reloadWithState(restarted, env, nil))
	_, err := signCounter(restarted, env.PublicKey, 1, 1)
	require.NoError(t, err)
}

func TestReloadRefusesUnauthenticSealedState(t *testing.T) {
	t.Parallel()
	evidence := testEvidence(t, 3)
	first, _, _ := newTestService(t, evidence)
	env := provisionTestKey(t, first)
	signed, err := signCounter(first, env.PublicKey, 5, 1)
	require.NoError(t, err)
	require.NotEmpty(t, signed.SealedState)

	sealKey := testSealKey(t)
	foreignPub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	foreignPool, err := sealCounterState(sealKey, foreignPub, env.KMSKeyID, 5)
	require.NoError(t, err)
	foreignKMS, err := sealCounterState(sealKey, env.PublicKey, testForeignKMSKey, 5)
	require.NoError(t, err)
	tampered := bytes.Clone(signed.SealedState)
	tampered[len(tampered)-1] ^= 1
	truncated := signed.SealedState[:8]
	oversized := bytes.Repeat([]byte{1}, maxSealedStateSize+1)

	for name, state := range map[string][]byte{
		"tampered":     tampered,
		"truncated":    truncated,
		"oversized":    oversized,
		"foreign pool": foreignPool,
		"foreign KMS":  foreignKMS,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			restarted, _, _ := newTestService(t, evidence)
			err := reloadWithState(restarted, env, state)
			require.ErrorIs(t, err, ErrCounterState)
			// a refused reload installs nothing
			_, err = signCounter(restarted, env.PublicKey, 1, 2)
			require.ErrorIs(t, err, ErrNotLoaded)
		})
	}
}

func TestReloadNeverLowersLoadedCounter(t *testing.T) {
	t.Parallel()
	evidence := testEvidence(t, 3)
	service, _, _ := newTestService(t, evidence)
	env := provisionTestKey(t, service)
	low, err := signCounter(service, env.PublicKey, 5, 1)
	require.NoError(t, err)
	_, err = signCounter(service, env.PublicKey, 7, 2)
	require.NoError(t, err)

	require.NoError(t, reloadWithState(service, env, low.SealedState))
	_, err = signCounter(service, env.PublicKey, 6, 3)
	require.ErrorContains(t, err, "issue counter is not increasing")
	_, err = signCounter(service, env.PublicKey, 8, 4)
	require.NoError(t, err)

	// a higher stored state does raise it
	high, err := sealCounterState(testSealKey(t), env.PublicKey, env.KMSKeyID, 20)
	require.NoError(t, err)
	require.NoError(t, reloadWithState(service, env, high))
	_, err = signCounter(service, env.PublicKey, 20, 5)
	require.ErrorContains(t, err, "issue counter is not increasing")
	_, err = signCounter(service, env.PublicKey, 21, 6)
	require.NoError(t, err)
}
