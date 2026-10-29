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
	"encoding/json"
	"errors"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

const testKMSKey = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000001"

var testCredentials = Credentials{AccessKeyID: "ASIATEST", SecretAccessKey: "secret", SessionToken: "session"}

func testEvidence(t *testing.T, measurement byte) []byte {
	t.Helper()
	pcr := bytes.Repeat([]byte{measurement}, nitroPCRSize)
	payload, err := cbor.Marshal(attestationPayload{PCRs: map[uint][]byte{0: pcr}})
	require.NoError(t, err)
	evidence, err := cbor.Marshal(sign1Document{Payload: payload, Signature: []byte{1}})
	require.NoError(t, err)
	return evidence
}

type fakeRecipient struct {
	evidence []byte
	attested [][]byte
}

func (r *fakeRecipient) KMSAttestation() ([]byte, error) { return bytes.Clone(r.evidence), nil }
func (r *fakeRecipient) DecryptKMSRecipient(value []byte) ([]byte, error) {
	return bytes.Clone(value), nil
}

func (r *fakeRecipient) Attest(value []byte) ([]byte, error) {
	r.attested = append(r.attested, bytes.Clone(value))
	return bytes.Clone(r.evidence), nil
}

type fakeKMS struct {
	dataKey          []byte
	expectedEvidence []byte
	calls            int
}

func (k *fakeKMS) check(recipient []byte) error {
	k.calls++
	if !bytes.Equal(recipient, k.expectedEvidence) {
		return errors.New("AccessDeniedException: recipient measurement mismatch")
	}
	return nil
}

func (k *fakeKMS) GenerateDataKey(_ context.Context, _ string, recipient []byte) ([]byte, []byte, error) {
	if err := k.check(recipient); err != nil {
		return nil, nil, err
	}
	return []byte("kms-ciphertext"), bytes.Clone(k.dataKey), nil
}

func (k *fakeKMS) Decrypt(_ context.Context, _ string, ciphertext, recipient []byte) ([]byte, error) {
	if !bytes.Equal(ciphertext, []byte("kms-ciphertext")) {
		return nil, errors.New("unknown KMS ciphertext")
	}
	if err := k.check(recipient); err != nil {
		return nil, err
	}
	return bytes.Clone(k.dataKey), nil
}

func newTestService(t *testing.T, evidence []byte) (*Service, *fakeKMS, *fakeRecipient) {
	t.Helper()
	recipient := &fakeRecipient{evidence: evidence}
	kms := &fakeKMS{dataKey: bytes.Repeat([]byte{0x5a}, dataKeySize), expectedEvidence: evidence}
	service, err := NewService(recipient, func(region string, credentials Credentials) (KMS, error) {
		require.Equal(t, "us-east-1", region)
		require.Equal(t, testCredentials, credentials)
		return kms, nil
	})
	require.NoError(t, err)
	return service, kms, recipient
}

func provisionTestKey(t *testing.T, service *Service) Envelope {
	t.Helper()
	response, err := service.Provision(context.Background(), &ProvisionRequest{
		Version: Protocol, Region: "us-east-1", Credentials: testCredentials,
		KMSKeyID: testKMSKey, Role: backend.KeyTypePool,
	})
	require.NoError(t, err)
	require.Equal(t, Protocol, response.Version)
	return response.Envelope
}

func TestProvisionStoresOnlyWrappedMaterial(t *testing.T) {
	service, _, _ := newTestService(t, testEvidence(t, 1))
	env := provisionTestKey(t, service)
	require.NoError(t, validateEnvelope(env))
	seed, err := openSeed(bytes.Repeat([]byte{0x5a}, dataKeySize), env)
	require.NoError(t, err)
	defer clear(seed)
	encoded, err := json.Marshal(env)
	require.NoError(t, err)
	require.NotContains(t, encoded, seed)
	require.NotContains(t, encoded, bytes.Repeat([]byte{0x5a}, dataKeySize))
}

func TestProvisionRejectsKMSAliasBeforeKMS(t *testing.T) {
	service, kms, _ := newTestService(t, testEvidence(t, 1))
	_, err := service.Provision(context.Background(), &ProvisionRequest{
		Version: Protocol, Region: "us-east-1", Credentials: testCredentials,
		KMSKeyID: "arn:aws:kms:us-east-1:123456789012:alias/pool-cold", Role: backend.KeyTypePool,
	})
	require.ErrorIs(t, err, ErrProtocol)
	require.Zero(t, kms.calls)
}

func TestProvisionRejectsDebugAttestationBeforeKMS(t *testing.T) {
	service, kms, _ := newTestService(t, testEvidence(t, 0))
	_, err := service.Provision(context.Background(), &ProvisionRequest{
		Version: Protocol, Region: "us-east-1", Credentials: testCredentials,
		KMSKeyID: testKMSKey, Role: backend.KeyTypePool,
	})
	require.ErrorIs(t, err, ErrMeasurement)
	require.Zero(t, kms.calls)
}

func TestProvisionFailsClosedOnKMSMeasurementDenial(t *testing.T) {
	evidence := testEvidence(t, 1)
	service, kms, _ := newTestService(t, evidence)
	kms.expectedEvidence = testEvidence(t, 2)
	_, err := service.Provision(context.Background(), &ProvisionRequest{
		Version: Protocol, Region: "us-east-1", Credentials: testCredentials,
		KMSKeyID: testKMSKey, Role: backend.KeyTypePool,
	})
	require.ErrorContains(t, err, "measurement mismatch")
	_, err = service.Inventory(context.Background(), &InventoryRequest{Version: Protocol, Nonce: make([]byte, 32)})
	require.ErrorIs(t, err, ErrNotLoaded)
}

func TestReloadAndCanonicalOpCertSigning(t *testing.T) {
	evidence := testEvidence(t, 3)
	service, _, _ := newTestService(t, evidence)
	env := provisionTestKey(t, service)

	restarted, _, recipient := newTestService(t, evidence)
	response, err := restarted.Reload(context.Background(), &ReloadRequest{
		Version: Protocol, Region: "us-east-1", Credentials: testCredentials, Envelope: env,
	})
	require.NoError(t, err)
	require.Equal(t, env.PublicKey, response.PublicKey)

	nonce := bytes.Repeat([]byte{7}, requestNonceSize)
	payload := make([]byte, 48)
	copy(payload[:32], bytes.Repeat([]byte{4}, 32))
	binary.BigEndian.PutUint64(payload[32:40], 5)
	binary.BigEndian.PutUint64(payload[40:48], 120)
	request := &backend.AttestedRequest{
		Version: backend.AttestedProtocol, Purpose: backend.PurposeOpCert,
		KeyHash: backend.HashPublicKey(env.PublicKey).String(), Role: backend.KeyTypePool,
		Nonce: nonce, Payload: payload,
	}
	signed, err := restarted.Sign(context.Background(), request)
	require.NoError(t, err)
	require.True(t, ed25519.Verify(env.PublicKey, payload, signed.Signature))

	_, err = restarted.Sign(context.Background(), request)
	require.ErrorContains(t, err, "nonce replay")
	request.Nonce = bytes.Repeat([]byte{8}, requestNonceSize)
	_, err = restarted.Sign(context.Background(), request)
	require.ErrorContains(t, err, "issue counter is not increasing")

	inv, err := restarted.Inventory(context.Background(), &InventoryRequest{Version: Protocol, Nonce: bytes.Repeat([]byte{9}, 32)})
	require.NoError(t, err)
	require.Equal(t, backend.InventoryBinding(bytes.Repeat([]byte{9}, 32), inv.Keys), recipient.attested[0])
}

func TestMalformedLifecycleRequestsPreserveLoadedState(t *testing.T) {
	service, _, _ := newTestService(t, testEvidence(t, 4))
	env := provisionTestKey(t, service)
	payload := make([]byte, 48)
	binary.BigEndian.PutUint64(payload[32:40], 1)
	request := &backend.AttestedRequest{
		Version: backend.AttestedProtocol, Purpose: backend.PurposeOpCert,
		KeyHash: backend.HashPublicKey(env.PublicKey).String(), Role: backend.KeyTypePool,
		Nonce: bytes.Repeat([]byte{1}, requestNonceSize), Payload: payload,
	}
	_, err := service.Sign(context.Background(), request)
	require.NoError(t, err)

	malformedProvision := ProvisionRequest{Version: "invalid"}
	_, err = service.Provision(context.Background(), &malformedProvision)
	require.ErrorIs(t, err, ErrProtocol)

	env.Ciphertext[0] ^= 0xff
	_, err = service.Reload(context.Background(), &ReloadRequest{
		Version: Protocol, Region: "us-east-1", Credentials: testCredentials, Envelope: env,
	})
	require.ErrorIs(t, err, ErrEnvelope)

	inventory, err := service.Inventory(context.Background(), &InventoryRequest{Version: Protocol, Nonce: make([]byte, 32)})
	require.NoError(t, err)
	require.Equal(t, env.PublicKey, inventory.Keys[0].PublicKey)
	_, err = service.Sign(context.Background(), request)
	require.ErrorContains(t, err, "nonce replay")
	request.Nonce = bytes.Repeat([]byte{2}, requestNonceSize)
	_, err = service.Sign(context.Background(), request)
	require.ErrorContains(t, err, "issue counter is not increasing")

	env.Ciphertext[0] ^= 0xff
	_, err = service.Reload(context.Background(), &ReloadRequest{
		Version: Protocol, Region: "us-east-1", Credentials: testCredentials, Envelope: env,
	})
	require.NoError(t, err)
	request.Nonce = bytes.Repeat([]byte{1}, requestNonceSize)
	_, err = service.Sign(context.Background(), request)
	require.ErrorContains(t, err, "nonce replay")
	request.Nonce = bytes.Repeat([]byte{3}, requestNonceSize)
	_, err = service.Sign(context.Background(), request)
	require.ErrorContains(t, err, "issue counter is not increasing")
}

func TestReloadRejectsOversizedEnvelopeBeforeKMS(t *testing.T) {
	for name, mutate := range map[string]func(*Envelope){
		"encrypted data key": func(env *Envelope) {
			env.EncryptedDataKey = make([]byte, maxEnvelopeSize+1)
		},
		"private-key ciphertext": func(env *Envelope) {
			env.Ciphertext = make([]byte, maxEnvelopeSize+1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			service, kms, _ := newTestService(t, testEvidence(t, 4))
			env := provisionTestKey(t, service)
			kms.calls = 0
			mutate(&env)

			_, err := service.Reload(context.Background(), &ReloadRequest{
				Version: Protocol, Region: "us-east-1", Credentials: testCredentials, Envelope: env,
			})
			require.ErrorIs(t, err, ErrEnvelope)
			require.Zero(t, kms.calls)
		})
	}
}

func TestServiceRejectsMalformedSignRequests(t *testing.T) {
	service, _, _ := newTestService(t, testEvidence(t, 5))
	env := provisionTestKey(t, service)
	valid := backend.AttestedRequest{
		Version: backend.AttestedProtocol, Purpose: backend.PurposeOpCert,
		KeyHash: backend.HashPublicKey(env.PublicKey).String(), Role: backend.KeyTypePool,
		Nonce: make([]byte, 32), Payload: make([]byte, 48),
	}
	for name, mutate := range map[string]func(*backend.AttestedRequest){
		"version": func(r *backend.AttestedRequest) { r.Version = "other" },
		"purpose": func(r *backend.AttestedRequest) { r.Purpose = backend.PurposeTxHash },
		"role":    func(r *backend.AttestedRequest) { r.Role = backend.KeyTypePayment },
		"payload": func(r *backend.AttestedRequest) { r.Payload = r.Payload[:47] },
		"nonce":   func(r *backend.AttestedRequest) { r.Nonce = r.Nonce[:31] },
		"hash": func(r *backend.AttestedRequest) {
			r.KeyHash = "00000000000000000000000000000000000000000000000000000000"
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			request.Payload = bytes.Clone(valid.Payload)
			request.Nonce = bytes.Clone(valid.Nonce)
			mutate(&request)
			_, err := service.Sign(context.Background(), &request)
			require.Error(t, err)
		})
	}
}
