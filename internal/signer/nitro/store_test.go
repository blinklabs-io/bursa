// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package nitro

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/stretchr/testify/require"
)

type fakeSecrets struct {
	value       []byte
	getErr      error
	describe    *secretsmanager.DescribeSecretOutput
	describeErr error
}

func (s *fakeSecrets) GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return &secretsmanager.GetSecretValueOutput{SecretBinary: s.value}, nil
}

func (s *fakeSecrets) DescribeSecret(context.Context, *secretsmanager.DescribeSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error) {
	if s.describeErr != nil {
		return nil, s.describeErr
	}
	return s.describe, nil
}

func (s *fakeSecrets) PutSecretValue(_ context.Context, input *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	s.value = append([]byte(nil), input.SecretBinary...)
	return &secretsmanager.PutSecretValueOutput{}, nil
}

func validTestEnvelope() Envelope {
	return Envelope{
		Version: EnvelopeVersion, Role: backend.KeyTypePool, KMSKeyID: testKMSKey,
		PublicKey: make([]byte, 32), EncryptedDataKey: []byte("kms"),
		Ciphertext: []byte("ciphertext"), Nonce: make([]byte, 12),
	}
}

func TestSecretStoreRoundTrip(t *testing.T) {
	client := &fakeSecrets{}
	store, err := NewSecretStore(client, "pool-cold")
	require.NoError(t, err)
	env := validTestEnvelope()
	require.NoError(t, store.Save(context.Background(), env))
	loaded, err := store.Load(context.Background())
	require.NoError(t, err)
	require.Equal(t, env, loaded)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(client.value, &fields))
	require.NotContains(t, fields, "private_key")
	require.NotContains(t, fields, "data_key")
}

func TestSecretStoreRejectsUnknownAndTrailingFields(t *testing.T) {
	env := validTestEnvelope()
	encoded, err := json.Marshal(env)
	require.NoError(t, err)
	client := &fakeSecrets{}
	store, err := NewSecretStore(client, "pool-cold")
	require.NoError(t, err)
	for name, value := range map[string][]byte{
		"unknown":  append(encoded[:len(encoded)-1], []byte(`,"private_key":"secret"}`)...),
		"trailing": append(encoded, []byte(`{}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			client.value = value
			_, err := store.Load(context.Background())
			require.ErrorIs(t, err, ErrEnvelope)
		})
	}
}

func TestSecretStoreLoadDistinguishesVersionlessSecret(t *testing.T) {
	notFound := &types.ResourceNotFoundException{Message: aws.String("not found")}
	for name, tc := range map[string]struct {
		client *fakeSecrets
		want   error
	}{
		"versionless secret": {
			client: &fakeSecrets{getErr: notFound, describe: &secretsmanager.DescribeSecretOutput{}},
			want:   ErrNoEnvelope,
		},
		"missing secret": {
			client: &fakeSecrets{getErr: notFound, describeErr: notFound},
			want:   ErrEnvelope,
		},
		"current version unreadable": {
			client: &fakeSecrets{getErr: notFound, describe: &secretsmanager.DescribeSecretOutput{
				VersionIdsToStages: map[string][]string{"v1": {"AWSCURRENT"}},
			}},
			want: ErrEnvelope,
		},
	} {
		t.Run(name, func(t *testing.T) {
			store, err := NewSecretStore(tc.client, "pool-cold")
			require.NoError(t, err)
			_, err = store.Load(context.Background())
			require.ErrorIs(t, err, tc.want)
		})
	}
}
