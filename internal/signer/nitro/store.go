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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

const maxEnvelopeSize = 64 << 10

type secretsAPI interface {
	GetSecretValue(
		context.Context,
		*secretsmanager.GetSecretValueInput,
		...func(*secretsmanager.Options),
	) (*secretsmanager.GetSecretValueOutput, error)
	PutSecretValue(
		context.Context,
		*secretsmanager.PutSecretValueInput,
		...func(*secretsmanager.Options),
	) (*secretsmanager.PutSecretValueOutput, error)
	DescribeSecret(
		context.Context,
		*secretsmanager.DescribeSecretInput,
		...func(*secretsmanager.Options),
	) (*secretsmanager.DescribeSecretOutput, error)
}

// storedSecret is the secret's value: the envelope fields, plus the sealed
// counter state once one exists. A secret written before the state existed
// holds the envelope fields only and decodes with an empty state.
type storedSecret struct {
	Envelope
	SealedCounterState []byte `json:"sealed_counter_state,omitempty"`
}

// SecretStore persists exactly one wrapped envelope, and the enclave's sealed
// counter state, in one existing Secrets Manager secret. It never creates,
// deletes, or changes cloud resources.
//
// One secret keeps the envelope and its counter state in a single atomic
// write. It does not coordinate hosts: two hosts pointed at one secret
// overwrite each other's state, so the signer's shared watermark stays the
// cross-replica authority.
type SecretStore struct {
	client   secretsAPI
	secretID string
	// mu guards env, the envelope SaveSealedState writes back beside the
	// state; the last one loaded or saved.
	mu  sync.Mutex
	env *Envelope
}

// NewSecretStore constructs a wrapped-envelope store.
func NewSecretStore(client secretsAPI, secretID string) (*SecretStore, error) {
	if client == nil || secretID == "" {
		return nil, errors.New(
			"secrets manager client and secret ID are required",
		)
	}
	return &SecretStore{client: client, secretID: secretID}, nil
}

// Load reads and strictly validates the wrapped envelope.
func (s *SecretStore) Load(ctx context.Context) (Envelope, error) {
	env, _, err := s.LoadSealed(ctx)
	return env, err
}

// LoadSealed reads the wrapped envelope and the sealed counter state stored
// with it. The state is empty for a secret that holds only an envelope.
func (s *SecretStore) LoadSealed(
	ctx context.Context,
) (Envelope, []byte, error) {
	stored, err := s.load(ctx)
	if err != nil {
		return Envelope{}, nil, err
	}
	s.remember(stored.Envelope)
	return stored.Envelope, stored.SealedCounterState, nil
}

func (s *SecretStore) remember(env Envelope) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cloned := cloneEnvelope(env)
	s.env = &cloned
}

func (s *SecretStore) load(ctx context.Context) (storedSecret, error) {
	result, err := s.client.GetSecretValue(
		ctx,
		&secretsmanager.GetSecretValueInput{SecretId: aws.String(s.secretID)},
	)
	if err != nil {
		var missing *types.ResourceNotFoundException
		if errors.As(err, &missing) {
			return storedSecret{}, s.classifyMissingValue(ctx)
		}
		return storedSecret{}, fmt.Errorf("read wrapped key: %w", err)
	}
	var data []byte
	switch {
	case len(result.SecretBinary) > 0:
		data = result.SecretBinary
	case result.SecretString != nil:
		data = []byte(*result.SecretString)
	default:
		return storedSecret{}, ErrNoEnvelope
	}
	if len(data) == 0 {
		return storedSecret{}, ErrNoEnvelope
	}
	if len(data) > maxEnvelopeSize {
		return storedSecret{}, fmt.Errorf(
			"%w: secret exceeds %d bytes",
			ErrEnvelope,
			maxEnvelopeSize,
		)
	}
	var stored storedSecret
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&stored); err != nil {
		return storedSecret{}, fmt.Errorf("%w: %w", ErrEnvelope, err)
	}
	if err := dec.Decode(&json.RawMessage{}); !errors.Is(err, io.EOF) {
		return storedSecret{}, fmt.Errorf("%w: trailing secret data", ErrEnvelope)
	}
	if err := validateEnvelope(stored.Envelope); err != nil {
		return storedSecret{}, err
	}
	if len(stored.SealedCounterState) > maxSealedStateSize {
		return storedSecret{}, fmt.Errorf(
			"%w: stored state exceeds %d bytes",
			ErrCounterState,
			maxSealedStateSize,
		)
	}
	return stored, nil
}

// classifyMissingValue separates a secret that has no AWSCURRENT value yet,
// which GetSecretValue also reports as ResourceNotFoundException, from a
// secret that does not exist.
func (s *SecretStore) classifyMissingValue(ctx context.Context) error {
	described, err := s.client.DescribeSecret(
		ctx,
		&secretsmanager.DescribeSecretInput{SecretId: aws.String(s.secretID)},
	)
	if err != nil {
		var missing *types.ResourceNotFoundException
		if errors.As(err, &missing) {
			return fmt.Errorf("%w: secret does not exist", ErrEnvelope)
		}
		return fmt.Errorf("describe wrapped key secret: %w", err)
	}
	for _, stages := range described.VersionIdsToStages {
		if slices.Contains(stages, "AWSCURRENT") {
			return fmt.Errorf(
				"%w: current secret value is unreadable",
				ErrEnvelope,
			)
		}
	}
	return ErrNoEnvelope
}

// Save writes a validated wrapped envelope as a new value of an existing
// secret. Secrets Manager encryption is additional protection; the stored
// value already contains only KMS/AES ciphertext and public metadata.
func (s *SecretStore) Save(ctx context.Context, env Envelope) error {
	if err := validateEnvelope(env); err != nil {
		return err
	}
	return s.put(ctx, storedSecret{Envelope: env})
}

// SaveSealedState durably replaces the sealed counter state, keeping the
// envelope last loaded or saved. It needs one of those first, so the write
// can never drop the wrapped key.
func (s *SecretStore) SaveSealedState(ctx context.Context, state []byte) error {
	if len(state) == 0 || len(state) > maxSealedStateSize {
		return fmt.Errorf(
			"%w: state must be 1 to %d bytes",
			ErrCounterState,
			maxSealedStateSize,
		)
	}
	s.mu.Lock()
	var env Envelope
	known := s.env != nil
	if known {
		env = cloneEnvelope(*s.env)
	}
	s.mu.Unlock()
	if !known {
		return errors.New("no wrapped envelope loaded to store state beside")
	}
	return s.put(ctx, storedSecret{
		Envelope:           env,
		SealedCounterState: bytes.Clone(state),
	})
}

func (s *SecretStore) put(ctx context.Context, stored storedSecret) error {
	data, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	if len(data) > maxEnvelopeSize {
		return fmt.Errorf(
			"%w: envelope exceeds %d bytes",
			ErrEnvelope,
			maxEnvelopeSize,
		)
	}
	_, err = s.client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(s.secretID),
		SecretBinary: data,
	})
	if err != nil {
		return fmt.Errorf("write wrapped key: %w", err)
	}
	s.remember(stored.Envelope)
	return nil
}
