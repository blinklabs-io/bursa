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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

const maxEnvelopeSize = 64 << 10

type secretsAPI interface {
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	PutSecretValue(context.Context, *secretsmanager.PutSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
	DescribeSecret(context.Context, *secretsmanager.DescribeSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error)
}

// SecretStore persists exactly one wrapped envelope in an existing Secrets
// Manager secret. It never creates, deletes, or changes cloud resources.
type SecretStore struct {
	client   secretsAPI
	secretID string
}

// NewSecretStore constructs a wrapped-envelope store.
func NewSecretStore(client secretsAPI, secretID string) (*SecretStore, error) {
	if client == nil || secretID == "" {
		return nil, errors.New("secrets manager client and secret ID are required")
	}
	return &SecretStore{client: client, secretID: secretID}, nil
}

// Load reads and strictly validates the wrapped envelope.
func (s *SecretStore) Load(ctx context.Context) (Envelope, error) {
	result, err := s.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(s.secretID)})
	if err != nil {
		var missing *types.ResourceNotFoundException
		if errors.As(err, &missing) {
			return Envelope{}, s.classifyMissingValue(ctx)
		}
		return Envelope{}, fmt.Errorf("read wrapped key: %w", err)
	}
	var data []byte
	switch {
	case len(result.SecretBinary) > 0:
		data = result.SecretBinary
	case result.SecretString != nil:
		data = []byte(*result.SecretString)
	default:
		return Envelope{}, ErrNoEnvelope
	}
	if len(data) == 0 {
		return Envelope{}, ErrNoEnvelope
	}
	if len(data) > maxEnvelopeSize {
		return Envelope{}, fmt.Errorf("%w: secret exceeds %d bytes", ErrEnvelope, maxEnvelopeSize)
	}
	var env Envelope
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return Envelope{}, fmt.Errorf("%w: %w", ErrEnvelope, err)
	}
	if err := dec.Decode(&json.RawMessage{}); !errors.Is(err, io.EOF) {
		return Envelope{}, fmt.Errorf("%w: trailing secret data", ErrEnvelope)
	}
	if err := validateEnvelope(env); err != nil {
		return Envelope{}, err
	}
	return env, nil
}

// classifyMissingValue separates a secret that has no AWSCURRENT value yet,
// which GetSecretValue also reports as ResourceNotFoundException, from a
// secret that does not exist.
func (s *SecretStore) classifyMissingValue(ctx context.Context) error {
	described, err := s.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(s.secretID)})
	if err != nil {
		var missing *types.ResourceNotFoundException
		if errors.As(err, &missing) {
			return fmt.Errorf("%w: secret does not exist", ErrEnvelope)
		}
		return fmt.Errorf("describe wrapped key secret: %w", err)
	}
	for _, stages := range described.VersionIdsToStages {
		if slices.Contains(stages, "AWSCURRENT") {
			return fmt.Errorf("%w: current secret value is unreadable", ErrEnvelope)
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
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	if len(data) > maxEnvelopeSize {
		return fmt.Errorf("%w: envelope exceeds %d bytes", ErrEnvelope, maxEnvelopeSize)
	}
	_, err = s.client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(s.secretID),
		SecretBinary: data,
	})
	if err != nil {
		return fmt.Errorf("write wrapped key: %w", err)
	}
	return nil
}
