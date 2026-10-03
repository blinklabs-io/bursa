// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/blinklabs-io/bursa/gcp"
	"github.com/blinklabs-io/bursa/internal/logging"
	"github.com/blinklabs-io/bursa/internal/sops"
)

// secretsAPI is the part of the Secrets Manager client AWSStore uses.
type secretsAPI interface {
	secretsmanager.ListSecretsAPIClient
	GetSecretValue(
		ctx context.Context,
		in *secretsmanager.GetSecretValueInput,
		opts ...func(*secretsmanager.Options),
	) (*secretsmanager.GetSecretValueOutput, error)
	CreateSecret(
		ctx context.Context,
		in *secretsmanager.CreateSecretInput,
		opts ...func(*secretsmanager.Options),
	) (*secretsmanager.CreateSecretOutput, error)
	PutSecretValue(
		ctx context.Context,
		in *secretsmanager.PutSecretValueInput,
		opts ...func(*secretsmanager.Options),
	) (*secretsmanager.PutSecretValueOutput, error)
	DeleteSecret(
		ctx context.Context,
		in *secretsmanager.DeleteSecretInput,
		opts ...func(*secretsmanager.Options),
	) (*secretsmanager.DeleteSecretOutput, error)
}

// AWSStore implements Store on AWS Secrets Manager. Each wallet is one secret
// named prefix+wallet whose value is the SOPS-encrypted item map.
type AWSStore struct {
	client secretsAPI
	prefix string
}

// NewAWSStore builds an AWSStore using the default AWS credential and region
// resolution chain.
func NewAWSStore(ctx context.Context, prefix string) (*AWSStore, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load aws configuration: %w", err)
	}
	return &AWSStore{client: secretsmanager.NewFromConfig(awsCfg), prefix: prefix}, nil
}

func (s *AWSStore) secretName(name string) string { return s.prefix + name }

func (s *AWSStore) GetWallet(ctx context.Context, name string) (Wallet, error) {
	w := s.newWallet(name)
	if err := w.Load(ctx); err != nil {
		return nil, err
	}
	return w, nil
}

func (s *AWSStore) ListWallets(ctx context.Context) ([]Wallet, error) {
	pages := secretsmanager.NewListSecretsPaginator(s.client, &secretsmanager.ListSecretsInput{
		Filters: []smtypes.Filter{{
			Key:    smtypes.FilterNameStringTypeName,
			Values: []string{s.prefix},
		}},
	})
	var wallets []Wallet
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list secrets: %w", err)
		}
		for _, entry := range page.SecretList {
			secretName := aws.ToString(entry.Name)
			if !strings.HasPrefix(secretName, s.prefix) {
				continue
			}
			name := strings.TrimPrefix(secretName, s.prefix)
			w, err := s.GetWallet(ctx, name)
			if err != nil {
				logging.GetLogger().
					Debug("skipping inaccessible wallet during list", "wallet", name, "error", err)
				continue
			}
			wallets = append(wallets, w)
		}
	}
	return wallets, nil
}

func (s *AWSStore) CreateWallet(name string) (Wallet, error) {
	return s.newWallet(name), nil
}

func (s *AWSStore) DeleteWallet(ctx context.Context, name string) error {
	return s.newWallet(name).Delete(ctx)
}

func (s *AWSStore) newWallet(name string) *awsWallet {
	return &awsWallet{Wallet: &gcpWalletAdapter{wallet: gcp.NewGoogleWallet(name)}, store: s}
}

// awsWallet reuses the in-memory item handling of the shared wallet adapter
// and replaces only the persistence calls.
type awsWallet struct {
	Wallet
	store *AWSStore
}

func (w *awsWallet) Load(ctx context.Context) error {
	out, err := w.store.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: new(w.store.secretName(w.Name())),
	})
	if err != nil {
		return fmt.Errorf("failed to get secret: %w", err)
	}
	payload := out.SecretBinary
	if payload == nil && out.SecretString != nil {
		payload = []byte(*out.SecretString)
	}
	plain, err := sops.Decrypt(payload)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %w", err)
	}
	items := map[string]string{}
	if err := json.Unmarshal(plain, &items); err != nil {
		return fmt.Errorf("failed to decode json: %w", err)
	}
	for k, v := range items {
		w.PutItem(k, v)
	}
	return nil
}

func (w *awsWallet) Save(ctx context.Context) error {
	data, err := json.Marshal(w.Items())
	if err != nil {
		return fmt.Errorf("failed to create payload: %w", err)
	}
	// Encrypt first so a missing or invalid key resource fails before any
	// remote state is created.
	enc, err := sops.Encrypt(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}
	id := w.store.secretName(w.Name())
	_, err = w.store.client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId:     &id,
		SecretBinary: enc,
	})
	var notFound *smtypes.ResourceNotFoundException
	if errors.As(err, &notFound) {
		_, err = w.store.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         &id,
			SecretBinary: enc,
		})
		if err != nil {
			return fmt.Errorf("failed to create secret: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to add secret version: %w", err)
	}
	return nil
}

func (w *awsWallet) Delete(ctx context.Context) error {
	_, err := w.store.client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{
		SecretId:                   new(w.store.secretName(w.Name())),
		ForceDeleteWithoutRecovery: new(true),
	})
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}
	return nil
}
