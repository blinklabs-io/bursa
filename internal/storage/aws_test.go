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
	"errors"
	"sort"
	"testing"

	"filippo.io/age"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/stretchr/testify/require"
)

// fakeSecrets is an in-memory Secrets Manager. putErr, when set, is returned
// by PutSecretValue in place of the usual not-found behaviour.
type fakeSecrets struct {
	secrets map[string][]byte
	putErr  error
	creates int
	deleted []string
	// raceCreate makes CreateSecret behave as if another writer created the
	// secret first.
	raceCreate bool
	// getHook, when set, runs before GetSecretValue and may fail it.
	getHook func(ctx context.Context) error
}

func newFakeSecrets() *fakeSecrets { return &fakeSecrets{secrets: map[string][]byte{}} }

func (f *fakeSecrets) GetSecretValue(
	ctx context.Context,
	in *secretsmanager.GetSecretValueInput,
	_ ...func(*secretsmanager.Options),
) (*secretsmanager.GetSecretValueOutput, error) {
	if f.getHook != nil {
		if err := f.getHook(ctx); err != nil {
			return nil, err
		}
	}
	v, ok := f.secrets[*in.SecretId]
	if !ok {
		return nil, &smtypes.ResourceNotFoundException{}
	}
	return &secretsmanager.GetSecretValueOutput{SecretBinary: v}, nil
}

func (f *fakeSecrets) CreateSecret(
	_ context.Context,
	in *secretsmanager.CreateSecretInput,
	_ ...func(*secretsmanager.Options),
) (*secretsmanager.CreateSecretOutput, error) {
	f.creates++
	if f.raceCreate {
		f.secrets[*in.Name] = []byte("concurrent writer")
		return nil, &smtypes.ResourceExistsException{}
	}
	f.secrets[*in.Name] = in.SecretBinary
	return &secretsmanager.CreateSecretOutput{}, nil
}

func (f *fakeSecrets) PutSecretValue(
	_ context.Context,
	in *secretsmanager.PutSecretValueInput,
	_ ...func(*secretsmanager.Options),
) (*secretsmanager.PutSecretValueOutput, error) {
	if f.putErr != nil {
		return nil, f.putErr
	}
	if _, ok := f.secrets[*in.SecretId]; !ok {
		return nil, &smtypes.ResourceNotFoundException{}
	}
	f.secrets[*in.SecretId] = in.SecretBinary
	return &secretsmanager.PutSecretValueOutput{}, nil
}

func (f *fakeSecrets) DeleteSecret(
	_ context.Context,
	in *secretsmanager.DeleteSecretInput,
	_ ...func(*secretsmanager.Options),
) (*secretsmanager.DeleteSecretOutput, error) {
	delete(f.secrets, *in.SecretId)
	f.deleted = append(f.deleted, *in.SecretId)
	return &secretsmanager.DeleteSecretOutput{}, nil
}

func (f *fakeSecrets) ListSecrets(
	_ context.Context,
	_ *secretsmanager.ListSecretsInput,
	_ ...func(*secretsmanager.Options),
) (*secretsmanager.ListSecretsOutput, error) {
	// Return every secret and ignore the filter, so the store's own prefix
	// check decides what is listed.
	out := &secretsmanager.ListSecretsOutput{}
	names := []string{}
	for name := range f.secrets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		out.SecretList = append(out.SecretList, smtypes.SecretListEntry{Name: &name})
	}
	return out, nil
}

// useAgeRecipient points SOPS at a fresh age key for the test. The process
// config and SOPS_AGE_KEY are global, so callers cannot run in parallel.
func useAgeRecipient(t *testing.T) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	cfg := config.GetConfig()
	previous := cfg.Age.Recipients
	cfg.Age.Recipients = id.Recipient().String()
	t.Cleanup(func() { cfg.Age.Recipients = previous })
	t.Setenv("SOPS_AGE_KEY", id.String())
}

func TestAWSStoreSaveLoadListDelete(t *testing.T) {
	// Not t.Parallel: see useAgeRecipient.
	useAgeRecipient(t)
	fake := newFakeSecrets()
	store := &AWSStore{client: fake, prefix: "pre-"}
	ctx := context.Background()

	w, err := store.CreateWallet("w1")
	require.NoError(t, err)
	w.PutItem("mnemonic", "secret seed phrase")
	require.NoError(t, w.Save(ctx))
	require.Equal(t, 1, fake.creates)
	require.NotContains(t, string(fake.secrets["pre-w1"]), "secret seed phrase")

	// A second save writes a new version rather than creating again.
	w.PutItem("extra", "v")
	require.NoError(t, w.Save(ctx))
	require.Equal(t, 1, fake.creates)

	got, err := store.GetWallet(ctx, "w1")
	require.NoError(t, err)
	item, err := got.GetItem("mnemonic")
	require.NoError(t, err)
	require.Equal(t, "secret seed phrase", item)
	_, err = got.GetItem("extra")
	require.NoError(t, err)

	fake.secrets["other-w2"] = []byte("not ours")
	// Unprefixed, but its name maps onto an existing wallet if stripped.
	fake.secrets["w1"] = []byte("not ours")
	wallets, err := store.ListWallets(ctx)
	require.NoError(t, err)
	require.Len(t, wallets, 1)
	require.Equal(t, "w1", wallets[0].Name())

	require.NoError(t, store.DeleteWallet(ctx, "w1"))
	require.Equal(t, []string{"pre-w1"}, fake.deleted)
	_, err = store.GetWallet(ctx, "w1")
	require.Error(t, err)
}

func TestAWSStoreSavePropagatesBackendError(t *testing.T) {
	// Not t.Parallel: see useAgeRecipient.
	useAgeRecipient(t)
	denied := errors.New("access denied")
	fake := newFakeSecrets()
	fake.putErr = denied
	store := &AWSStore{client: fake, prefix: "pre-"}

	w, err := store.CreateWallet("w1")
	require.NoError(t, err)
	w.PutItem("k", "v")
	err = w.Save(context.Background())
	require.ErrorIs(t, err, denied)
	require.Zero(t, fake.creates)
}

func TestAWSStoreSaveWithoutMasterKeyWritesNothing(t *testing.T) {
	// Not t.Parallel: it edits the process-global config.
	cfg := config.GetConfig()
	saved := *cfg
	cfg.Google.ResourceId, cfg.Aws.KMSKeyARN, cfg.Age.Recipients = "", "", ""
	t.Cleanup(func() { *cfg = saved })

	fake := newFakeSecrets()
	w, err := (&AWSStore{client: fake, prefix: "pre-"}).CreateWallet("w1")
	require.NoError(t, err)
	w.PutItem("k", "v")
	require.Error(t, w.Save(context.Background()))
	require.Zero(t, fake.creates)
	require.Empty(t, fake.secrets)
}

func TestNewStoreAWSBackendRequiresPrefix(t *testing.T) {
	store, err := NewStore(&config.Config{
		Storage: config.StorageConfig{Backend: "aws"},
	})
	require.Nil(t, store)
	require.ErrorContains(t, err, "aws secret prefix is required")
}

func TestNewStoreRejectsUnknownBackendWithGCPConfigured(t *testing.T) {
	store, err := NewStore(&config.Config{
		Storage: config.StorageConfig{Backend: "awss"},
		Google:  config.GoogleConfig{Project: "project", ResourceId: "resource"},
	})
	require.Nil(t, store)
	require.ErrorContains(t, err, `unsupported storage backend "awss"`)
}

func TestNewStoreUsesGCPForLegacyConfiguration(t *testing.T) {
	store, err := NewStore(&config.Config{
		Google: config.GoogleConfig{Project: "project", ResourceId: "resource"},
	})
	require.NoError(t, err)
	require.IsType(t, (*GCPStore)(nil), store)
}

func TestNewStoreAWSBackend(t *testing.T) {
	t.Parallel()
	store, err := NewStore(&config.Config{
		Storage: config.StorageConfig{Backend: "aws"},
		Aws:     config.AwsConfig{Prefix: "pre-"},
	})
	require.NoError(t, err)
	aws, ok := store.(*AWSStore)
	require.True(t, ok, "got %T", store)
	require.Equal(t, "pre-", aws.prefix)
}

func TestAWSStoreSaveOverwritesAfterConcurrentCreate(t *testing.T) {
	// Not t.Parallel: see useAgeRecipient.
	useAgeRecipient(t)
	fake := newFakeSecrets()
	fake.raceCreate = true
	store := &AWSStore{client: fake, prefix: "pre-"}

	w, err := store.CreateWallet("w1")
	require.NoError(t, err)
	w.PutItem("k", "v")
	require.NoError(t, w.Save(context.Background()))
	require.NotEqual(t, "concurrent writer", string(fake.secrets["pre-w1"]))

	got, err := store.GetWallet(context.Background(), "w1")
	require.NoError(t, err)
	item, err := got.GetItem("k")
	require.NoError(t, err)
	require.Equal(t, "v", item)
}

func TestAWSStoreListWalletNamesDoesNotLoadWalletContents(t *testing.T) {
	fake := newFakeSecrets()
	fake.secrets["pre-one"] = []byte("unused")
	fake.secrets["other"] = []byte("unused")
	fake.getHook = func(context.Context) error {
		return errors.New("wallet contents were loaded")
	}

	names, err := (&AWSStore{client: fake, prefix: "pre-"}).ListWalletNames(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"one"}, names)
}

func TestAWSStoreListWalletsReportsCancellation(t *testing.T) {
	// Not t.Parallel: see useAgeRecipient.
	useAgeRecipient(t)
	fake := newFakeSecrets()
	store := &AWSStore{client: fake, prefix: "pre-"}
	for _, name := range []string{"w1", "w2"} {
		w, err := store.CreateWallet(name)
		require.NoError(t, err)
		w.PutItem("k", "v")
		require.NoError(t, w.Save(context.Background()))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake.getHook = func(ctx context.Context) error {
		cancel()
		return ctx.Err()
	}
	wallets, err := store.ListWallets(ctx)
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, wallets)
}
