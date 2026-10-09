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

package sops

import (
	"testing"

	"filippo.io/age"
	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/getsops/sops/v3/gcpkms"
	"github.com/getsops/sops/v3/kms"
	"github.com/stretchr/testify/require"
)

func TestMasterKeysRejectsEmptyConfig(t *testing.T) {
	t.Parallel()
	keys, err := masterKeys(&config.Config{})
	require.ErrorIs(t, err, ErrNoMasterKey)
	require.Empty(t, keys)
}

func TestMasterKeysRejectsMalformedResources(t *testing.T) {
	t.Parallel()
	for name, cfg := range map[string]config.Config{
		"kms arn not an arn":    {Aws: config.AwsConfig{KMSKeyARN: "alias/foo"}},
		"kms arn wrong service": {Aws: config.AwsConfig{KMSKeyARN: "arn:aws:s3:::bucket"}},
		"age recipient":         {Age: config.AgeConfig{Recipients: "not-a-recipient"}},
		"age blank entry":       {Age: config.AgeConfig{Recipients: " , "}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := masterKeys(&cfg)
			require.Error(t, err)
			require.NotErrorIs(t, err, ErrNoMasterKey)
		})
	}
}

func TestMasterKeysCombinesConfiguredResources(t *testing.T) {
	t.Parallel()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	keys, err := masterKeys(&config.Config{
		Google: config.GoogleConfig{ResourceId: "projects/p/locations/l/keyRings/r/cryptoKeys/k"},
		Aws:    config.AwsConfig{KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/abcd"},
		Age:    config.AgeConfig{Recipients: id.Recipient().String()},
	})
	require.NoError(t, err)
	require.Len(t, keys, 3)
}

func TestEncryptDecryptWithAgeRecipient(t *testing.T) {
	// Not t.Parallel: Encrypt reads the process-global config and Decrypt
	// reads SOPS_AGE_KEY from the process environment.
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	cfg := config.GetConfig()
	previous := cfg.Age.Recipients
	cfg.Age.Recipients = id.Recipient().String()
	t.Cleanup(func() { cfg.Age.Recipients = previous })
	t.Setenv("SOPS_AGE_KEY", id.String())

	plain := []byte(`{"mnemonic":"seed words"}`)
	enc, err := Encrypt(plain)
	require.NoError(t, err)
	require.NotContains(t, string(enc), "seed words")
	require.Contains(t, string(enc), id.Recipient().String())

	dec, err := Decrypt(enc)
	require.NoError(t, err)
	require.JSONEq(t, string(plain), string(dec))
}

func TestEncryptWithoutMasterKeyFailsBeforeBuildingTree(t *testing.T) {
	// Not t.Parallel: Encrypt reads the process-global config.
	cfg := config.GetConfig()
	saved := *cfg
	cfg.Google.ResourceId = ""
	cfg.Aws.KMSKeyARN = ""
	cfg.Age.Recipients = ""
	t.Cleanup(func() { *cfg = saved })

	_, err := Encrypt([]byte(`{"a":"b"}`))
	require.ErrorIs(t, err, ErrNoMasterKey)
}

func TestMasterKeysRejectsMalformedGoogleResourceID(t *testing.T) {
	t.Parallel()
	for _, id := range []string{
		"projects/p/keyRings/r/cryptoKeys/k",
		"projects/p/locations/l/keyRings/r/cryptoKeys/k,",
	} {
		_, err := masterKeys(&config.Config{
			Google: config.GoogleConfig{ResourceId: id},
		})
		require.Error(t, err, id)
		require.NotErrorIs(t, err, ErrNoMasterKey)
	}
}

func TestMasterKeysTrimsEachEntry(t *testing.T) {
	t.Parallel()
	const (
		gcpID  = "projects/p/locations/l/keyRings/r/cryptoKeys/k"
		kmsArn = "arn:aws:kms:us-east-1:123456789012:key/abcd"
	)
	keys, err := masterKeys(&config.Config{
		Google: config.GoogleConfig{ResourceId: "\t" + gcpID + "\n"},
		Aws:    config.AwsConfig{KMSKeyARN: "\t" + kmsArn + "\n"},
	})
	require.NoError(t, err)
	require.Len(t, keys, 2)
	gk, ok := keys[0].(*gcpkms.MasterKey)
	require.True(t, ok, "got %T", keys[0])
	require.Equal(t, gcpID, gk.ResourceID)
	ak, ok := keys[1].(*kms.MasterKey)
	require.True(t, ok, "got %T", keys[1])
	require.Equal(t, kmsArn, ak.Arn)
}
