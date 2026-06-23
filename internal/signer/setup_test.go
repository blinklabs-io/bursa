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

package signer

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	sops "github.com/blinklabs-io/bursa/internal/sops"
)

func TestKeyTypeFromEnvelope(t *testing.T) {
	tests := []struct {
		envelopeType string
		want         backend.KeyType
	}{
		// Payment signing keys
		{"PaymentSigningKeyShelley_ed25519", backend.KeyTypePayment},
		{"PaymentExtendedSigningKeyShelley_ed25519_bip32", backend.KeyTypePayment},
		// Stake signing key (must NOT match StakePool prefix)
		{"StakeSigningKeyShelley_ed25519", backend.KeyTypeStake},
		// StakePool signing key (was previously shadowed by the Stake case)
		{"StakePoolSigningKeyShelley_ed25519", backend.KeyTypePool},
		// Governance / committee keys
		{"DRepSigningKeyShelley_ed25519", backend.KeyTypeDRep},
		{"CommitteeHotSigningKeyShelley_ed25519", backend.KeyTypeCCHot},
		{"CommitteeColdSigningKeyShelley_ed25519", backend.KeyTypeCCCold},
		// Unknown type falls back to the payment default
		{"UnknownFuturekeyShelley_ed25519", backend.KeyTypePayment},
	}
	for _, tc := range tests {
		t.Run(tc.envelopeType, func(t *testing.T) {
			got := keyTypeFromEnvelope(tc.envelopeType)
			if got != tc.want {
				t.Errorf("keyTypeFromEnvelope(%q) = %q, want %q", tc.envelopeType, got, tc.want)
			}
		})
	}
}

func TestBuildPolicies(t *testing.T) {
	keys := []config.SignerKeyConfig{{
		Hash:            "00000000000000000000000000000000000000000000000000000001",
		Backend:         "software",
		AllowedRequests: []string{"tx"},
		TxPolicy:        map[string]any{"max_output_ada": 100, "allow_mint": false},
	}}
	pols, err := BuildPolicies(keys)
	if err != nil {
		t.Fatalf("BuildPolicies: %v", err)
	}
	if len(pols) != 1 || pols[0].Tx == nil || pols[0].Tx.MaxOutputAda != 100 {
		t.Fatalf("unexpected policy mapping: %+v", pols)
	}
}

func TestBuildPolicies_UnknownFieldRejected(t *testing.T) {
	// A typo'd key in tx_policy must fail at boot (not silently be ignored).
	keys := []config.SignerKeyConfig{{
		Hash:            "00000000000000000000000000000000000000000000000000000002",
		Backend:         "software",
		AllowedRequests: []string{"tx"},
		TxPolicy:        map[string]any{"max_output_lovelace": 999},
	}}
	_, err := BuildPolicies(keys)
	if err == nil {
		t.Fatal("expected error for unknown field max_output_lovelace, got nil")
	}
}

func writeTestSkey(t *testing.T, dir, name string, encrypt bool, passphrase string) string {
	t.Helper()
	seed := bytes.Repeat([]byte{0x42}, 32)
	envelope := fmt.Sprintf(
		`{"type":"PaymentSigningKeyShelley_ed25519","description":"Payment Signing Key","cborHex":"5820%x"}`,
		seed,
	)
	data := []byte(envelope)
	if encrypt {
		enc, err := sops.EncryptWithPassphrase(data, passphrase)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		data = enc
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestBuildBackends_SoftwarePassphrase(t *testing.T) {
	dir := t.TempDir()
	writeTestSkey(t, dir, "payment.skey", true, "test-passphrase")

	t.Setenv("TEST_BURSA_KEY_PASSPHRASE", "test-passphrase")
	backends, err := BuildBackends(context.Background(), []config.SignerBackendConfig{
		{Name: "sw", Type: "software", Path: dir, PassphraseEnv: "TEST_BURSA_KEY_PASSPHRASE"},
	})
	if err != nil {
		t.Fatalf("BuildBackends: %v", err)
	}
	keys, err := backends[0].ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
}

func TestBuildBackends_SoftwareEncryptedWithoutPassphrase(t *testing.T) {
	dir := t.TempDir()
	writeTestSkey(t, dir, "payment.skey", true, "test-passphrase")

	_, err := BuildBackends(context.Background(), []config.SignerBackendConfig{
		{Name: "sw", Type: "software", Path: dir},
	})
	if err == nil {
		t.Fatal("expected error for encrypted key without passphrase_env")
	}
}

func TestBuildBackends_SoftwareWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	writeTestSkey(t, dir, "payment.skey", true, "correct-passphrase")

	t.Setenv("TEST_BURSA_KEY_PASSPHRASE", "wrong-passphrase")
	_, err := BuildBackends(context.Background(), []config.SignerBackendConfig{
		{Name: "sw", Type: "software", Path: dir, PassphraseEnv: "TEST_BURSA_KEY_PASSPHRASE"},
	})
	if err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
	if strings.Contains(err.Error(), "wrong-passphrase") {
		t.Fatalf("error message leaks the passphrase: %q", err.Error())
	}
}

func TestBuildBackends_SoftwarePlaintextStillWorks(t *testing.T) {
	dir := t.TempDir()
	writeTestSkey(t, dir, "payment.skey", false, "")

	backends, err := BuildBackends(context.Background(), []config.SignerBackendConfig{
		{Name: "sw", Type: "software", Path: dir, PassphraseEnv: "UNSET_ENV_VAR_FOR_TEST"},
	})
	if err != nil {
		t.Fatalf("BuildBackends: %v", err)
	}
	keys, _ := backends[0].ListKeys(context.Background())
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
}

type fakeSecretSource struct {
	secrets map[string][]byte
}

func (f *fakeSecretSource) List(_ context.Context) ([]string, error) {
	names := make([]string, 0, len(f.secrets))
	for n := range f.secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

func (f *fakeSecretSource) Get(_ context.Context, name string) ([]byte, error) {
	d, ok := f.secrets[name]
	if !ok {
		return nil, fmt.Errorf("secret %q not found", name)
	}
	return d, nil
}

func TestBuildBackends_Sops(t *testing.T) {
	seed := bytes.Repeat([]byte{0x33}, 32)
	envelope := fmt.Sprintf(
		`{"type":"PaymentSigningKeyShelley_ed25519","description":"","cborHex":"5820%x"}`,
		seed,
	)
	orig := newSopsSecretSource
	defer func() { newSopsSecretSource = orig }()
	newSopsSecretSource = func(_ context.Context, _ config.SignerBackendConfig) (backend.SecretSource, error) {
		return &fakeSecretSource{secrets: map[string][]byte{"signer-payment-1": []byte(envelope)}}, nil
	}
	origDecrypt := sopsDecrypt
	defer func() { sopsDecrypt = origDecrypt }()
	sopsDecrypt = func(d []byte) ([]byte, error) { return d, nil } // fake: secrets arrive "decrypted"

	backends, err := BuildBackends(context.Background(), []config.SignerBackendConfig{
		{Name: "gcp", Type: "sops", SecretPrefix: "signer-"},
	})
	if err != nil {
		t.Fatalf("BuildBackends: %v", err)
	}
	keys, err := backends[0].ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].Backend() != "gcp" {
		t.Fatalf("expected backend gcp, got %q", keys[0].Backend())
	}
	if keys[0].Type() != backend.KeyTypePayment {
		t.Fatalf("expected derived type payment, got %q", keys[0].Type())
	}
}

func TestBuildCallerACL(t *testing.T) {
	hash := strings.Repeat("ab", 28)
	m, err := BuildCallerACL([]config.SignerCallerConfig{{Subject: "alice", Keys: []string{hash}}})
	if err != nil {
		t.Fatalf("BuildCallerACL: %v", err)
	}
	if len(m["alice"]) != 1 {
		t.Fatalf("expected 1 key for alice, got %d", len(m["alice"]))
	}
	if _, err := BuildCallerACL([]config.SignerCallerConfig{{Subject: "", Keys: nil}}); err == nil {
		t.Fatal("expected error for empty subject")
	}
	if _, err := BuildCallerACL([]config.SignerCallerConfig{
		{Subject: "a"}, {Subject: "a"},
	}); err == nil {
		t.Fatal("expected error for duplicate subject")
	}
	if _, err := BuildCallerACL([]config.SignerCallerConfig{{Subject: "a", Keys: []string{"zz"}}}); err == nil {
		t.Fatal("expected error for bad hash")
	}
	if m, _ := BuildCallerACL(nil); m != nil {
		t.Fatal("expected nil map for no callers")
	}
}

func TestBuildBackends_SopsNoSecrets(t *testing.T) {
	orig := newSopsSecretSource
	defer func() { newSopsSecretSource = orig }()
	newSopsSecretSource = func(_ context.Context, _ config.SignerBackendConfig) (backend.SecretSource, error) {
		return &fakeSecretSource{secrets: map[string][]byte{}}, nil
	}
	_, err := BuildBackends(context.Background(), []config.SignerBackendConfig{
		{Name: "gcp", Type: "sops", SecretPrefix: "signer-"},
	})
	if err == nil {
		t.Fatal("expected error when no secrets match the prefix")
	}
}
