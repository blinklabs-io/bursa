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
	"testing"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
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
