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

package bursa

import (
	"encoding/hex"
	"testing"

	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGovernanceKeyFilesUseCardanoCLITypes asserts the envelope type strings
// written for DRep and committee keys are the ones cardano-cli expects.
func TestGovernanceKeyFilesUseCardanoCLITypes(t *testing.T) {
	t.Parallel()
	account := capabilityAccountKey(t)
	drep, err := GetDRepKey(account, 0)
	require.NoError(t, err)
	cold, err := GetCommitteeColdKey(account, 0)
	require.NoError(t, err)
	hot, err := GetCommitteeHotKey(account, 0)
	require.NoError(t, err)

	cases := []struct {
		name string
		get  func() (KeyFile, error)
		want string
	}{
		{"drep vkey", func() (KeyFile, error) { return GetDRepVKey(drep) }, "DRepVerificationKey_ed25519"},
		{"drep skey", func() (KeyFile, error) { return GetDRepSKey(drep) }, "DRepExtendedSigningKey_ed25519_bip32"},
		{"drep xskey", func() (KeyFile, error) { return GetDRepExtendedSKey(drep) }, "DRepExtendedSigningKey_ed25519_bip32"},
		{"cold vkey", func() (KeyFile, error) { return GetCommitteeColdVKey(cold) }, "ConstitutionalCommitteeColdVerificationKey_ed25519"},
		{"cold skey", func() (KeyFile, error) { return GetCommitteeColdSKey(cold) }, "ConstitutionalCommitteeColdExtendedSigningKey_ed25519_bip32"},
		{"cold xskey", func() (KeyFile, error) { return GetCommitteeColdExtendedSKey(cold) }, "ConstitutionalCommitteeColdExtendedSigningKey_ed25519_bip32"},
		{"hot vkey", func() (KeyFile, error) { return GetCommitteeHotVKey(hot) }, "ConstitutionalCommitteeHotVerificationKey_ed25519"},
		{"hot skey", func() (KeyFile, error) { return GetCommitteeHotSKey(hot) }, "ConstitutionalCommitteeHotExtendedSigningKey_ed25519_bip32"},
		{"hot xskey", func() (KeyFile, error) { return GetCommitteeHotExtendedSKey(hot) }, "ConstitutionalCommitteeHotExtendedSigningKey_ed25519_bip32"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			kf, err := tc.get()
			require.NoError(t, err)
			assert.Equal(t, tc.want, kf.Type)
		})
	}
}

// TestGovernanceKeyTypesLoadAndBech32 asserts the loader and the bech32
// renderer accept both the cardano-cli type names and the legacy Bursa
// names, so wallets written before the rename still load.
func TestGovernanceKeyTypesLoadAndBech32(t *testing.T) {
	t.Parallel()
	account := capabilityAccountKey(t)
	drep, err := GetDRepKey(account, 0)
	require.NoError(t, err)
	cold, err := GetCommitteeColdKey(account, 0)
	require.NoError(t, err)
	hot, err := GetCommitteeHotKey(account, 0)
	require.NoError(t, err)

	type role struct {
		name       string
		vkey, xkey KeyFile
		// skey is a non-extended signing key built from the extended one.
		cliV, cliX, cliS string
		legV, legX, legS string
		vPrefix, xPrefix string
		sPrefix          string
	}
	mk := func(vf, xf func() (KeyFile, error)) (KeyFile, KeyFile) {
		v, err := vf()
		require.NoError(t, err)
		x, err := xf()
		require.NoError(t, err)
		return v, x
	}
	dv, dx := mk(func() (KeyFile, error) { return GetDRepVKey(drep) }, func() (KeyFile, error) { return GetDRepExtendedSKey(drep) })
	cv, cx := mk(func() (KeyFile, error) { return GetCommitteeColdVKey(cold) }, func() (KeyFile, error) { return GetCommitteeColdExtendedSKey(cold) })
	hv, hx := mk(func() (KeyFile, error) { return GetCommitteeHotVKey(hot) }, func() (KeyFile, error) { return GetCommitteeHotExtendedSKey(hot) })
	roles := []role{
		{name: "drep", vkey: dv, xkey: dx,
			cliV: "DRepVerificationKey_ed25519", cliX: "DRepExtendedSigningKey_ed25519_bip32", cliS: "DRepSigningKey_ed25519",
			legV: "DRepVerificationKeyShelley_ed25519", legX: "DRepExtendedSigningKeyShelley_ed25519_bip32", legS: "DRepSigningKeyShelley_ed25519",
			vPrefix: "drep_vk", xPrefix: "drep_xsk", sPrefix: "drep_sk"},
		{name: "cold", vkey: cv, xkey: cx,
			cliV: "ConstitutionalCommitteeColdVerificationKey_ed25519", cliX: "ConstitutionalCommitteeColdExtendedSigningKey_ed25519_bip32", cliS: "ConstitutionalCommitteeColdSigningKey_ed25519",
			legV: "CommitteeColdVerificationKeyShelley_ed25519", legX: "CommitteeColdExtendedSigningKeyShelley_ed25519_bip32", legS: "CommitteeColdSigningKeyShelley_ed25519",
			vPrefix: "cc_cold_vk", xPrefix: "cc_cold_xsk", sPrefix: "cc_cold_sk"},
		{name: "hot", vkey: hv, xkey: hx,
			cliV: "ConstitutionalCommitteeHotVerificationKey_ed25519", cliX: "ConstitutionalCommitteeHotExtendedSigningKey_ed25519_bip32", cliS: "ConstitutionalCommitteeHotSigningKey_ed25519",
			legV: "CommitteeHotVerificationKeyShelley_ed25519", legX: "CommitteeHotExtendedSigningKeyShelley_ed25519_bip32", legS: "CommitteeHotSigningKeyShelley_ed25519",
			vPrefix: "cc_hot_vk", xPrefix: "cc_hot_xsk", sPrefix: "cc_hot_sk"},
	}
	for _, r := range roles {
		wantVKey := decodeCborBytes(t, r.vkey.CborHex)
		for _, typ := range []string{r.cliV, r.legV} {
			t.Run(r.name+"/"+typ, func(t *testing.T) {
				t.Parallel()
				lk, err := LoadKeyFromBytes(envelopeJSON(t, typ, r.vkey.CborHex))
				require.NoError(t, err)
				assert.Equal(t, wantVKey, []byte(lk.VKey))
				kf := KeyFile{Type: typ, CborHex: r.vkey.CborHex}
				assert.Contains(t, kf.String(), r.vPrefix+"1")
			})
		}
		for _, typ := range []string{r.cliX, r.legX} {
			t.Run(r.name+"/"+typ, func(t *testing.T) {
				t.Parallel()
				lk, err := LoadKeyFromBytes(envelopeJSON(t, typ, r.xkey.CborHex))
				require.NoError(t, err)
				assert.Equal(t, wantVKey, []byte(lk.VKey))
				kf := KeyFile{Type: typ, CborHex: r.xkey.CborHex}
				assert.Contains(t, kf.String(), r.xPrefix+"1")
			})
		}
		// Non-extended signing key: 32-byte seed.
		seed := make([]byte, 32)
		seedRaw, err := cbor.Encode(seed)
		require.NoError(t, err)
		seedCbor := hex.EncodeToString(seedRaw)
		for _, typ := range []string{r.cliS, r.legS} {
			t.Run(r.name+"/"+typ, func(t *testing.T) {
				t.Parallel()
				lk, err := LoadKeyFromBytes(envelopeJSON(t, typ, seedCbor))
				require.NoError(t, err)
				assert.NotEmpty(t, lk.SKey)
				kf := KeyFile{Type: typ, CborHex: seedCbor}
				assert.Contains(t, kf.String(), r.sPrefix+"1")
			})
		}
	}
}
