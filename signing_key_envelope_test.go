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
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	signingEnvelopeTestMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	pinnedCardanoCLIVersion     = "cardano-cli 10.14.0.0"
)

type signingKeyExporterVector struct {
	name              string
	signingKey        KeyFile
	verificationKey   []byte
	wantType          string
	wantMaterialBytes int
}

func mustSigningKey(key KeyFile, err error) KeyFile {
	if err != nil {
		panic(err)
	}
	return key
}

func mustVerificationKeyBytes(t *testing.T, key KeyFile, err error) []byte {
	t.Helper()
	require.NoError(t, err)
	raw, err := hex.DecodeString(key.CborHex)
	require.NoError(t, err)
	var material []byte
	_, err = cbor.Decode(raw, &material)
	require.NoError(t, err)
	return material
}

// signingKeyExporterRegistry is the single test registry for every public
// signing-key envelope exporter. TestSigningKeyExporterRegistryComplete scans
// bursa.go so a newly-added Get*SKey function cannot escape this contract.
func signingKeyExporterRegistry(t *testing.T) []signingKeyExporterVector {
	t.Helper()
	root, err := GetRootKeyFromMnemonic(signingEnvelopeTestMnemonic, "")
	require.NoError(t, err)
	account, err := GetAccountKey(root, 0)
	require.NoError(t, err)
	payment, err := GetPaymentKey(account, 0)
	require.NoError(t, err)
	calidus, err := GetCalidusKey(account, 0)
	require.NoError(t, err)
	stake, err := GetStakeKey(account, 0)
	require.NoError(t, err)
	drep, err := GetDRepKey(account, 0)
	require.NoError(t, err)
	committeeCold, err := GetCommitteeColdKey(account, 0)
	require.NoError(t, err)
	committeeHot, err := GetCommitteeHotKey(account, 0)
	require.NoError(t, err)
	poolCold, err := GetPoolColdKey(root, 0, 0)
	require.NoError(t, err)
	policy, err := GetPolicyKey(root, 0)
	require.NoError(t, err)
	multisigAccount, err := GetMultiSigAccountKey(root, 0)
	require.NoError(t, err)
	multisigPayment, err := GetMultiSigPaymentKey(multisigAccount, 0)
	require.NoError(t, err)
	multisigStake, err := GetMultiSigStakeKey(multisigAccount, 0)
	require.NoError(t, err)
	vrfSeed, err := GetVRFSeed(root, 0)
	require.NoError(t, err)
	vrfVKey, vrfSKey, err := GetVRFKeyPair(vrfSeed)
	require.NoError(t, err)
	kesSeed, err := GetKESSeed(root, 0)
	require.NoError(t, err)
	kesSKey, kesVKey, err := GetKESKeyPair(kesSeed)
	require.NoError(t, err)

	poolSeed := poolCold.PrivateKey()[:ed25519.SeedSize]
	poolVKey := ed25519.NewKeyFromSeed(poolSeed).Public().(ed25519.PublicKey)

	return []signingKeyExporterVector{
		{
			name: "GetRootSKey", signingKey: mustSigningKey(GetRootSKey(root)),
			verificationKey: root.PublicKey(),
			wantType:        "RootExtendedSigningKeyShelley_ed25519_bip32", wantMaterialBytes: 128,
		},
		{
			name: "GetAccountSKey", signingKey: mustSigningKey(GetAccountSKey(account)),
			verificationKey: account.PublicKey(),
			wantType:        "AccountExtendedSigningKeyShelley_ed25519_bip32", wantMaterialBytes: 128,
		},
		{
			name: "GetPaymentSKey", signingKey: mustSigningKey(GetPaymentSKey(payment)),
			verificationKey: payment.PublicKey(),
			wantType:        "PaymentExtendedSigningKeyShelley_ed25519_bip32", wantMaterialBytes: 128,
		},
		{
			name: "GetPaymentExtendedSKey", signingKey: mustSigningKey(GetPaymentExtendedSKey(payment)),
			verificationKey: payment.PublicKey(),
			wantType:        "PaymentExtendedSigningKeyShelley_ed25519_bip32", wantMaterialBytes: 128,
		},
		{
			name: "GetCalidusSKey", signingKey: mustSigningKey(GetCalidusSKey(calidus)),
			verificationKey: calidus.PublicKey(),
			wantType:        "CalidusExtendedSigningKeyShelley_ed25519_bip32", wantMaterialBytes: 128,
		},
		{
			name: "GetCalidusExtendedSKey", signingKey: mustSigningKey(GetCalidusExtendedSKey(calidus)),
			verificationKey: calidus.PublicKey(),
			wantType:        "CalidusExtendedSigningKeyShelley_ed25519_bip32", wantMaterialBytes: 128,
		},
		{
			name: "GetStakeSKey", signingKey: mustSigningKey(GetStakeSKey(stake)),
			verificationKey: stake.PublicKey(),
			wantType:        "StakeExtendedSigningKeyShelley_ed25519_bip32", wantMaterialBytes: 128,
		},
		{
			name: "GetStakeExtendedSKey", signingKey: mustSigningKey(GetStakeExtendedSKey(stake)),
			verificationKey: stake.PublicKey(),
			wantType:        "StakeExtendedSigningKeyShelley_ed25519_bip32", wantMaterialBytes: 128,
		},
		{
			name: "GetDRepSKey", signingKey: mustSigningKey(GetDRepSKey(drep)),
			verificationKey: drep.PublicKey(),
			wantType:        "DRepExtendedSigningKeyShelley_ed25519_bip32", wantMaterialBytes: 128,
		},
		{
			name: "GetDRepExtendedSKey", signingKey: mustSigningKey(GetDRepExtendedSKey(drep)),
			verificationKey: drep.PublicKey(),
			wantType:        "DRepExtendedSigningKeyShelley_ed25519_bip32", wantMaterialBytes: 128,
		},
		{
			name: "GetCommitteeColdSKey", signingKey: mustSigningKey(GetCommitteeColdSKey(committeeCold)),
			verificationKey: committeeCold.PublicKey(),
			wantType:        "CommitteeColdExtendedSigningKeyShelley_ed25519_bip32", wantMaterialBytes: 128,
		},
		{
			name: "GetCommitteeColdExtendedSKey", signingKey: mustSigningKey(GetCommitteeColdExtendedSKey(committeeCold)),
			verificationKey: committeeCold.PublicKey(),
			wantType:        "CommitteeColdExtendedSigningKeyShelley_ed25519_bip32", wantMaterialBytes: 128,
		},
		{
			name: "GetCommitteeHotSKey", signingKey: mustSigningKey(GetCommitteeHotSKey(committeeHot)),
			verificationKey: committeeHot.PublicKey(),
			wantType:        "CommitteeHotExtendedSigningKeyShelley_ed25519_bip32", wantMaterialBytes: 128,
		},
		{
			name: "GetCommitteeHotExtendedSKey", signingKey: mustSigningKey(GetCommitteeHotExtendedSKey(committeeHot)),
			verificationKey: committeeHot.PublicKey(),
			wantType:        "CommitteeHotExtendedSigningKeyShelley_ed25519_bip32", wantMaterialBytes: 128,
		},
		{
			name: "GetPoolColdSKey", signingKey: mustSigningKey(GetPoolColdSKey(poolCold)),
			verificationKey: poolVKey,
			wantType:        "StakePoolSigningKey_ed25519", wantMaterialBytes: 32,
		},
		{
			name: "GetPoolColdExtendedSKey", signingKey: mustSigningKey(GetPoolColdExtendedSKey(poolCold)),
			verificationKey: poolVKey,
			wantType:        "StakePoolExtendedSigningKeyShelley_ed25519_bip32", wantMaterialBytes: 128,
		},
		{
			name: "GetPolicySKey", signingKey: mustSigningKey(GetPolicySKey(policy)),
			verificationKey: policy.PublicKey(),
			wantType:        "PolicyExtendedSigningKeyShelley_ed25519_bip32", wantMaterialBytes: 128,
		},
		{
			name: "GetPolicyExtendedSKey", signingKey: mustSigningKey(GetPolicyExtendedSKey(policy)),
			verificationKey: policy.PublicKey(),
			wantType:        "PolicyExtendedSigningKeyShelley_ed25519_bip32", wantMaterialBytes: 128,
		},
		{
			name: "GetVRFSKey", signingKey: mustSigningKey(GetVRFSKey(vrfSKey)),
			verificationKey: vrfVKey,
			wantType:        "VRFSigningKey_PraosVRF", wantMaterialBytes: len(vrfSKey),
		},
		{
			name: "GetKESSKey", signingKey: mustSigningKey(GetKESSKey(kesSKey)),
			verificationKey: kesVKey,
			wantType:        "KESSigningKey_PraosV2", wantMaterialBytes: len(kesSKey.Data),
		},
		{
			name: "GetMultiSigPaymentSKey", signingKey: mustSigningKey(GetMultiSigPaymentSKey(multisigPayment)),
			verificationKey: multisigPayment.PublicKey(),
			wantType:        "PaymentExtendedSigningKeyShelley_ed25519_bip32", wantMaterialBytes: 128,
		},
		{
			name: "GetMultiSigStakeSKey", signingKey: mustSigningKey(GetMultiSigStakeSKey(multisigStake)),
			verificationKey: multisigStake.PublicKey(),
			wantType:        "StakeExtendedSigningKeyShelley_ed25519_bip32", wantMaterialBytes: 128,
		},
	}
}

func TestSigningKeyExporterRegistryComplete(t *testing.T) {
	registry := signingKeyExporterRegistry(t)
	want := make([]string, 0, len(registry))
	for _, vector := range registry {
		want = append(want, vector.name)
	}
	sort.Strings(want)

	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	sourceFile := filepath.Join(filepath.Dir(thisFile), "bursa.go")
	parsed, err := parser.ParseFile(token.NewFileSet(), sourceFile, nil, 0)
	require.NoError(t, err)

	got := make([]string, 0, len(want))
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || !strings.HasPrefix(function.Name.Name, "Get") ||
			!strings.HasSuffix(function.Name.Name, "SKey") ||
			function.Type.Results == nil || len(function.Type.Results.List) < 1 {
			continue
		}
		firstResult, ok := function.Type.Results.List[0].Type.(*ast.Ident)
		if ok && firstResult.Name == "KeyFile" {
			got = append(got, function.Name.Name)
		}
	}
	sort.Strings(got)
	assert.Equal(t, want, got)
}

func TestSigningKeyExportersImplyPairedVerificationIdentity(t *testing.T) {
	for _, vector := range signingKeyExporterRegistry(t) {
		t.Run(vector.name, func(t *testing.T) {
			assert.Equal(t, vector.wantType, vector.signingKey.Type)

			raw, err := hex.DecodeString(vector.signingKey.CborHex)
			require.NoError(t, err)
			var material []byte
			_, err = cbor.Decode(raw, &material)
			require.NoError(t, err)
			assert.Len(t, material, vector.wantMaterialBytes)

			envelope, err := json.Marshal(vector.signingKey)
			require.NoError(t, err)
			loaded, err := LoadKeyFromBytes(envelope)
			require.NoError(t, err)
			assert.Equal(t, vector.verificationKey, loaded.VKey)
			if len(loaded.SKey) == ed25519.PrivateKeySize || len(loaded.SKey) == 96 {
				actualSigningIdentity, err := PublicKeyOf(loaded)
				require.NoError(t, err)
				assert.Equal(t, vector.verificationKey, actualSigningIdentity)
			}
		})
	}
}

func TestSigningKeyEnvelopeControls(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	seedCBOR, err := cbor.Encode(seed)
	require.NoError(t, err)
	nonExtended := KeyFile{
		Type:    "PaymentSigningKeyShelley_ed25519",
		CborHex: hex.EncodeToString(seedCBOR),
	}
	raw, err := json.Marshal(nonExtended)
	require.NoError(t, err)
	loaded, err := LoadKeyFromBytes(raw)
	require.NoError(t, err)
	assert.Equal(t, ed25519.NewKeyFromSeed(seed).Public(), ed25519.PublicKey(loaded.VKey))

	root, err := GetRootKeyFromMnemonic(signingEnvelopeTestMnemonic, "")
	require.NoError(t, err)
	account, err := GetAccountKey(root, 0)
	require.NoError(t, err)
	payment, err := GetPaymentKey(account, 0)
	require.NoError(t, err)
	extended := mustSigningKey(GetPaymentExtendedSKey(payment))
	raw, err = json.Marshal(extended)
	require.NoError(t, err)
	loaded, err = LoadKeyFromBytes(raw)
	require.NoError(t, err)
	assert.Equal(t, payment.PublicKey(), loaded.VKey)

	extended.Type = "PaymentSigningKeyShelley_ed25519"
	raw, err = json.Marshal(extended)
	require.NoError(t, err)
	_, err = LoadKeyFromBytes(raw)
	require.ErrorContains(t, err, "expected 32 bytes")
}

func TestLegacyBIP32MaterialInNonExtendedEnvelopeDoesNotMatchIdentity(t *testing.T) {
	root, err := GetRootKeyFromMnemonic(signingEnvelopeTestMnemonic, "")
	require.NoError(t, err)
	account, err := GetAccountKey(root, 0)
	require.NoError(t, err)
	payment, err := GetPaymentKey(account, 0)
	require.NoError(t, err)
	stake, err := GetStakeKey(account, 0)
	require.NoError(t, err)

	vectors := []struct {
		name    string
		key     []byte
		vkey    []byte
		keyType string
	}{
		{
			name: "payment", key: payment.PrivateKey()[:ed25519.SeedSize],
			vkey: payment.PublicKey(), keyType: "PaymentSigningKeyShelley_ed25519",
		},
		{
			name: "stake", key: stake.PrivateKey()[:ed25519.SeedSize],
			vkey: stake.PublicKey(), keyType: "StakeSigningKeyShelley_ed25519",
		},
	}

	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			keyCBOR, err := cbor.Encode(vector.key)
			require.NoError(t, err)
			legacy := KeyFile{
				Type:    vector.keyType,
				CborHex: hex.EncodeToString(keyCBOR),
			}
			raw, err := json.Marshal(legacy)
			require.NoError(t, err)
			loaded, err := LoadKeyFromBytes(raw)
			require.NoError(t, err)
			assert.NotEqual(t, vector.vkey, loaded.VKey)
		})
	}
}

func TestSigningKeyCardanoCLIDifferential(t *testing.T) {
	cardanoCLI, err := exec.LookPath("cardano-cli")
	if err != nil {
		t.Skip("cardano-cli is not installed")
	}
	version, err := exec.Command(cardanoCLI, "version").CombinedOutput()
	require.NoError(t, err)
	if !strings.Contains(string(version), pinnedCardanoCLIVersion) {
		t.Skipf("requires pinned %s, got %q", pinnedCardanoCLIVersion, strings.TrimSpace(string(version)))
	}

	wallet, err := NewWallet(signingEnvelopeTestMnemonic)
	require.NoError(t, err)
	vectors := []struct {
		name            string
		skey            KeyFile
		vkey            KeyFile
		wantDerivedType string
	}{
		{
			name: "payment", skey: wallet.PaymentSKey, vkey: wallet.PaymentVKey,
			wantDerivedType: "PaymentExtendedVerificationKeyShelley_ed25519_bip32",
		},
		{
			name: "stake", skey: wallet.StakeSKey, vkey: wallet.StakeVKey,
			wantDerivedType: "StakeExtendedVerificationKeyShelley_ed25519_bip32",
		},
		{
			name: "pool-cold", skey: wallet.PoolColdSKey, vkey: wallet.PoolColdVKey,
			wantDerivedType: "StakePoolVerificationKey_ed25519",
		},
	}

	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			skeyFile := filepath.Join(tmpDir, "key.skey")
			derivedFile := filepath.Join(tmpDir, "derived.vkey")
			raw, err := json.Marshal(vector.skey)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(skeyFile, raw, 0o600))

			output, err := exec.Command(
				cardanoCLI,
				"key", "verification-key",
				"--signing-key-file", skeyFile,
				"--verification-key-file", derivedFile,
			).CombinedOutput()
			require.NoErrorf(t, err, "cardano-cli failed: %s", output)

			derivedRaw, err := os.ReadFile(derivedFile)
			require.NoError(t, err)
			var derived KeyFile
			require.NoError(t, json.Unmarshal(derivedRaw, &derived))
			assert.Equal(t, vector.wantDerivedType, derived.Type)

			pairedIdentity := mustVerificationKeyBytes(t, vector.vkey, nil)
			derivedRawCBOR, err := hex.DecodeString(derived.CborHex)
			require.NoError(t, err)
			var derivedMaterial []byte
			_, err = cbor.Decode(derivedRawCBOR, &derivedMaterial)
			require.NoError(t, err)
			require.GreaterOrEqual(t, len(derivedMaterial), ed25519.PublicKeySize)
			assert.Equal(t, pairedIdentity, derivedMaterial[:ed25519.PublicKeySize])
		})
	}
}

func TestSigningKeyGoldenVerificationVectors(t *testing.T) {
	wallet, err := NewWallet(signingEnvelopeTestMnemonic)
	require.NoError(t, err)

	vectors := []struct {
		name string
		key  KeyFile
		want string
	}{
		{name: "payment", key: wallet.PaymentVKey, want: "58207ea09a34aebb13c9841c71397b1cabfec5ddf950405293dee496cac2f437480a"},
		{name: "stake", key: wallet.StakeVKey, want: "5820012f5dc3115b8a07981e6e50f5a671e2c6fbb26c3ffde1cd1dcaf40a7fe8f160"},
		{name: "pool-cold", key: wallet.PoolColdVKey, want: "5820beafe7eb55afd03bde1170d2286695085e5fce98a1529456bff18c17e6f6cf4e"},
	}
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			assert.Equal(t, vector.want, vector.key.CborHex)
		})
	}
}
