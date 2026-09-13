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
	"testing"

	"github.com/blinklabs-io/bursa/bip32"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/kes"
	"github.com/blinklabs-io/gouroboros/vrf"
	"github.com/stretchr/testify/require"
)

// authoritativeEnvelopeVector is a constructor output paired with the public
// identity that the loader must return. The identity is supplied by the
// derivation path (or the corresponding constructor), rather than by parsing
// the envelope under test.
type authoritativeEnvelopeVector struct {
	name     string
	key      KeyFile
	wantVKey []byte
	extended bool
	signing  bool
}

func authoritativeEnvelopeJSON(t *testing.T, key KeyFile) []byte {
	t.Helper()
	data, err := json.Marshal(key)
	require.NoError(t, err)
	return data
}

func appendKeyPair(
	t *testing.T,
	vectors *[]authoritativeEnvelopeVector,
	name string,
	key bip32.XPrv,
	vkey, skey KeyFile,
) {
	t.Helper()
	want := append([]byte(nil), key.Public().PublicKey()...)
	*vectors = append(*vectors,
		authoritativeEnvelopeVector{name + " verification", vkey, want, false, false},
		authoritativeEnvelopeVector{name + " extended signing", skey, want, true, true},
	)
}

func appendExtendedAlias(
	t *testing.T,
	vectors *[]authoritativeEnvelopeVector,
	name string,
	key bip32.XPrv,
	skey KeyFile,
) {
	t.Helper()
	*vectors = append(*vectors, authoritativeEnvelopeVector{
		name + " explicit extended signing",
		skey,
		append([]byte(nil), key.Public().PublicKey()...),
		true,
		true,
	})
}

// authoritativeEnvelopeVectors covers every exported Ed25519 key role and
// derivation path, including CIP-1852, CIP-1853, CIP-1854, CIP-1855, CIP-88,
// and the multi-signature paths. The payment and stake values are also
// checked against the cardano-cli-compatible constants in the existing
// capability tests; all other rows are checked against their independent
// derivation path here.
func authoritativeEnvelopeVectors(t *testing.T) []authoritativeEnvelopeVector {
	t.Helper()
	root, err := GetRootKeyFromMnemonic(capabilityMnemonic, "")
	require.NoError(t, err)
	account, err := GetAccountKey(root, 0)
	require.NoError(t, err)
	payment, err := GetPaymentKey(account, 0)
	require.NoError(t, err)
	stake, err := GetStakeKey(account, 0)
	require.NoError(t, err)
	drep, err := GetDRepKey(account, 0)
	require.NoError(t, err)
	cold, err := GetCommitteeColdKey(account, 0)
	require.NoError(t, err)
	hot, err := GetCommitteeHotKey(account, 0)
	require.NoError(t, err)
	pool, err := GetPoolColdKey(root, 0, 0)
	require.NoError(t, err)
	policy, err := GetPolicyKey(root, 0)
	require.NoError(t, err)
	calidus, err := GetCalidusKey(account, 0)
	require.NoError(t, err)
	msAccount, err := GetMultiSigAccountKey(root, 0)
	require.NoError(t, err)
	msPayment, err := GetMultiSigPaymentKey(msAccount, 0)
	require.NoError(t, err)
	msStake, err := GetMultiSigStakeKey(msAccount, 0)
	require.NoError(t, err)

	var vectors []authoritativeEnvelopeVector
	rootSKey, err := GetRootSKey(root)
	require.NoError(t, err)
	rootWant := append([]byte(nil), root.Public().PublicKey()...)
	vectors = append(vectors, authoritativeEnvelopeVector{
		"root extended signing", rootSKey, rootWant, true, true,
	})

	accountVKey, err := GetAccountVKey(account)
	require.NoError(t, err)
	accountSKey, err := GetAccountSKey(account)
	require.NoError(t, err)
	appendKeyPair(t, &vectors, "account", account, accountVKey, accountSKey)

	paymentVKey, err := GetPaymentVKey(payment)
	require.NoError(t, err)
	paymentSKey, err := GetPaymentSKey(payment)
	require.NoError(t, err)
	appendKeyPair(t, &vectors, "payment", payment, paymentVKey, paymentSKey)
	paymentExtSKey, err := GetPaymentExtendedSKey(payment)
	require.NoError(t, err)
	appendExtendedAlias(t, &vectors, "payment", payment, paymentExtSKey)

	calidusVKey, err := GetCalidusVKey(calidus)
	require.NoError(t, err)
	calidusSKey, err := GetCalidusSKey(calidus)
	require.NoError(t, err)
	appendKeyPair(t, &vectors, "calidus", calidus, calidusVKey, calidusSKey)
	calidusExtSKey, err := GetCalidusExtendedSKey(calidus)
	require.NoError(t, err)
	appendExtendedAlias(t, &vectors, "calidus", calidus, calidusExtSKey)

	stakeVKey, err := GetStakeVKey(stake)
	require.NoError(t, err)
	stakeSKey, err := GetStakeSKey(stake)
	require.NoError(t, err)
	appendKeyPair(t, &vectors, "stake", stake, stakeVKey, stakeSKey)
	stakeExtSKey, err := GetStakeExtendedSKey(stake)
	require.NoError(t, err)
	appendExtendedAlias(t, &vectors, "stake", stake, stakeExtSKey)

	drepVKey, err := GetDRepVKey(drep)
	require.NoError(t, err)
	drepSKey, err := GetDRepSKey(drep)
	require.NoError(t, err)
	appendKeyPair(t, &vectors, "drep", drep, drepVKey, drepSKey)
	drepExtSKey, err := GetDRepExtendedSKey(drep)
	require.NoError(t, err)
	appendExtendedAlias(t, &vectors, "drep", drep, drepExtSKey)

	coldVKey, err := GetCommitteeColdVKey(cold)
	require.NoError(t, err)
	coldSKey, err := GetCommitteeColdSKey(cold)
	require.NoError(t, err)
	appendKeyPair(t, &vectors, "committee cold", cold, coldVKey, coldSKey)
	coldExtSKey, err := GetCommitteeColdExtendedSKey(cold)
	require.NoError(t, err)
	appendExtendedAlias(t, &vectors, "committee cold", cold, coldExtSKey)

	hotVKey, err := GetCommitteeHotVKey(hot)
	require.NoError(t, err)
	hotSKey, err := GetCommitteeHotSKey(hot)
	require.NoError(t, err)
	appendKeyPair(t, &vectors, "committee hot", hot, hotVKey, hotSKey)
	hotExtSKey, err := GetCommitteeHotExtendedSKey(hot)
	require.NoError(t, err)
	appendExtendedAlias(t, &vectors, "committee hot", hot, hotExtSKey)

	poolVKey, err := GetPoolColdVKey(pool)
	require.NoError(t, err)
	poolSKey, err := GetPoolColdSKey(pool)
	require.NoError(t, err)
	poolExtSKey, err := GetPoolColdExtendedSKey(pool)
	require.NoError(t, err)
	poolWant := decodeCborBytes(t, poolVKey.CborHex)
	vectors = append(vectors,
		authoritativeEnvelopeVector{"pool cold verification", poolVKey, poolWant, false, false},
		authoritativeEnvelopeVector{"pool cold signing", poolSKey, poolWant, false, true},
		authoritativeEnvelopeVector{"pool cold extended signing", poolExtSKey, poolWant, true, true},
	)

	policyVKey, err := GetPolicyVKey(policy)
	require.NoError(t, err)
	policySKey, err := GetPolicySKey(policy)
	require.NoError(t, err)
	appendKeyPair(t, &vectors, "policy", policy, policyVKey, policySKey)
	policyExtSKey, err := GetPolicyExtendedSKey(policy)
	require.NoError(t, err)
	appendExtendedAlias(t, &vectors, "policy", policy, policyExtSKey)

	msPaymentVKey, err := GetMultiSigPaymentVKey(msPayment)
	require.NoError(t, err)
	msPaymentSKey, err := GetMultiSigPaymentSKey(msPayment)
	require.NoError(t, err)
	appendKeyPair(t, &vectors, "multi-sig payment", msPayment, msPaymentVKey, msPaymentSKey)

	msStakeVKey, err := GetMultiSigStakeVKey(msStake)
	require.NoError(t, err)
	msStakeSKey, err := GetMultiSigStakeSKey(msStake)
	require.NoError(t, err)
	appendKeyPair(t, &vectors, "multi-sig stake", msStake, msStakeVKey, msStakeSKey)

	vrfSeed, err := GetVRFSeed(root, 0)
	require.NoError(t, err)
	vrfPub, vrfSec, err := GetVRFKeyPair(vrfSeed)
	require.NoError(t, err)
	vrfVKey, err := GetVRFVKey(vrfPub)
	require.NoError(t, err)
	vrfSKey, err := GetVRFSKey(vrfSec)
	require.NoError(t, err)
	vectors = append(vectors,
		authoritativeEnvelopeVector{"VRF verification", vrfVKey, vrfPub, false, false},
		authoritativeEnvelopeVector{"VRF signing", vrfSKey, vrfPub, false, true},
	)

	kesSeed, err := GetKESSeed(root, 0)
	require.NoError(t, err)
	kesSec, kesPub, err := GetKESKeyPair(kesSeed)
	require.NoError(t, err)
	kesVKey, err := GetKESVKey(kesPub)
	require.NoError(t, err)
	kesSKey, err := GetKESSKey(kesSec)
	require.NoError(t, err)
	vectors = append(vectors,
		authoritativeEnvelopeVector{"KES verification", kesVKey, kesPub, false, false},
		authoritativeEnvelopeVector{"KES signing", kesSKey, kesPub, false, true},
	)

	// Keep the standard legacy signer aliases in the matrix: these are accepted
	// cardano-cli envelope names and use the same canonical 32-byte seed.
	seedCbor, err := cbor.Encode(append([]byte(nil), payment.PrivateKey()[:32]...))
	require.NoError(t, err)
	legacySeed := append([]byte(nil), payment.PrivateKey()[:32]...)
	legacyPub := ed25519.NewKeyFromSeed(legacySeed).Public().(ed25519.PublicKey)
	for _, name := range []string{
		"SigningKeyShelley_ed25519",
		"AccountSigningKeyShelley_ed25519",
		"PaymentSigningKeyShelley_ed25519",
		"StakeSigningKeyShelley_ed25519",
		"DRepSigningKeyShelley_ed25519",
		"CommitteeColdSigningKeyShelley_ed25519",
		"CommitteeHotSigningKeyShelley_ed25519",
		"StakePoolSigningKey_ed25519",
		"StakePoolSigningKeyShelley_ed25519",
		"PolicySigningKeyShelley_ed25519",
		"CalidusSigningKeyShelley_ed25519",
	} {
		vectors = append(vectors, authoritativeEnvelopeVector{
			"legacy " + name,
			KeyFile{Type: name, Description: "legacy", CborHex: hex.EncodeToString(seedCbor)},
			append([]byte(nil), legacyPub...),
			false,
			true,
		})
	}
	return vectors
}

func TestExportedKeyEnvelopeVectors(t *testing.T) {
	vectors := authoritativeEnvelopeVectors(t)
	require.GreaterOrEqual(t, len(vectors), 45)
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			loaded, err := LoadKeyFromBytes(authoritativeEnvelopeJSON(t, vector.key))
			require.NoError(t, err)
			require.Equal(t, vector.key.Type, loaded.Type)
			require.Equal(t, vector.wantVKey, loaded.VKey)
			if vector.signing {
				require.NotEmpty(t, loaded.SKey, "signing envelope must expose secret material")
			}
		})
	}
}

func TestExportedKeyEnvelopeVectorsRejectTrailingCBOR(t *testing.T) {
	for _, vector := range authoritativeEnvelopeVectors(t) {
		t.Run(vector.name, func(t *testing.T) {
			polluted := vector.key
			polluted.CborHex += "00"
			_, err := LoadKeyFromBytes(authoritativeEnvelopeJSON(t, polluted))
			require.ErrorContains(t, err, "trailing byte")
		})
	}
}

func TestExportedKeyEnvelopeVectorsRejectWrongPayloadLength(t *testing.T) {
	for _, vector := range authoritativeEnvelopeVectors(t) {
		t.Run(vector.name, func(t *testing.T) {
			invalid, err := cbor.Encode([]byte{0})
			require.NoError(t, err)
			mutated := vector.key
			mutated.CborHex = hex.EncodeToString(invalid)
			_, err = LoadKeyFromBytes(authoritativeEnvelopeJSON(t, mutated))
			require.Error(t, err)
		})
	}
}

func TestExportedExtendedEnvelopesRejectMismatchedIdentity(t *testing.T) {
	for _, vector := range authoritativeEnvelopeVectors(t) {
		if !vector.extended {
			continue
		}
		t.Run(vector.name, func(t *testing.T) {
			raw, err := hex.DecodeString(vector.key.CborHex)
			require.NoError(t, err)
			var body []byte
			_, err = cbor.Decode(raw, &body)
			require.NoError(t, err)
			require.Len(t, body, 128)
			body[64] ^= 1
			mutated, err := cbor.Encode(body)
			require.NoError(t, err)
			polluted := vector.key
			polluted.CborHex = hex.EncodeToString(mutated)
			_, err = LoadKeyFromBytes(authoritativeEnvelopeJSON(t, polluted))
			require.ErrorContains(t, err, "does not match")
		})
	}
}

func TestVRFCardanoCLIEnvelopeRejectsMismatchedIdentity(t *testing.T) {
	root, err := GetRootKeyFromMnemonic(capabilityMnemonic, "")
	require.NoError(t, err)
	seed, err := GetVRFSeed(root, 0)
	require.NoError(t, err)
	pub, _, err := GetVRFKeyPair(seed)
	require.NoError(t, err)
	body := append(append([]byte(nil), seed...), pub...)
	body[len(seed)] ^= 1
	encoded, err := cbor.Encode(body)
	require.NoError(t, err)
	key := KeyFile{
		Type:    "VRFSigningKey_PraosVRF",
		CborHex: hex.EncodeToString(encoded),
	}
	_, err = LoadKeyFromBytes(authoritativeEnvelopeJSON(t, key))
	require.ErrorContains(t, err, "does not match")
}

func TestExportedKESAndVRFVectorsUseCanonicalLengths(t *testing.T) {
	for _, vector := range authoritativeEnvelopeVectors(t) {
		switch vector.key.Type {
		case "VRFVerificationKey_PraosVRF", "VRFSigningKey_PraosVRF":
			if vector.key.Type == "VRFSigningKey_PraosVRF" {
				require.Len(t, decodeCborBytes(t, vector.key.CborHex), vrf.SeedSize)
			} else {
				require.Len(t, decodeCborBytes(t, vector.key.CborHex), vrf.PublicKeySize)
			}
		case "KESVerificationKey_PraosV2":
			require.Len(t, decodeCborBytes(t, vector.key.CborHex), kes.PublicKeySize)
		case "KESSigningKey_PraosV2":
			require.Len(t, decodeCborBytes(t, vector.key.CborHex), kes.CardanoKesSecretKeySize)
		}
	}
}

func TestPoolCertificateBuildersRejectInvalidInputs(t *testing.T) {
	t.Run("registration nil", func(t *testing.T) {
		var got []byte
		var err error
		require.NotPanics(t, func() {
			got, err = CreatePoolRegistrationCertificate(nil)
		})
		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("retirement nil", func(t *testing.T) {
		var got []byte
		var err error
		require.NotPanics(t, func() {
			got, err = CreatePoolRetirementCertificate(nil)
		})
		require.Error(t, err)
		require.Nil(t, got)
	})

	for _, test := range []struct {
		name string
		num  int64
		den  int64
	}{
		{name: "negative numerator", num: -1, den: 10},
		{name: "numerator exceeds denominator", num: 11, den: 10},
		{name: "negative denominator", num: 0, den: -1},
	} {
		t.Run(test.name, func(t *testing.T) {
			cert := &PoolRegistrationCertificate{
				MarginNum:     test.num,
				MarginDenom:   test.den,
				RewardAccount: make([]byte, 29),
			}
			_, err := CreatePoolRegistrationCertificate(cert)
			require.Error(t, err)
		})
	}

	for _, test := range []struct {
		name string
		num  int64
	}{
		{name: "zero", num: 0},
		{name: "one", num: 10},
	} {
		t.Run("valid "+test.name, func(t *testing.T) {
			_, err := CreatePoolRegistrationCertificate(&PoolRegistrationCertificate{
				MarginNum:     test.num,
				MarginDenom:   10,
				RewardAccount: make([]byte, 29),
			})
			require.NoError(t, err)
		})
	}
}
