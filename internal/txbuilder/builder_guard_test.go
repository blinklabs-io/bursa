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

package txbuilder

import (
	"bytes"
	"context"
	"math"
	"math/big"
	"testing"

	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/conway"
	"github.com/stretchr/testify/require"
)

const guardAddr = "addr_test1vzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07shflwre"

func guardChain() *FakeChain {
	chain := NewFakeChain()
	chain.UtxosMap[guardAddr] = []UTxO{
		MakeUTxO(guardAddr, "7777777777777777777777777777777777777777777777777777777777777777", 0, 1_000_000_000),
	}
	return chain
}

func guardCertFile(t *testing.T, cert lcommon.Certificate, typ lcommon.CertificateType) string {
	t.Helper()
	return writeEnvelopeCert(t, t.TempDir(), "cert", "CertificateConway", encodeWrapper(t, cert, typ))
}

// Byron inputs need bootstrap witnesses, which the fee estimate does not
// size, so a Byron change address is refused.
func TestBuildRejectsByronChangeAddress(t *testing.T) {
	byron := "Ae2tdPwUPEYwFx4dmJheyNPPYXtvHbJLeCaA96o6Y2iiUL18cAt7AizN2zG"
	chain := NewFakeChain()
	chain.UtxosMap[byron] = []UTxO{
		MakeUTxO(byron, "7878787878787878787878787878787878787878787878787878787878787878", 0, 1_000_000_000),
	}
	_, err := Build(context.Background(), chain, BuildOptions{ChangeAddress: byron})
	require.ErrorContains(t, err, "Byron")
}

func TestBuildRejectsScriptChangeAddress(t *testing.T) {
	addr, err := lcommon.NewAddressFromParts(
		lcommon.AddressTypeScriptNone,
		lcommon.AddressNetworkTestnet,
		bytes.Repeat([]byte{0x44}, 28),
		nil,
	)
	require.NoError(t, err)
	script := addr.String()
	chain := NewFakeChain()
	chain.UtxosMap[script] = []UTxO{
		MakeUTxO(script, "7979797979797979797979797979797979797979797979797979797979797979", 0, 1_000_000_000),
	}
	_, err = Build(context.Background(), chain, BuildOptions{ChangeAddress: script})
	require.ErrorContains(t, err, "script")
}

func TestBuildRejectsRemovedCertificateTypes(t *testing.T) {
	mir := &lcommon.MoveInstantaneousRewardsCertificate{
		CertType: uint(lcommon.CertificateTypeMoveInstantaneousRewards),
		Reward: lcommon.MoveInstantaneousRewardsCertificateReward{
			Source:   1,
			OtherPot: 1_000_000,
		},
	}
	gen := &lcommon.GenesisKeyDelegationCertificate{
		CertType: uint(lcommon.CertificateTypeGenesisKeyDelegation),
	}
	for _, tc := range []struct {
		cert lcommon.Certificate
		typ  lcommon.CertificateType
	}{
		{mir, lcommon.CertificateTypeMoveInstantaneousRewards},
		{gen, lcommon.CertificateTypeGenesisKeyDelegation},
	} {
		_, err := Build(context.Background(), guardChain(), BuildOptions{
			ChangeAddress:    guardAddr,
			CertificateFiles: []string{guardCertFile(t, tc.cert, tc.typ)},
		})
		require.ErrorContains(t, err, "no longer supported", tc.typ)
	}
}

func TestBuildRejectsTTLMarginOverflow(t *testing.T) {
	chain := guardChain()
	chain.SlotVal = math.MaxUint64 - 10
	_, err := Build(context.Background(), chain, BuildOptions{
		ChangeAddress: guardAddr,
		TTLMargin:     11,
	})
	require.ErrorContains(t, err, "overflow")
	_, err = Build(context.Background(), chain, BuildOptions{
		ChangeAddress: guardAddr,
		TTLMargin:     10,
	})
	require.NoError(t, err)
}

// balance returns inputs + refunds - (outputs + fee) for a built tx, which
// is the deposit the builder charged.
func chargedDeposit(t *testing.T, built *BuiltTx, inputs uint64) uint64 {
	t.Helper()
	require.NotNil(t, built)
	tx, err := conway.NewConwayTransactionFromCbor(built.TxCBOR)
	require.NoError(t, err)
	out := tx.Body.TxFee
	for _, o := range tx.Body.TxOutputs {
		out += o.OutputAmount.Amount
	}
	return inputs - out
}

func TestBuildChargesPoolDepositOncePerPool(t *testing.T) {
	rewardAcct := bytes.Repeat([]byte{0x62}, 28)
	newCert := func(cost uint64) lcommon.Certificate {
		cert := &lcommon.PoolRegistrationCertificate{
			CertType:      uint(lcommon.CertificateTypePoolRegistration),
			Operator:      lcommon.PoolKeyHash(bytes.Repeat([]byte{0x61}, 28)),
			VrfKeyHash:    lcommon.VrfKeyHash(bytes.Repeat([]byte{0x63}, 32)),
			Pledge:        1_000_000,
			Cost:          cost,
			Margin:        lcommon.GenesisRat{Rat: big.NewRat(1, 20)},
			RewardAccount: lcommon.AddrKeyHash(rewardAcct),
			PoolOwners:    []lcommon.AddrKeyHash{},
			Relays:        []lcommon.PoolRelay{},
		}
		require.NoError(t, cert.SetRewardAccountCredential(lcommon.Credential{
			CredType:   lcommon.CredentialTypeAddrKeyHash,
			Credential: lcommon.CredentialHash(rewardAcct),
		}, 0))
		return cert
	}
	chain := guardChain()
	built, err := Build(context.Background(), chain, BuildOptions{
		ChangeAddress: guardAddr,
		CertificateFiles: []string{
			guardCertFile(t, newCert(340_000_000), lcommon.CertificateTypePoolRegistration),
			guardCertFile(t, newCert(350_000_000), lcommon.CertificateTypePoolRegistration),
		},
	})
	require.NoError(t, err)
	require.Equal(t, chain.PpExtra.PoolDeposit, chargedDeposit(t, built, 1_000_000_000))
}

// A legacy deregistration of a credential registered earlier in the same
// transaction refunds the current key deposit, not a recorded one.
func TestRefundLegacyDeregistrationOfSameTxRegistration(t *testing.T) {
	chain := guardChain()
	cred := makeStakeCredential(t, 0x71)
	// A stale recorded deposit must not be used for this credential.
	chain.StakeDelegDeposits[StakeCredentialKeyFrom(cred)] = 9_000_000
	reg := &lcommon.StakeRegistrationCertificate{
		CertType:        uint(lcommon.CertificateTypeStakeRegistration),
		StakeCredential: cred,
	}
	dereg := &lcommon.StakeDeregistrationCertificate{
		CertType:        uint(lcommon.CertificateTypeStakeDeregistration),
		StakeCredential: cred,
	}
	built, err := Build(context.Background(), chain, BuildOptions{
		ChangeAddress: guardAddr,
		CertificateFiles: []string{
			guardCertFile(t, reg, lcommon.CertificateTypeStakeRegistration),
			guardCertFile(t, dereg, lcommon.CertificateTypeStakeDeregistration),
		},
	})
	require.NoError(t, err)
	// Deposit and refund are both KeyDeposit, so nothing net is charged.
	require.Equal(t, uint64(0), chargedDeposit(t, built, 1_000_000_000))
}

// The ledger rejects deregistering a credential that is not registered, so
// the builder refuses instead of refunding nothing.
func TestBuildRejectsDeregistrationOfUnregisteredCredential(t *testing.T) {
	cred := makeStakeCredential(t, 0x72)
	dereg := &lcommon.StakeDeregistrationCertificate{
		CertType:        uint(lcommon.CertificateTypeStakeDeregistration),
		StakeCredential: cred,
	}
	_, err := Build(context.Background(), guardChain(), BuildOptions{
		ChangeAddress:    guardAddr,
		CertificateFiles: []string{guardCertFile(t, dereg, lcommon.CertificateTypeStakeDeregistration)},
	})
	require.ErrorContains(t, err, "not registered")
}

// A deregistration that comes before the registration in certificate order
// does not see it: the ledger applies certificates in order.
func TestBuildRejectsDeregistrationBeforeRegistration(t *testing.T) {
	cred := makeStakeCredential(t, 0x73)
	reg := &lcommon.StakeRegistrationCertificate{
		CertType:        uint(lcommon.CertificateTypeStakeRegistration),
		StakeCredential: cred,
	}
	dereg := &lcommon.StakeDeregistrationCertificate{
		CertType:        uint(lcommon.CertificateTypeStakeDeregistration),
		StakeCredential: cred,
	}
	_, err := Build(context.Background(), guardChain(), BuildOptions{
		ChangeAddress: guardAddr,
		CertificateFiles: []string{
			guardCertFile(t, dereg, lcommon.CertificateTypeStakeDeregistration),
			guardCertFile(t, reg, lcommon.CertificateTypeStakeRegistration),
		},
	})
	require.ErrorContains(t, err, "not registered")
}
