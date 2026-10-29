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
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/conway"
	"github.com/blinklabs-io/gouroboros/ledger/shelley"
	"github.com/blinklabs-io/plutigo/data"
	"github.com/stretchr/testify/require"
	utxorpc "github.com/utxorpc/go-codegen/utxorpc/v1alpha/cardano"
)

func writeEnvelopeCert(t *testing.T, dir, name string, envType string, certBytes []byte) string {
	t.Helper()
	env := struct {
		Type        string `json:"type"`
		Description string `json:"description"`
		CborHex     string `json:"cborHex"`
	}{
		Type:        envType,
		Description: "test",
		CborHex:     hex.EncodeToString(certBytes),
	}
	data, err := json.Marshal(env)
	require.NoError(t, err)
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, data, 0o600))
	return p
}

func makeStakeCredential(t *testing.T, fill byte) lcommon.Credential {
	t.Helper()
	h := make([]byte, 28)
	for i := range h {
		h[i] = fill + byte(i)
	}
	return lcommon.Credential{
		CredType:   lcommon.CredentialTypeAddrKeyHash,
		Credential: lcommon.CredentialHash(h),
	}
}

func encodeWrapper(t *testing.T, cert lcommon.Certificate, typ lcommon.CertificateType) []byte {
	t.Helper()
	wrapper := lcommon.CertificateWrapper{Type: uint(typ), Certificate: cert}
	b, err := cbor.Encode(wrapper)
	require.NoError(t, err)
	return b
}

func TestBuildCoinSelectionAndFeeAndBalance(t *testing.T) {
	chain := NewFakeChain()
	addr := "addr_test1wzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07s7prw5e"
	chain.UtxosMap[addr] = []UTxO{
		MakeUTxO(addr, "0000000000000000000000000000000000000000000000000000000000000001", 0, 10_000_000),
	}
	ctx := context.Background()
	built, err := Build(ctx, chain, BuildOptions{
		ChangeAddress: addr,
		WitnessCount:  2,
	})
	require.NoError(t, err)
	require.NotNil(t, built)
	tx, err := conway.NewConwayTransactionFromCbor(built.TxCBOR)
	require.NoError(t, err)
	estSize, err := bursa.EstimateWitnessedTxSize(built.TxCBOR, 2, 0)
	require.NoError(t, err)
	minFee, err := bursa.MinFee(estSize, *chain.PpFee)
	require.NoError(t, err)
	require.GreaterOrEqual(t, tx.Body.TxFee, minFee)
	var inSum uint64 = 10_000_000
	var outSum uint64
	for _, o := range tx.Body.TxOutputs {
		outSum += o.OutputAmount.Amount
	}
	require.Equal(t, inSum, outSum+tx.Body.TxFee)
	require.Equal(t, uint64(1), uint64(len(tx.Body.TxOutputs)))
	require.Equal(t, addr, tx.Body.TxOutputs[0].OutputAddress.String())
}

func TestBuildPoolDepositChargedOnlyIfNotRegistered(t *testing.T) {
	chain := NewFakeChain()
	addr := "addr_test1wzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07s7prw5e"
	chain.UtxosMap[addr] = []UTxO{
		MakeUTxO(addr, "0000000000000000000000000000000000000000000000000000000000000002", 0, 10_000_000_000),
	}
	poolKey := make([]byte, 28)
	for i := range poolKey {
		poolKey[i] = byte(i)
	}
	vrfKey := make([]byte, 32)
	rewardAcct := make([]byte, 28)
	poolCert := lcommon.PoolRegistrationCertificate{
		CertType:      uint(lcommon.CertificateTypePoolRegistration),
		Operator:      lcommon.PoolKeyHash(poolKey),
		VrfKeyHash:    lcommon.VrfKeyHash(vrfKey),
		Pledge:        1000000,
		Cost:          340000000,
		Margin:        lcommon.GenesisRat{Rat: big.NewRat(0, 1)},
		RewardAccount: lcommon.AddrKeyHash(rewardAcct),
		PoolOwners:    []lcommon.AddrKeyHash{},
		Relays:        []lcommon.PoolRelay{},
	}
	_ = poolCert.SetRewardAccountCredential(lcommon.Credential{
		CredType:   lcommon.CredentialTypeAddrKeyHash,
		Credential: lcommon.CredentialHash(rewardAcct),
	}, 0)
	wrapBytes := encodeWrapper(t, &poolCert, lcommon.CertificateTypePoolRegistration)

	dir := t.TempDir()
	certFile := writeEnvelopeCert(t, dir, "pool.cert", "CertificateConway", wrapBytes)

	ctx := context.Background()
	// Not registered -> should charge pool deposit
	chain.PoolRegistered = map[string]bool{}
	built, err := Build(ctx, chain, BuildOptions{
		ChangeAddress:    addr,
		CertificateFiles: []string{certFile},
		WitnessCount:     1,
	})
	require.NoError(t, err)
	tx, err := conway.NewConwayTransactionFromCbor(built.TxCBOR)
	require.NoError(t, err)
	require.Len(t, tx.Body.TxCertificates, 1)
	// Inputs sum 10B, fee + 500M deposit => change = 10B - fee - 500M
	inSum := uint64(10_000_000_000)
	outSum := tx.Body.TxOutputs[0].OutputAmount.Amount
	require.Equal(t, inSum, outSum+tx.Body.TxFee+chain.PpExtra.PoolDeposit)

	// Registered -> no deposit
	chain.PoolRegistered[hex.EncodeToString(poolKey)] = true
	built2, err := Build(ctx, chain, BuildOptions{
		ChangeAddress:    addr,
		CertificateFiles: []string{certFile},
		WitnessCount:     1,
	})
	require.NoError(t, err)
	tx2, err := conway.NewConwayTransactionFromCbor(built2.TxCBOR)
	require.NoError(t, err)
	outSum2 := tx2.Body.TxOutputs[0].OutputAmount.Amount
	require.Equal(t, inSum, outSum2+tx2.Body.TxFee)
	require.Greater(t, outSum2, outSum)
}

func TestBuildKeyDepositForLegacyStakeRegistration(t *testing.T) {
	chain := NewFakeChain()
	addr := "addr_test1wzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07s7prw5e"
	chain.UtxosMap[addr] = []UTxO{
		MakeUTxO(addr, "1111111111111111111111111111111111111111111111111111111111111111", 0, 20_000_000),
	}
	cred := makeStakeCredential(t, 0x11)
	cert := &lcommon.StakeRegistrationCertificate{
		CertType:        uint(lcommon.CertificateTypeStakeRegistration),
		StakeCredential: cred,
	}
	wrapBytes := encodeWrapper(t, cert, lcommon.CertificateTypeStakeRegistration)
	dir := t.TempDir()
	certFile := writeEnvelopeCert(t, dir, "stake.reg", "CertificateShelley", wrapBytes)
	ctx := context.Background()
	built, err := Build(ctx, chain, BuildOptions{
		ChangeAddress:    addr,
		CertificateFiles: []string{certFile},
		WitnessCount:     1,
	})
	require.NoError(t, err)
	tx, err := conway.NewConwayTransactionFromCbor(built.TxCBOR)
	require.NoError(t, err)
	require.Len(t, tx.Body.TxCertificates, 1)
	inSum := uint64(20_000_000)
	outSum := tx.Body.TxOutputs[0].OutputAmount.Amount
	require.Equal(t, inSum, outSum+tx.Body.TxFee+chain.PpExtra.KeyDeposit)
}

func TestBuildConwayRegistrationDeposit(t *testing.T) {
	chain := NewFakeChain()
	addr := "addr_test1wzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07s7prw5e"
	chain.UtxosMap[addr] = []UTxO{
		MakeUTxO(addr, "2222222222222222222222222222222222222222222222222222222222222222", 0, 20_000_000),
	}
	cred := makeStakeCredential(t, 0x22)
	deposit := uint64(3_000_000)
	cert := &lcommon.RegistrationCertificate{
		CertType:        uint(lcommon.CertificateTypeRegistration),
		StakeCredential: cred,
		Amount:          deposit,
	}
	wrapBytes := encodeWrapper(t, cert, lcommon.CertificateTypeRegistration)
	dir := t.TempDir()
	certFile := writeEnvelopeCert(t, dir, "stake.reg.conway", "CertificateConway", wrapBytes)
	ctx := context.Background()
	built, err := Build(ctx, chain, BuildOptions{
		ChangeAddress:    addr,
		CertificateFiles: []string{certFile},
		WitnessCount:     1,
	})
	require.NoError(t, err)
	tx, err := conway.NewConwayTransactionFromCbor(built.TxCBOR)
	require.NoError(t, err)
	inSum := uint64(20_000_000)
	outSum := tx.Body.TxOutputs[0].OutputAmount.Amount
	require.Equal(t, inSum, outSum+tx.Body.TxFee+deposit)
}

func TestBuildPoolRetirementNoDeposit(t *testing.T) {
	chain := NewFakeChain()
	addr := "addr_test1wzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07s7prw5e"
	chain.UtxosMap[addr] = []UTxO{
		MakeUTxO(addr, "3333333333333333333333333333333333333333333333333333333333333333", 0, 10_000_000),
	}
	poolKey := make([]byte, 28)
	for i := range poolKey {
		poolKey[i] = byte(0xab)
	}
	cert := &lcommon.PoolRetirementCertificate{
		CertType:    uint(lcommon.CertificateTypePoolRetirement),
		PoolKeyHash: lcommon.PoolKeyHash(poolKey),
		Epoch:       500,
	}
	wrapBytes := encodeWrapper(t, cert, lcommon.CertificateTypePoolRetirement)
	dir := t.TempDir()
	certFile := writeEnvelopeCert(t, dir, "pool.retire", "CertificateShelley", wrapBytes)
	ctx := context.Background()
	built, err := Build(ctx, chain, BuildOptions{
		ChangeAddress:    addr,
		CertificateFiles: []string{certFile},
		WitnessCount:     1,
	})
	require.NoError(t, err)
	tx, err := conway.NewConwayTransactionFromCbor(built.TxCBOR)
	require.NoError(t, err)
	inSum := uint64(10_000_000)
	outSum := tx.Body.TxOutputs[0].OutputAmount.Amount
	require.Equal(t, inSum, outSum+tx.Body.TxFee)
}

func TestBuildCertificatesInBodyEqualFiles(t *testing.T) {
	chain := NewFakeChain()
	addr := "addr_test1wzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07s7prw5e"
	chain.UtxosMap[addr] = []UTxO{
		MakeUTxO(addr, "4444444444444444444444444444444444444444444444444444444444444444", 0, 50_000_000),
	}
	cred1 := makeStakeCredential(t, 0x01)
	cred2 := makeStakeCredential(t, 0x02)
	cert1 := &lcommon.StakeRegistrationCertificate{
		CertType:        uint(lcommon.CertificateTypeStakeRegistration),
		StakeCredential: cred1,
	}
	// delegation cert
	poolHash := make([]byte, 28)
	for i := range poolHash {
		poolHash[i] = byte(i + 10)
	}
	cert2 := &lcommon.StakeDelegationCertificate{
		CertType:        uint(lcommon.CertificateTypeStakeDelegation),
		StakeCredential: &cred2,
		PoolKeyHash:     lcommon.PoolKeyHash(poolHash),
	}
	wrap1 := encodeWrapper(t, cert1, lcommon.CertificateTypeStakeRegistration)
	wrap2 := encodeWrapper(t, cert2, lcommon.CertificateTypeStakeDelegation)
	dir := t.TempDir()
	f1 := writeEnvelopeCert(t, dir, "c1", "CertificateShelley", wrap1)
	f2 := writeEnvelopeCert(t, dir, "c2", "CertificateShelley", wrap2)
	ctx := context.Background()
	built, err := Build(ctx, chain, BuildOptions{
		ChangeAddress:    addr,
		CertificateFiles: []string{f1, f2},
		WitnessCount:     1,
	})
	require.NoError(t, err)
	tx, err := conway.NewConwayTransactionFromCbor(built.TxCBOR)
	require.NoError(t, err)
	require.Len(t, tx.Body.TxCertificates, 2)
	// Compare cert bodies round-trip via CBOR
	for i, raw := range [][]byte{wrap1, wrap2} {
		got, err := cbor.Encode(tx.Body.TxCertificates[i])
		require.NoError(t, err)
		require.Equal(t, raw, got)
	}
}

func TestBuildRoundTripsThroughSign(t *testing.T) {
	chain := NewFakeChain()
	addr := "addr_test1wzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07s7prw5e"
	chain.UtxosMap[addr] = []UTxO{
		MakeUTxO(addr, "5555555555555555555555555555555555555555555555555555555555555555", 0, 30_000_000),
	}
	cred := makeStakeCredential(t, 0x33)
	cert := &lcommon.StakeRegistrationCertificate{
		CertType:        uint(lcommon.CertificateTypeStakeRegistration),
		StakeCredential: cred,
	}
	wrapBytes := encodeWrapper(t, cert, lcommon.CertificateTypeStakeRegistration)
	dir := t.TempDir()
	certFile := writeEnvelopeCert(t, dir, "stake.reg", "CertificateShelley", wrapBytes)
	ctx := context.Background()
	built, err := Build(ctx, chain, BuildOptions{
		ChangeAddress:    addr,
		CertificateFiles: []string{certFile},
		WitnessCount:     1,
	})
	require.NoError(t, err)
	// Write envelope to temp file and sign
	txFile := filepath.Join(dir, "tx.conway")
	envStr, err := bursa.WriteCborEnvelope(built.TxEnvelopeType, "Unwitnessed Tx", built.TxCBOR, txFile)
	require.NoError(t, err)
	require.NotEmpty(t, envStr)
	// Read back and ensure signable
	raw, envType, err := bursa.ReadTxInput([]byte(envStr), "")
	require.NoError(t, err)
	require.NotEmpty(t, raw)
	require.NotEmpty(t, envType)
	// Generate a deterministic key for signing
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	wallet, err := bursa.NewWallet(mnemonic, bursa.WithNetwork("preprod"))
	require.NoError(t, err)
	lk := &bursa.LoadedKey{
		Type:        wallet.PaymentSKey.Type,
		Description: wallet.PaymentSKey.Description,
	}
	// Load via parsing the key file bytes directly would be more involved;
	// instead use the wallet's payment extended skey via helper that creates LoadedKey from File
	// We can write the key to temp and load
	paymentSkeyJSON, err := json.Marshal(wallet.PaymentSKey)
	require.NoError(t, err)
	skeyFile := filepath.Join(dir, "payment.skey")
	require.NoError(t, os.WriteFile(skeyFile, paymentSkeyJSON, 0o600))
	loaded, err := bursa.LoadSecretKeyFromFile(skeyFile)
	require.NoError(t, err)
	signed, err := bursa.SignTransaction(raw, []*bursa.LoadedKey{loaded})
	require.NoError(t, err)
	require.NotEmpty(t, signed)
	_ = lk
}

func TestSubmitPassesBytesAndReportsRejection(t *testing.T) {
	chain := NewFakeChain()
	txBytes := []byte{0x84, 0x00}
	errRejection := errors.New("rejected: missing witness")
	chain.SubmitErr = errRejection
	ctx := context.Background()
	err := chain.SubmitTx(ctx, txBytes)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rejected")
	require.Empty(t, chain.Submitted)

	chain.SubmitErr = nil
	require.NoError(t, chain.SubmitTx(ctx, txBytes))
	require.Len(t, chain.Submitted, 1)
	require.Equal(t, txBytes, chain.Submitted[0])
}

func TestBuildTTLFromSlot(t *testing.T) {
	chain := NewFakeChain()
	addr := "addr_test1wzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07s7prw5e"
	chain.UtxosMap[addr] = []UTxO{
		MakeUTxO(addr, "6666666666666666666666666666666666666666666666666666666666666666", 0, 10_000_000),
	}
	chain.SlotVal = 123456
	ctx := context.Background()
	built, err := Build(ctx, chain, BuildOptions{
		ChangeAddress: addr,
		WitnessCount:  1,
	})
	require.NoError(t, err)
	tx, err := conway.NewConwayTransactionFromCbor(built.TxCBOR)
	require.NoError(t, err)
	require.Equal(t, uint64(123456+3600), tx.Body.Ttl)
	// Explicit TTL
	built2, err := Build(ctx, chain, BuildOptions{
		ChangeAddress: addr,
		WitnessCount:  1,
		TTL:           999999,
	})
	require.NoError(t, err)
	tx2, err := conway.NewConwayTransactionFromCbor(built2.TxCBOR)
	require.NoError(t, err)
	require.Equal(t, uint64(999999), tx2.Body.Ttl)
}

func TestBuildFeeMeetsMinFeeForWitnessedSize(t *testing.T) {
	chain := NewFakeChain()
	addr := "addr_test1wzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07s7prw5e"
	chain.UtxosMap[addr] = []UTxO{
		MakeUTxO(addr, "7777777777777777777777777777777777777777777777777777777777777777", 0, 100_000_000),
	}
	ctx := context.Background()
	for _, wc := range []uint{1, 2, 5} {
		built, err := Build(ctx, chain, BuildOptions{
			ChangeAddress: addr,
			WitnessCount:  wc,
		})
		require.NoError(t, err)
		tx, err := conway.NewConwayTransactionFromCbor(built.TxCBOR)
		require.NoError(t, err)
		estSize, err := bursa.EstimateWitnessedTxSize(built.TxCBOR, wc, 0)
		require.NoError(t, err)
		minFee, err := bursa.MinFee(estSize, *chain.PpFee)
		require.NoError(t, err)
		require.GreaterOrEqual(t, tx.Body.TxFee, minFee)
	}
}

func TestBuildInsufficientFunds(t *testing.T) {
	chain := NewFakeChain()
	addr := "addr_test1wzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07s7prw5e"
	chain.UtxosMap[addr] = []UTxO{
		MakeUTxO(addr, "8888888888888888888888888888888888888888888888888888888888888888", 0, 1_000_000),
	}
	// Legacy registration needs 2M deposit + fee > 1M => insufficient
	cred := makeStakeCredential(t, 0x44)
	cert := &lcommon.StakeRegistrationCertificate{
		CertType:        uint(lcommon.CertificateTypeStakeRegistration),
		StakeCredential: cred,
	}
	wrapBytes := encodeWrapper(t, cert, lcommon.CertificateTypeStakeRegistration)
	dir := t.TempDir()
	certFile := writeEnvelopeCert(t, dir, "stake.reg", "CertificateShelley", wrapBytes)
	ctx := context.Background()
	_, err := Build(ctx, chain, BuildOptions{
		ChangeAddress:    addr,
		CertificateFiles: []string{certFile},
		WitnessCount:     1,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "insufficient funds")
}

func TestBuildSkipsAssetsUTxOs(t *testing.T) {
	chain := NewFakeChain()
	addr := "addr_test1wzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07s7prw5e"
	adaUTxO := MakeUTxO(addr, "9999999999999999999999999999999999999999999999999999999999999999", 0, 10_000_000)
	assetUTxO := makeAssetUTxO(addr, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, 5_000_000)
	chain.UtxosMap[addr] = []UTxO{assetUTxO, adaUTxO}
	ctx := context.Background()
	built, err := Build(ctx, chain, BuildOptions{
		ChangeAddress: addr,
		WitnessCount:  1,
	})
	require.NoError(t, err)
	tx, err := conway.NewConwayTransactionFromCbor(built.TxCBOR)
	require.NoError(t, err)
	// Should only use adaUTxO, so inputs = 1
	require.Len(t, tx.Body.TxInputs.Items(), 1)
}

// helper for asset UTxO
type assetFakeOutput struct {
	address  lcommon.Address
	lovelace uint64
	assets   *lcommon.MultiAsset[lcommon.MultiAssetTypeOutput]
}

func (o *assetFakeOutput) Address() lcommon.Address                                  { return o.address }
func (o *assetFakeOutput) Amount() *big.Int                                          { return new(big.Int).SetUint64(o.lovelace) }
func (o *assetFakeOutput) Assets() *lcommon.MultiAsset[lcommon.MultiAssetTypeOutput] { return o.assets }
func (o *assetFakeOutput) Datum() *lcommon.Datum                                     { return nil }
func (o *assetFakeOutput) DatumHash() *lcommon.Blake2b256                            { return nil }
func (o *assetFakeOutput) Cbor() []byte                                              { return nil }
func (o *assetFakeOutput) Utxorpc() (*utxorpc.TxOutput, error)                       { return nil, nil }
func (o *assetFakeOutput) ScriptRef() lcommon.Script                                 { return nil }
func (o *assetFakeOutput) ToPlutusData() data.PlutusData                             { return nil }
func (o *assetFakeOutput) String() string                                            { return o.address.String() }

func makeAssetUTxO(addr string, txHashHex string, idx uint32, lovelace uint64) UTxO {
	var txID lcommon.Blake2b256
	b, _ := hex.DecodeString(txHashHex)
	copy(txID[:], b)
	input := shelley.ShelleyTransactionInput{TxId: txID, OutputIndex: idx}
	a, _ := lcommon.NewAddress(addr)
	policy := lcommon.Blake2b224{1, 2, 3}
	assetName := cbor.NewByteString([]byte("TOKEN"))
	ma := lcommon.NewMultiAsset[lcommon.MultiAssetTypeOutput](map[lcommon.Blake2b224]map[cbor.ByteString]*big.Int{
		policy: {assetName: big.NewInt(100)},
	})
	_ = ma
	return UTxO{
		Input:  input,
		Output: &assetFakeOutput{address: a, lovelace: lovelace, assets: &ma},
	}
}

func TestRefundLegacyStakeDeregistration(t *testing.T) {
	chain := NewFakeChain()
	addr := "addr_test1wzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07s7prw5e"
	chain.UtxosMap[addr] = []UTxO{
		MakeUTxO(addr, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0, 20_000_000),
	}
	cred := makeStakeCredential(t, 0x55)
	cert := &lcommon.StakeDeregistrationCertificate{
		CertType:        uint(lcommon.CertificateTypeStakeDeregistration),
		StakeCredential: cred,
	}
	wrapBytes := encodeWrapper(t, cert, lcommon.CertificateTypeStakeDeregistration)
	dir := t.TempDir()
	certFile := writeEnvelopeCert(t, dir, "stake.dereg", "CertificateShelley", wrapBytes)
	ctx := context.Background()
	built, err := Build(ctx, chain, BuildOptions{
		ChangeAddress:    addr,
		CertificateFiles: []string{certFile},
		WitnessCount:     1,
	})
	require.NoError(t, err)
	tx, err := conway.NewConwayTransactionFromCbor(built.TxCBOR)
	require.NoError(t, err)
	inSum := uint64(20_000_000)
	var outSum uint64
	for _, o := range tx.Body.TxOutputs {
		outSum += o.OutputAmount.Amount
	}
	refund := chain.PpExtra.KeyDeposit
	// sum(inputs) + refunds == sum(outputs) + fee + deposits
	require.Equal(t, inSum+refund, outSum+tx.Body.TxFee+uint64(0))
}

func TestRefundConwayDeregistration(t *testing.T) {
	chain := NewFakeChain()
	addr := "addr_test1wzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07s7prw5e"
	chain.UtxosMap[addr] = []UTxO{
		MakeUTxO(addr, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 0, 20_000_000),
	}
	cred := makeStakeCredential(t, 0x56)
	deregAmt := uint64(5_000_000)
	cert := &lcommon.DeregistrationCertificate{
		CertType:        uint(lcommon.CertificateTypeDeregistration),
		StakeCredential: cred,
		Amount:          deregAmt,
	}
	wrapBytes := encodeWrapper(t, cert, lcommon.CertificateTypeDeregistration)
	dir := t.TempDir()
	certFile := writeEnvelopeCert(t, dir, "stake.dereg.conway", "CertificateConway", wrapBytes)
	ctx := context.Background()
	built, err := Build(ctx, chain, BuildOptions{
		ChangeAddress:    addr,
		CertificateFiles: []string{certFile},
		WitnessCount:     1,
	})
	require.NoError(t, err)
	tx, err := conway.NewConwayTransactionFromCbor(built.TxCBOR)
	require.NoError(t, err)
	inSum := uint64(20_000_000)
	var outSum uint64
	for _, o := range tx.Body.TxOutputs {
		outSum += o.OutputAmount.Amount
	}
	require.Equal(t, inSum+deregAmt, outSum+tx.Body.TxFee+uint64(0))
}

func TestRefundDrepDeregistration(t *testing.T) {
	chain := NewFakeChain()
	addr := "addr_test1wzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07s7prw5e"
	chain.UtxosMap[addr] = []UTxO{
		MakeUTxO(addr, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddd0001", 0, 20_000_000),
	}
	cred := makeStakeCredential(t, 0x60)
	refundAmt := uint64(5_000_000)
	cert := &lcommon.DeregistrationDrepCertificate{
		CertType:       uint(lcommon.CertificateTypeDeregistrationDrep),
		DrepCredential: cred,
		Amount:         refundAmt,
	}
	wrapBytes := encodeWrapper(t, cert, lcommon.CertificateTypeDeregistrationDrep)
	dir := t.TempDir()
	certFile := writeEnvelopeCert(t, dir, "drep.dereg", "CertificateConway", wrapBytes)
	ctx := context.Background()
	built, err := Build(ctx, chain, BuildOptions{
		ChangeAddress:    addr,
		CertificateFiles: []string{certFile},
		WitnessCount:     1,
	})
	require.NoError(t, err)
	tx, err := conway.NewConwayTransactionFromCbor(built.TxCBOR)
	require.NoError(t, err)
	inSum := uint64(20_000_000)
	var outSum uint64
	for _, o := range tx.Body.TxOutputs {
		outSum += o.OutputAmount.Amount
	}
	// The DRep deposit refund counts on the consumed side:
	// sum(inputs) + refund == sum(outputs) + fee
	require.Equal(t, inSum+refundAmt, outSum+tx.Body.TxFee)
}

func TestRefundMixedRegistrationAndDeregistration(t *testing.T) {
	chain := NewFakeChain()
	addr := "addr_test1wzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07s7prw5e"
	chain.UtxosMap[addr] = []UTxO{
		MakeUTxO(addr, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", 0, 50_000_000),
	}
	credReg := makeStakeCredential(t, 0x57)
	credDereg := makeStakeCredential(t, 0x58)
	regCert := &lcommon.StakeRegistrationCertificate{
		CertType:        uint(lcommon.CertificateTypeStakeRegistration),
		StakeCredential: credReg,
	}
	deregCert := &lcommon.StakeDeregistrationCertificate{
		CertType:        uint(lcommon.CertificateTypeStakeDeregistration),
		StakeCredential: credDereg,
	}
	wrapReg := encodeWrapper(t, regCert, lcommon.CertificateTypeStakeRegistration)
	wrapDereg := encodeWrapper(t, deregCert, lcommon.CertificateTypeStakeDeregistration)
	dir := t.TempDir()
	f1 := writeEnvelopeCert(t, dir, "reg", "CertificateShelley", wrapReg)
	f2 := writeEnvelopeCert(t, dir, "dereg", "CertificateShelley", wrapDereg)
	ctx := context.Background()
	built, err := Build(ctx, chain, BuildOptions{
		ChangeAddress:    addr,
		CertificateFiles: []string{f1, f2},
		WitnessCount:     1,
	})
	require.NoError(t, err)
	tx, err := conway.NewConwayTransactionFromCbor(built.TxCBOR)
	require.NoError(t, err)
	inSum := uint64(50_000_000)
	var outSum uint64
	for _, o := range tx.Body.TxOutputs {
		outSum += o.OutputAmount.Amount
	}
	deposits := chain.PpExtra.KeyDeposit
	refunds := chain.PpExtra.KeyDeposit
	require.Equal(t, inSum+refunds, outSum+tx.Body.TxFee+deposits)
}

func TestPoolLookupError(t *testing.T) {
	chain := NewFakeChain()
	addr := "addr_test1wzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07s7prw5e"
	chain.UtxosMap[addr] = []UTxO{
		MakeUTxO(addr, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", 0, 10_000_000_000),
	}
	poolKey := make([]byte, 28)
	for i := range poolKey {
		poolKey[i] = byte(i)
	}
	poolCert := lcommon.PoolRegistrationCertificate{
		CertType:      uint(lcommon.CertificateTypePoolRegistration),
		Operator:      lcommon.PoolKeyHash(poolKey),
		VrfKeyHash:    lcommon.VrfKeyHash(make([]byte, 32)),
		Pledge:        1000000,
		Cost:          340000000,
		Margin:        lcommon.GenesisRat{Rat: big.NewRat(0, 1)},
		RewardAccount: lcommon.AddrKeyHash(make([]byte, 28)),
		PoolOwners:    []lcommon.AddrKeyHash{},
		Relays:        []lcommon.PoolRelay{},
	}
	_ = poolCert.SetRewardAccountCredential(lcommon.Credential{
		CredType:   lcommon.CredentialTypeAddrKeyHash,
		Credential: lcommon.CredentialHash(make([]byte, 28)),
	}, 0)
	wrapBytes := encodeWrapper(t, &poolCert, lcommon.CertificateTypePoolRegistration)
	dir := t.TempDir()
	certFile := writeEnvelopeCert(t, dir, "pool.cert", "CertificateConway", wrapBytes)
	chain.PoolRegistration = func(poolKeyHash []byte) (bool, error) {
		return false, errors.New("pool lookup failed")
	}
	ctx := context.Background()
	_, err := Build(ctx, chain, BuildOptions{
		ChangeAddress:    addr,
		CertificateFiles: []string{certFile},
		WitnessCount:     1,
	})
	require.Error(t, err)
}

func TestCoinSelectionDeterministicAndMinInputs(t *testing.T) {
	chain := NewFakeChain()
	addr := "addr_test1wzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07s7prw5e"
	// 20 UTxOs of 5 ADA each
	var utxos []UTxO
	for i := 0; i < 20; i++ {
		txh := make([]byte, 32)
		for j := range txh {
			txh[j] = byte(i + 1)
		}
		utxos = append(utxos, MakeUTxO(addr, hex.EncodeToString(txh), 0, 5_000_000))
	}
	chain.UtxosMap[addr] = utxos
	// Make each UTxO small so need multiple
	// recreate with smaller amounts
	utxos = make([]UTxO, 0, 20)
	for i := 0; i < 20; i++ {
		txh := make([]byte, 32)
		for j := range txh {
			txh[j] = byte(i + 1)
		}
		utxos = append(utxos, MakeUTxO(addr, hex.EncodeToString(txh), 0, 1_500_000))
	}
	chain.UtxosMap[addr] = utxos
	// Add registration to need deposits
	cred := makeStakeCredential(t, 0x99)
	cert := &lcommon.StakeRegistrationCertificate{
		CertType:        uint(lcommon.CertificateTypeStakeRegistration),
		StakeCredential: cred,
	}
	wrapBytes := encodeWrapper(t, cert, lcommon.CertificateTypeStakeRegistration)
	dir := t.TempDir()
	certFile := writeEnvelopeCert(t, dir, "stake.reg", "CertificateShelley", wrapBytes)
	ctx := context.Background()
	// Need ~6 ADA - should take smallest prefix covering needs (deterministic order largest first)
	built, err := Build(ctx, chain, BuildOptions{
		ChangeAddress:    addr,
		CertificateFiles: []string{certFile},
		WitnessCount:     1,
	})
	require.NoError(t, err)
	tx, err := conway.NewConwayTransactionFromCbor(built.TxCBOR)
	require.NoError(t, err)
	require.Equal(t, 2, len(tx.Body.TxInputs.Items()))

	// Two builds with UTxOs supplied in different orders produce byte-identical bodies
	chain2 := NewFakeChain()
	chain2.PpFee = chain.PpFee
	chain2.PpExtra = chain.PpExtra
	chain2.SlotVal = chain.SlotVal
	var utxosRev []UTxO
	for i := len(utxos) - 1; i >= 0; i-- {
		utxosRev = append(utxosRev, utxos[i])
	}
	chain2.UtxosMap[addr] = utxosRev
	built2, err := Build(ctx, chain2, BuildOptions{
		ChangeAddress:    addr,
		CertificateFiles: []string{certFile},
		WitnessCount:     1,
	})
	require.NoError(t, err)
	require.Equal(t, built.TxCBOR, built2.TxCBOR)
}

func TestCoinSelectionExceedsMaxTxSize(t *testing.T) {
	chain := NewFakeChain()
	addr := "addr_test1wzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07s7prw5e"
	// Make many large inputs
	var utxos []UTxO
	for i := 0; i < 200; i++ {
		txh := make([]byte, 32)
		for j := range txh {
			txh[j] = byte(i%251 + 1)
		}
		utxos = append(utxos, MakeUTxO(addr, hex.EncodeToString(txh), uint32(i%10), 10_000_000))
	}
	chain.UtxosMap[addr] = utxos
	if chain.PpExtra != nil {
		chain.PpExtra.MaxTxSize = 1000 // very small
	}
	ctx := context.Background()
	_, err := Build(ctx, chain, BuildOptions{
		ChangeAddress: addr,
		WitnessCount:  10,
	})
	require.Error(t, err)
}

func TestFeeIndependentCalculationAndBoundaries(t *testing.T) {
	chain := NewFakeChain()
	addr := "addr_test1wzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07s7prw5e"
	chain.UtxosMap[addr] = []UTxO{
		MakeUTxO(addr, "1111111111111111111111111111111111111111111111111111111111111112", 0, 100_000_000),
	}
	ctx := context.Background()
	built, err := Build(ctx, chain, BuildOptions{
		ChangeAddress: addr,
		WitnessCount:  3,
	})
	require.NoError(t, err)
	tx, err := conway.NewConwayTransactionFromCbor(built.TxCBOR)
	require.NoError(t, err)
	estSize, err := bursa.EstimateWitnessedTxSize(built.TxCBOR, 3, 0)
	require.NoError(t, err)
	// compute min fee independently: MinFeeA * (len(final body bytes) + witness overhead for --witness-count real vkey witnesses) + MinFeeB
	// EstimateWitnessedTxSize already includes witness overhead; bursa.MinFee uses protocol params
	minFee := chain.PpExtra.MinFeeA*uint64(estSize) + chain.PpExtra.MinFeeB
	require.GreaterOrEqual(t, tx.Body.TxFee, minFee)

	// case where the change crosses 65536 lovelace
	chain2 := NewFakeChain()
	chain2.UtxosMap[addr] = []UTxO{
		MakeUTxO(addr, "2222222222222222222222222222222222222222222222222222222222222223", 0, 200_000),
	}
	built2, err := Build(ctx, chain2, BuildOptions{
		ChangeAddress: addr,
		WitnessCount:  1,
	})
	// might be insufficient depending; try to make change cross 65536
	if err == nil {
		// just ensure fee valid
		tx2, err := conway.NewConwayTransactionFromCbor(built2.TxCBOR)
		require.NoError(t, err)
		est2, _ := bursa.EstimateWitnessedTxSize(built2.TxCBOR, 1, 0)
		minFee2 := chain2.PpExtra.MinFeeA*uint64(est2) + chain2.PpExtra.MinFeeB
		require.GreaterOrEqual(t, tx2.Body.TxFee, minFee2)
	}

	// case crossing 2^32 lovelace
	chain3 := NewFakeChain()
	chain3.UtxosMap[addr] = []UTxO{
		MakeUTxO(addr, "3333333333333333333333333333333333333333333333333333333333333334", 0, 5_000_000_000),
	}
	built3, err := Build(ctx, chain3, BuildOptions{
		ChangeAddress: addr,
		WitnessCount:  1,
	})
	require.NoError(t, err)
	tx3, err := conway.NewConwayTransactionFromCbor(built3.TxCBOR)
	require.NoError(t, err)
	est3, _ := bursa.EstimateWitnessedTxSize(built3.TxCBOR, 1, 0)
	minFee3 := chain3.PpExtra.MinFeeA*uint64(est3) + chain3.PpExtra.MinFeeB
	require.GreaterOrEqual(t, tx3.Body.TxFee, minFee3)
}

func TestChangeBelowMinUTxO(t *testing.T) {
	chain := NewFakeChain()
	addr := "addr_test1wzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07s7prw5e"
	// Small UTxO that would leave change below min UTxO
	chain.UtxosMap[addr] = []UTxO{
		MakeUTxO(addr, "4444444444444444444444444444444444444444444444444444444444444445", 0, 1_000_000),
	}
	if chain.PpExtra != nil {
		chain.PpExtra.CoinsPerUTxOByte = 4310
	}
	ctx := context.Background()
	_, err := Build(ctx, chain, BuildOptions{
		ChangeAddress: addr,
		WitnessCount:  1,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "minimum")
}

func TestBodyWithoutWithdrawalsHasNoWithdrawalsKey(t *testing.T) {
	chain := NewFakeChain()
	addr := "addr_test1wzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07s7prw5e"
	chain.UtxosMap[addr] = []UTxO{
		MakeUTxO(addr, "5555555555555555555555555555555555555555555555555555555555555556", 0, 10_000_000),
	}
	ctx := context.Background()
	built, err := Build(ctx, chain, BuildOptions{
		ChangeAddress: addr,
		WitnessCount:  1,
	})
	require.NoError(t, err)
	// Decode the body map and check keys
	var bodyMap cbor.Map
	// Try to decode the ConwayTransaction body
	tx, err := conway.NewConwayTransactionFromCbor(built.TxCBOR)
	require.NoError(t, err)
	// Re-encode body to inspect CBOR map structure
	bodyCbor, err := cbor.Encode(tx.Body)
	require.NoError(t, err)
	if _, err := cbor.Decode(bodyCbor, &bodyMap); err == nil {
		// In CBOR map with int keys (keyasint), withdrawals is key 5
		_, hasWithdrawals := bodyMap[uint(5)]
		require.False(t, hasWithdrawals)
	} else {
		// Fallback: check that withdrawals is nil/empty
		require.Nil(t, tx.Body.TxWithdrawals)
	}
}

func TestSelectionAddsInputWhenChangeBelowMinUTxO(t *testing.T) {
	chain := NewFakeChain()
	chain.PpExtra.CoinsPerUTxOByte = 4310
	addr := "addr_test1wzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07s7prw5e"
	// The 1 ADA input alone covers the fee but leaves change below the
	// minimum UTxO; adding the 0.3 ADA input fixes that.
	chain.UtxosMap[addr] = []UTxO{
		MakeUTxO(addr, "5555555555555555555555555555555555555555555555555555555555555555", 0, 1_000_000),
		MakeUTxO(addr, "6666666666666666666666666666666666666666666666666666666666666666", 0, 300_000),
	}
	built, err := Build(context.Background(), chain, BuildOptions{
		ChangeAddress: addr,
		WitnessCount:  1,
	})
	require.NoError(t, err)
	tx, err := conway.NewConwayTransactionFromCbor(built.TxCBOR)
	require.NoError(t, err)
	require.Len(t, tx.Inputs(), 2)
	require.Len(t, tx.Outputs(), 1)
	require.Equal(t, uint64(1_300_000), tx.Outputs()[0].Amount().Uint64()+tx.Fee().Uint64())
}

func TestBuildWithPoolVote(t *testing.T) {
	chain := NewFakeChain()
	addr := "addr_test1wzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07s7prw5e"
	chain.UtxosMap[addr] = []UTxO{
		MakeUTxO(addr, "0000000000000000000000000000000000000000000000000000000000000001", 0, 10_000_000),
	}
	poolKey := make([]byte, 28)
	for i := range poolKey {
		poolKey[i] = byte(i + 1)
	}
	actionTxID := make([]byte, 32)
	for i := range actionTxID {
		actionTxID[i] = byte(i + 2)
	}

	tests := []struct {
		name       string
		vote       uint8
		index      uint32
		withAnchor bool
	}{
		{"yes_index3", lcommon.GovVoteYes, 3, false},
		{"no_index3", lcommon.GovVoteNo, 3, false},
		{"abstain_index3", lcommon.GovVoteAbstain, 3, false},
		{"yes_with_anchor", lcommon.GovVoteYes, 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var anchor *lcommon.GovAnchor
			if tt.withAnchor {
				a, err := lcommon.NewGovAnchor("https://example.com/vote.json", make([]byte, 32))
				for i := range a.DataHash {
					a.DataHash[i] = byte(i)
				}
				require.NoError(t, err)
				anchor = &a
			}
			var poolKeyArr [28]byte
			copy(poolKeyArr[:], poolKey)
			var actionTxArr [32]byte
			copy(actionTxArr[:], actionTxID)
			ctx := context.Background()
			built, err := Build(ctx, chain, BuildOptions{
				ChangeAddress: addr,
				WitnessCount:  1,
				Vote: &PoolVote{
					PoolKeyHash: poolKeyArr,
					ActionTxId:  actionTxArr,
					ActionIndex: tt.index,
					Vote:        tt.vote,
					Anchor:      anchor,
				},
			})
			require.NoError(t, err)
			tx, err := conway.NewConwayTransactionFromCbor(built.TxCBOR)
			require.NoError(t, err)
			require.Len(t, tx.Body.TxVotingProcedures, 1)
			for voter, actions := range tx.Body.TxVotingProcedures {
				require.Equal(t, lcommon.VoterTypeStakingPoolKeyHash, voter.Type)
				require.Equal(t, poolKeyArr, [28]byte(voter.Hash))
				require.Len(t, actions, 1)
				for aid, proc := range actions {
					require.Equal(t, actionTxArr[:], aid.TransactionId[:])
					require.Equal(t, tt.index, uint32(aid.GovActionIdx))
					require.Equal(t, tt.vote, proc.Vote)
					if tt.withAnchor {
						require.NotNil(t, proc.Anchor)
						require.Equal(t, anchor.Url, proc.Anchor.Url)
						require.Equal(t, anchor.DataHash, proc.Anchor.DataHash)
					} else {
						require.Nil(t, proc.Anchor)
					}
				}
			}
		})
	}
}

func TestBuildWithVoteAndPoolRegistration(t *testing.T) {
	chain := NewFakeChain()
	addr := "addr_test1wzt7vzv8fwn43jw04aas85pzxspdfkg5qh5m0ljs82vh07s7prw5e"
	chain.UtxosMap[addr] = []UTxO{
		MakeUTxO(addr, "0000000000000000000000000000000000000000000000000000000000000003", 0, 10_000_000_000),
	}
	poolKey := make([]byte, 28)
	for i := range poolKey {
		poolKey[i] = byte(i)
	}
	vrfKey := make([]byte, 32)
	rewardAcct := make([]byte, 28)
	poolCert := lcommon.PoolRegistrationCertificate{
		CertType:      uint(lcommon.CertificateTypePoolRegistration),
		Operator:      lcommon.PoolKeyHash(poolKey),
		VrfKeyHash:    lcommon.VrfKeyHash(vrfKey),
		Pledge:        1000000,
		Cost:          340000000,
		Margin:        lcommon.GenesisRat{Rat: big.NewRat(0, 1)},
		RewardAccount: lcommon.AddrKeyHash(rewardAcct),
		PoolOwners:    []lcommon.AddrKeyHash{},
		Relays:        []lcommon.PoolRelay{},
	}
	_ = poolCert.SetRewardAccountCredential(lcommon.Credential{
		CredType:   lcommon.CredentialTypeAddrKeyHash,
		Credential: lcommon.CredentialHash(rewardAcct),
	}, 0)
	wrapBytes := encodeWrapper(t, &poolCert, lcommon.CertificateTypePoolRegistration)
	dir := t.TempDir()
	certFile := writeEnvelopeCert(t, dir, "pool.cert", "CertificateConway", wrapBytes)

	var poolKeyArr [28]byte
	copy(poolKeyArr[:], poolKey)
	var actionTxArr [32]byte
	for i := range actionTxArr {
		actionTxArr[i] = 0xaa
	}
	chain.PoolRegistered = map[string]bool{}
	ctx := context.Background()
	built, err := Build(ctx, chain, BuildOptions{
		ChangeAddress:    addr,
		CertificateFiles: []string{certFile},
		WitnessCount:     1,
		Vote: &PoolVote{
			PoolKeyHash: poolKeyArr,
			ActionTxId:  actionTxArr,
			ActionIndex: 0,
			Vote:        lcommon.GovVoteYes,
		},
	})
	require.NoError(t, err)
	tx, err := conway.NewConwayTransactionFromCbor(built.TxCBOR)
	require.NoError(t, err)
	require.Len(t, tx.Body.TxCertificates, 1)
	require.Len(t, tx.Body.TxVotingProcedures, 1)
}
