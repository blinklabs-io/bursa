// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package poolops

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"strings"
	"testing"

	"github.com/Salvionied/apollo/v2/backend"
	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/ui/internal/keystore"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/conway"
	"github.com/blinklabs-io/gouroboros/ledger/shelley"
	"github.com/blinklabs-io/plutigo/data"
	utxorpc "github.com/utxorpc/go-codegen/utxorpc/v1alpha/cardano"
)

// fakeKeystore unlocks to a fixed mnemonic, or returns ErrDecryptFailed when the
// password does not match — mirroring the real keystore's wrong-password path.
type fakeKeystore struct {
	mnemonic string
	password string
	exists   bool
}

func (f *fakeKeystore) Exists() bool { return f.exists }

func (f *fakeKeystore) Unlock(password string) ([]byte, error) {
	if password != f.password {
		return nil, keystore.ErrDecryptFailed
	}
	return []byte(f.mnemonic), nil
}

func (f *fakeKeystore) UnlockFor(_ string, password string) ([]byte, error) {
	return f.Unlock(password)
}

func newSeedService(t *testing.T) (*Service, *wallet.Account) {
	t.Helper()
	acct, err := wallet.Derive(testMnemonic, "preview", 2)
	if err != nil {
		t.Fatalf("derive account: %v", err)
	}
	ks := &fakeKeystore{mnemonic: testMnemonic, password: "spend-password", exists: true}
	s := NewService(nil, ks, fakeGenesis{}, fakeTip{slot: 259200})
	s.SetAccount("test-wallet-id", acct)
	return s, acct
}

type fakeGenesis struct {
	err     error
	genesis *Genesis
}

func (f fakeGenesis) Genesis(_ context.Context) (Genesis, error) {
	if f.err != nil {
		return Genesis{}, f.err
	}
	if f.genesis != nil {
		return *f.genesis, nil
	}
	return Genesis{SlotsPerKESPeriod: 129600, MaxKESEvolutions: 62, EpochLength: 432000}, nil
}

type fakeTip struct{ slot uint64 }

func (f fakeTip) TipSlot() (uint64, error) { return f.slot, nil }

const differentMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

type genericOnlyKeystore struct {
	mnemonic    string
	unlockCalls int
}

func (g *genericOnlyKeystore) Exists() bool { return true }

func (g *genericOnlyKeystore) Unlock(string) ([]byte, error) {
	g.unlockCalls++
	return []byte(g.mnemonic), nil
}

type walletBoundKeystore struct {
	genericMnemonic string
	mnemonicByID    map[string]string
	unlockCalls     int
	unlockForIDs    []string
}

func (w *walletBoundKeystore) Exists() bool { return true }

func (w *walletBoundKeystore) Unlock(string) ([]byte, error) {
	w.unlockCalls++
	return []byte(w.genericMnemonic), nil
}

func (w *walletBoundKeystore) UnlockFor(id, _ string) ([]byte, error) {
	w.unlockForIDs = append(w.unlockForIDs, id)
	mnemonic, ok := w.mnemonicByID[id]
	if !ok {
		return nil, keystore.ErrDecryptFailed
	}
	return []byte(mnemonic), nil
}

type retirementFakeChain struct {
	utxos      map[string][]lcommon.Utxo
	pp         backend.ProtocolParameters
	submitHash lcommon.Blake2b256
	submitCbor []byte
}

func newRetirementFakeChain(addr string, lovelace uint64) *retirementFakeChain {
	var h lcommon.Blake2b256
	b, _ := hex.DecodeString("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	copy(h[:], b)

	fc := &retirementFakeChain{
		utxos: map[string][]lcommon.Utxo{},
		pp: backend.ProtocolParameters{
			MinFeeConstant:    155381,
			MinFeeCoefficient: 44,
			MaxTxSize:         16384,
			CoinsPerUtxoByte:  "4310",
			KeyDeposits:       "2000000",
			PoolDeposits:      "500000000",
		},
		submitHash: h,
	}
	fc.addUTxO(addr, lovelace, "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", 0)
	return fc
}

func (fc *retirementFakeChain) addUTxO(addrStr string, lovelace uint64, txHashHex string, outIdx uint32) {
	var txID lcommon.Blake2b256
	b, _ := hex.DecodeString(txHashHex)
	copy(txID[:], b)
	addr, _ := lcommon.NewAddress(addrStr)
	fc.utxos[addrStr] = append(fc.utxos[addrStr], lcommon.Utxo{
		Id:     shelley.ShelleyTransactionInput{TxId: txID, OutputIndex: outIdx},
		Output: &retirementFakeOutput{address: addr, lovelace: lovelace},
	})
}

func (fc *retirementFakeChain) ProtocolParams() (backend.ProtocolParameters, error) {
	return fc.pp, nil
}

func (fc *retirementFakeChain) GenesisParams() (backend.GenesisParameters, error) {
	return backend.GenesisParameters{NetworkMagic: 1}, nil
}

func (fc *retirementFakeChain) NetworkId() uint8 { return 0 }

func (fc *retirementFakeChain) CurrentEpoch() (uint64, error) { return 500, nil }

func (fc *retirementFakeChain) MaxTxFee() (uint64, error) {
	return backend.ComputeMaxTxFee(fc.pp)
}

func (fc *retirementFakeChain) Tip() (uint64, error) { return 10_000_000, nil }

func (fc *retirementFakeChain) Utxos(address lcommon.Address) ([]lcommon.Utxo, error) {
	return fc.utxos[address.String()], nil
}

func (fc *retirementFakeChain) SubmitTx(tx []byte) (lcommon.Blake2b256, error) {
	fc.submitCbor = append(fc.submitCbor[:0], tx...)
	return fc.submitHash, nil
}

func (fc *retirementFakeChain) EvaluateTx([]byte, []lcommon.Utxo) (map[lcommon.RedeemerKey]lcommon.ExUnits, error) {
	return nil, nil
}

func (fc *retirementFakeChain) UtxoByRef(txHash lcommon.Blake2b256, index uint32) (*lcommon.Utxo, error) {
	for _, utxos := range fc.utxos {
		for _, u := range utxos {
			if u.Id.Id() == txHash && u.Id.Index() == index {
				cp := u
				return &cp, nil
			}
		}
	}
	return nil, nil
}

func (fc *retirementFakeChain) ScriptCbor(lcommon.Blake2b224) ([]byte, error) {
	return nil, nil
}

type retirementFakeOutput struct {
	address  lcommon.Address
	lovelace uint64
}

func (o *retirementFakeOutput) Address() lcommon.Address { return o.address }
func (o *retirementFakeOutput) Amount() *big.Int         { return new(big.Int).SetUint64(o.lovelace) }
func (o *retirementFakeOutput) Assets() *lcommon.MultiAsset[lcommon.MultiAssetTypeOutput] {
	return nil
}
func (o *retirementFakeOutput) Datum() *lcommon.Datum               { return nil }
func (o *retirementFakeOutput) DatumHash() *lcommon.Blake2b256      { return nil }
func (o *retirementFakeOutput) Cbor() []byte                        { return nil }
func (o *retirementFakeOutput) Utxorpc() (*utxorpc.TxOutput, error) { return nil, nil }
func (o *retirementFakeOutput) ScriptRef() lcommon.Script           { return nil }
func (o *retirementFakeOutput) ToPlutusData() data.PlutusData       { return nil }
func (o *retirementFakeOutput) String() string                      { return o.address.String() }

// TestServiceCredentials checks credential derivation through the keystore and
// the wrong-password and no-wallet error paths.
func TestServiceCredentials(t *testing.T) {
	s, _ := newSeedService(t)
	creds, err := s.Credentials("spend-password")
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	if creds.Network != "preview" || creds.PoolID == "" {
		t.Fatalf("unexpected credentials: %+v", creds)
	}

	if _, err := s.Credentials("wrong"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password: got %v, want ErrWrongPassword", err)
	}

	empty := NewService(nil, &fakeKeystore{password: "x"}, nil, nil)
	if _, err := empty.Credentials("x"); !errors.Is(err, ErrNoWallet) {
		t.Fatalf("no wallet: got %v, want ErrNoWallet", err)
	}
}

func TestServiceWalletBoundUnlockRequiresUnlockFor(t *testing.T) {
	acct, err := wallet.Derive(testMnemonic, "preview", 2)
	if err != nil {
		t.Fatalf("derive account: %v", err)
	}
	ks := &genericOnlyKeystore{mnemonic: testMnemonic}
	s := NewService(nil, ks, nil, nil)
	s.SetAccount("wallet-a", acct)

	if _, err := s.Credentials("pw"); err == nil {
		t.Fatal("Credentials with wallet-bound generic keystore succeeded, want error")
	} else if !strings.Contains(err.Error(), "UnlockFor") {
		t.Fatalf("Credentials error = %v, want UnlockFor support error", err)
	}
	if ks.unlockCalls != 0 {
		t.Fatalf("generic Unlock calls = %d, want 0", ks.unlockCalls)
	}
}

func TestServiceCredentialsUseWalletBoundSeed(t *testing.T) {
	acct, err := wallet.Derive(testMnemonic, "preview", 2)
	if err != nil {
		t.Fatalf("derive account: %v", err)
	}
	ks := &walletBoundKeystore{
		genericMnemonic: differentMnemonic,
		mnemonicByID:    map[string]string{"wallet-a": testMnemonic},
	}
	s := NewService(nil, ks, nil, nil)
	s.SetAccount("wallet-a", acct)

	creds, err := s.Credentials("pw")
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	want, err := deriveCredentials(mustRoot(t), "preview", 0, 0, 0)
	if err != nil {
		t.Fatalf("derive want credentials: %v", err)
	}
	rootB, err := bursa.GetRootKeyFromMnemonic(differentMnemonic, "")
	if err != nil {
		t.Fatalf("root B: %v", err)
	}
	other, err := deriveCredentials(rootB, "preview", 0, 0, 0)
	if err != nil {
		t.Fatalf("derive other credentials: %v", err)
	}
	if creds.PoolID != want.PoolID {
		t.Fatalf("pool ID = %q, want wallet-bound %q", creds.PoolID, want.PoolID)
	}
	if creds.PoolID == other.PoolID {
		t.Fatal("pool ID matched generic unlock mnemonic; wallet-bound seed was not used")
	}
	if ks.unlockCalls != 0 {
		t.Fatalf("generic Unlock calls = %d, want 0", ks.unlockCalls)
	}
	if len(ks.unlockForIDs) != 1 || ks.unlockForIDs[0] != "wallet-a" {
		t.Fatalf("UnlockFor ids = %v, want [wallet-a]", ks.unlockForIDs)
	}
}

// TestServiceKESPeriod checks the KES period is tip/slotsPerKESPeriod and that
// a genesis error propagates.
func TestServiceKESPeriod(t *testing.T) {
	s, _ := newSeedService(t)
	info, err := s.KESPeriod(context.Background())
	if err != nil {
		t.Fatalf("KESPeriod: %v", err)
	}
	if info.CurrentPeriod != 2 { // 259200 / 129600
		t.Fatalf("current period = %d, want 2", info.CurrentPeriod)
	}
	if info.SlotsPerKESPeriod != 129600 || info.MaxKESEvolutions != 62 {
		t.Fatalf("genesis passthrough wrong: %+v", info)
	}

	bad := NewService(nil, &fakeKeystore{}, fakeGenesis{err: errors.New("boom")}, fakeTip{})
	if _, err := bad.KESPeriod(context.Background()); err == nil {
		t.Fatal("expected KESPeriod error when genesis fails")
	}
}

func TestServiceKESPeriodRejectsNegativeGenesis(t *testing.T) {
	cases := []Genesis{
		{SlotsPerKESPeriod: -1, MaxKESEvolutions: 62},
		{SlotsPerKESPeriod: 129600, MaxKESEvolutions: -1},
	}
	for _, g := range cases {
		s := NewService(nil, &fakeKeystore{}, fakeGenesis{genesis: &g}, fakeTip{slot: 1})
		if _, err := s.KESPeriod(context.Background()); err == nil {
			t.Fatalf("KESPeriod(%+v) expected error", g)
		}
	}
}

// TestServiceIssueAndRotateOpCert checks an issued opcert verifies against the
// cold vkey, and that rotation derives a new KES key + bumps the issue counter.
func TestServiceIssueOpCert(t *testing.T) {
	s, _ := newSeedService(t)
	creds, err := s.Credentials("spend-password")
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	coldVkey, _ := hex.DecodeString(creds.Cold.VKeyHex)

	opcert, err := s.IssueOpCert("spend-password", 0, 5, 2)
	if err != nil {
		t.Fatalf("IssueOpCert: %v", err)
	}
	if opcert.IssueNumber != 5 || opcert.KesPeriod != 2 {
		t.Fatalf("issue/period = %d/%d, want 5/2", opcert.IssueNumber, opcert.KesPeriod)
	}
	// The opcert ColdSignature must verify against the cold vkey over the
	// OCertSignable representation (kesVkey || issue || period, counters
	// big-endian uint64) — what gouroboros' CreateOpCert now signs.
	kesVkey, _ := hex.DecodeString(opcert.KesVKeyHex)
	sig, _ := hex.DecodeString(opcert.ColdSignatureHex)
	payload := lcommon.OpCertSignableBytes(kesVkey, uint64(5), uint64(2))
	if !ed25519.Verify(coldVkey, payload, sig) {
		t.Fatal("issued opcert does not verify against the cold vkey")
	}

	if _, err := s.IssueOpCert("wrong", 0, 5, 2); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password: got %v", err)
	}
}

func TestServiceRotateKES(t *testing.T) {
	s, _ := newSeedService(t)
	// Rotation: new KES index 1, previous issue 3 → new issue 4.
	rotated, err := s.RotateKES("spend-password", 1, 3, 5)
	if err != nil {
		t.Fatalf("RotateKES: %v", err)
	}
	if rotated.IssueNumber != 4 {
		t.Fatalf("rotated issue number = %d, want 4 (prev 3 + 1)", rotated.IssueNumber)
	}
	if rotated.KESIndex != 1 {
		t.Fatalf("rotated KES index = %d, want 1", rotated.KESIndex)
	}
	// The rotated opcert must use the KES key at index 1 (different from index 0).
	idx0, err := s.IssueOpCert("spend-password", 0, 4, 5)
	if err != nil {
		t.Fatalf("IssueOpCert: %v", err)
	}
	if rotated.KesVKeyHex == idx0.KesVKeyHex {
		t.Fatal("rotated KES vkey equals index-0 vkey; rotation did not change keys")
	}
}

func TestServiceRotateKESRejectsIssueNumberOverflow(t *testing.T) {
	s, _ := newSeedService(t)

	_, err := s.RotateKES("spend-password", 1, math.MaxUint64, 5)
	if err == nil {
		t.Fatal("RotateKES accepted an issue number that would overflow")
	}
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("RotateKES error = %v, want ErrInvalidRequest", err)
	}
	if !strings.Contains(err.Error(), "issue number overflow") {
		t.Fatalf("RotateKES error = %q, want issue number overflow", err)
	}
}

func TestServiceRotateKESAcceptsMaxMinusOne(t *testing.T) {
	s, _ := newSeedService(t)

	rotated, err := s.RotateKES("spend-password", 1, math.MaxUint64-1, 5)
	if err != nil {
		t.Fatalf("RotateKES: %v", err)
	}
	if rotated.IssueNumber != math.MaxUint64 {
		t.Fatalf("issue number = %d, want %d", rotated.IssueNumber, uint64(math.MaxUint64))
	}
}

// TestServiceRotateKESRejectionKeepsState checks a rejected rotation returns no
// certificate and leaves the wallet binding and the certificate the same
// inputs produce unchanged.
func TestServiceRotateKESRejectionKeepsState(t *testing.T) {
	s, _ := newSeedService(t)
	before, err := s.IssueOpCert("spend-password", 0, 5, 7)
	if err != nil {
		t.Fatalf("IssueOpCert: %v", err)
	}
	walletID, acct := s.currentBinding()

	got, err := s.RotateKES("spend-password", 1, math.MaxUint64, 7)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("RotateKES error = %v, want ErrInvalidRequest", err)
	}
	if got != (OpCert{}) {
		t.Fatalf("rejected rotation returned a certificate: %+v", got)
	}

	after, err := s.IssueOpCert("spend-password", 0, 5, 7)
	if err != nil {
		t.Fatalf("IssueOpCert after rejection: %v", err)
	}
	if after != before {
		t.Fatalf("certificate changed across a rejected rotation:\n before %+v\n after  %+v", before, after)
	}
	walletIDAfter, acctAfter := s.currentBinding()
	if walletIDAfter != walletID || acctAfter != acct {
		t.Fatal("wallet binding changed across a rejected rotation")
	}
}

// TestServiceBuildRegistrationFromSeed checks the seed path builds a cert whose
// pool ID matches the derived credentials and defaults the reward account to the
// wallet's stake address.
func TestServiceBuildRegistrationFromSeed(t *testing.T) {
	s, acct := newSeedService(t)
	creds, err := s.Credentials("spend-password")
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	p := RegistrationParams{Pledge: 1_000_000, Cost: 340_000_000, MarginNum: 1, MarginDenom: 50}
	res, err := s.BuildRegistrationFromSeed("spend-password", p)
	if err != nil {
		t.Fatalf("BuildRegistrationFromSeed: %v", err)
	}
	if res.PoolID != creds.PoolID {
		t.Fatalf("pool ID %q != %q", res.PoolID, creds.PoolID)
	}
	// reward account defaults to the wallet stake address — decode the cert CBOR and
	// confirm the embedded reward-account bytes match the account's stake address.
	raw, _ := hex.DecodeString(res.CBORHex)
	var arr []cbor.RawMessage
	if _, err := cbor.Decode(raw, &arr); err != nil {
		t.Fatalf("decode cert: %v", err)
	}
	if len(arr) < 7 {
		t.Fatalf("cert has %d fields, want at least 7", len(arr))
	}
	var reward []byte
	_, _ = cbor.Decode(arr[6], &reward)
	if len(reward) != 29 {
		t.Fatalf("default reward account len = %d, want 29", len(reward))
	}
	// Confirm the embedded bytes match acct.StakeAddress.
	wantAddr, err := lcommon.NewAddress(acct.StakeAddress)
	if err != nil {
		t.Fatalf("parse stake address: %v", err)
	}
	wantBytes, err := wantAddr.Bytes()
	if err != nil {
		t.Fatalf("stake address bytes: %v", err)
	}
	if !bytes.Equal(reward, wantBytes) {
		t.Fatalf("reward account bytes mismatch: got %x, want %x", reward, wantBytes)
	}
}

func TestResolveRewardAccountRejectsNonRewardAddress(t *testing.T) {
	s, acct := newSeedService(t)
	_, err := s.resolveRewardAccount(RegistrationParams{RewardAddress: acct.ReceiveAddresses[0]}, acct)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("resolveRewardAccount base address error = %v, want ErrInvalidRequest", err)
	}
}

func TestBuildRegistrationRejectsMetadataHashWithoutURL(t *testing.T) {
	s, _ := newSeedService(t)
	_, err := s.BuildRegistrationFromSeed("spend-password", RegistrationParams{
		Pledge:       1,
		Cost:         1,
		MarginNum:    0,
		MarginDenom:  1,
		MetadataHash: strings.Repeat("ab", 32),
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("BuildRegistrationFromSeed metadata hash without URL error = %v, want ErrInvalidRequest", err)
	}
}

// TestServiceAirGapRegistration checks the air-gap path builds a registration
// cert from an imported cold vkey + VRF hash without any keystore.
func TestServiceAirGapRegistration(t *testing.T) {
	// Service with no keystore (offline-only).
	acct, _ := wallet.Derive(testMnemonic, "preview", 2)
	s := NewService(nil, nil, nil, nil)
	s.SetAccount("test-wallet-id", acct)

	creds, _ := deriveCredentials(mustRoot(t), "preview", 0, 0, 0)
	p := AirGapRegistrationParams{
		RegistrationParams: RegistrationParams{
			Pledge: 1, Cost: 1, MarginNum: 0, MarginDenom: 1,
			ColdVKeyHex: creds.Cold.VKeyHex,
		},
		VRFKeyHashHex: creds.VRF.HashHex,
	}
	res, err := s.BuildRegistrationAirGap(p)
	if err != nil {
		t.Fatalf("BuildRegistrationAirGap: %v", err)
	}
	if res.PoolID != creds.PoolID {
		t.Fatalf("air-gap pool ID %q != %q", res.PoolID, creds.PoolID)
	}
}

// TestServicePoolIDFromColdVKey checks the air-gap import returns matching
// bech32 + hex IDs.
func TestServicePoolIDFromColdVKey(t *testing.T) {
	s := NewService(nil, nil, nil, nil)
	creds, _ := deriveCredentials(mustRoot(t), "preview", 0, 0, 0)
	id, idHex, err := s.PoolIDFromColdVKey(creds.Cold.VKeyHex)
	if err != nil {
		t.Fatalf("PoolIDFromColdVKey: %v", err)
	}
	if id != creds.PoolID || idHex != creds.PoolIDHex {
		t.Fatalf("got id=%q hex=%q, want %q / %q", id, idHex, creds.PoolID, creds.PoolIDHex)
	}
}

func TestSubmitRetirementPadsFeeForFinalWitnesses(t *testing.T) {
	acct, err := wallet.Derive(testMnemonic, "preview", 2)
	if err != nil {
		t.Fatalf("derive account: %v", err)
	}
	chain := newRetirementFakeChain(acct.ReceiveAddresses[0], 5_000_000)
	ks := &fakeKeystore{mnemonic: testMnemonic, password: "spend-password", exists: true}
	s := NewService(chain, ks, fakeGenesis{}, fakeTip{slot: 259200})
	s.SetAccount("wallet-a", acct)

	res, err := s.SubmitRetirement(context.Background(), "spend-password", 520)
	if err != nil {
		t.Fatalf("SubmitRetirement: %v", err)
	}
	if res.TxHash == "" {
		t.Fatal("SubmitRetirement returned empty tx hash")
	}
	if len(chain.submitCbor) == 0 {
		t.Fatal("SubmitRetirement did not submit transaction CBOR")
	}

	var tx conway.ConwayTransaction
	if _, err := cbor.Decode(chain.submitCbor, &tx); err != nil {
		t.Fatalf("decode submitted tx: %v", err)
	}
	finalMinFee := uint64(int64(len(chain.submitCbor))*chain.pp.MinFeeCoefficient + chain.pp.MinFeeConstant) //nolint:gosec // test protocol params are non-negative and small
	if tx.Body.TxFee < finalMinFee+retirementFeePaddingLovelace {
		t.Fatalf("retirement fee = %d, want at least final min %d + padding %d", tx.Body.TxFee, finalMinFee, retirementFeePaddingLovelace)
	}
	if got := len(tx.WitnessSet.VkeyWitnesses.Items()); got != 2 {
		t.Fatalf("vkey witness count = %d, want payment + cold witnesses", got)
	}
}

func TestSubmitRetirementUsesDerivedChangeAddressUTxOs(t *testing.T) {
	acct, err := wallet.Derive(testMnemonic, "preview", 2)
	if err != nil {
		t.Fatalf("derive account: %v", err)
	}
	if len(acct.ChangeAddresses) == 0 {
		t.Fatal("derived account has no change addresses")
	}
	changeAddr := acct.ChangeAddresses[0]
	acct.ChangeAddresses = nil // simulate older vault metadata without persisted change window
	chain := newRetirementFakeChain(changeAddr, 5_000_000)
	ks := &fakeKeystore{mnemonic: testMnemonic, password: "spend-password", exists: true}
	s := NewService(chain, ks, fakeGenesis{}, fakeTip{slot: 259200})
	s.SetAccount("wallet-a", acct)

	res, err := s.SubmitRetirement(context.Background(), "spend-password", 520)
	if err != nil {
		t.Fatalf("SubmitRetirement: %v", err)
	}
	if res.TxHash == "" {
		t.Fatal("SubmitRetirement returned empty tx hash")
	}
	if len(chain.submitCbor) == 0 {
		t.Fatal("SubmitRetirement did not submit transaction CBOR")
	}
}

// compile-time guard: the real keystore satisfies the generic interface used here.
var _ Keystore = (*keystore.Keystore)(nil)

func TestSubmitPoolVoteBuildsTransactionWithPoolVoterAndColdWitness(t *testing.T) {
	acct, err := wallet.Derive(testMnemonic, "preview", 2)
	if err != nil {
		t.Fatalf("derive account: %v", err)
	}
	creds, err := deriveCredentials(mustRoot(t), "preview", 0, 0, 0)
	if err != nil {
		t.Fatalf("derive credentials: %v", err)
	}
	poolIDHex := creds.PoolIDHex

	actionTxID := strings.Repeat("ab", 32)
	anchorURL := "ipfs://QmTest"
	anchorHash := strings.Repeat("cd", 32)

	cases := []struct {
		name       string
		vote       string
		wantVote   uint8
		withAnchor bool
	}{
		{name: "no", vote: "no", wantVote: lcommon.GovVoteNo, withAnchor: true},
		{name: "yes", vote: "yes", wantVote: lcommon.GovVoteYes, withAnchor: true},
		{name: "abstain", vote: "abstain", wantVote: lcommon.GovVoteAbstain, withAnchor: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chain := newRetirementFakeChain(acct.ReceiveAddresses[0], 5_000_000)
			ks := &fakeKeystore{mnemonic: testMnemonic, password: "spend-password", exists: true}
			s := NewService(chain, ks, fakeGenesis{}, fakeTip{slot: 259200})
			s.SetAccount("wallet-a", acct)

			params := PoolVoteParams{
				ActionTxID:  actionTxID,
				ActionIndex: 3,
				Vote:        tc.vote,
			}
			if tc.withAnchor {
				params.AnchorURL = anchorURL
				params.AnchorHash = anchorHash
			}

			res, err := s.SubmitPoolVote(context.Background(), "spend-password", params)
			if err != nil {
				t.Fatalf("SubmitPoolVote: %v", err)
			}
			if res.TxHash == "" {
				t.Fatal("SubmitPoolVote returned empty tx hash")
			}
			if len(chain.submitCbor) == 0 {
				t.Fatal("SubmitPoolVote did not submit transaction CBOR")
			}

			var tx conway.ConwayTransaction
			if _, err := cbor.Decode(chain.submitCbor, &tx); err != nil {
				t.Fatalf("decode submitted tx: %v", err)
			}
			if len(tx.Body.TxVotingProcedures) != 1 {
				t.Fatalf("voting procedures count = %d, want 1", len(tx.Body.TxVotingProcedures))
			}
			found := false
			for voter, votes := range tx.Body.TxVotingProcedures {
				if voter.Type != lcommon.VoterTypeStakingPoolKeyHash {
					t.Fatalf("voter type = %d, want staking pool key hash", voter.Type)
				}
				if hex.EncodeToString(voter.Hash[:]) != poolIDHex {
					t.Fatalf("voter hash mismatch")
				}
				if len(votes) != 1 {
					t.Fatalf("votes for voter = %d, want 1", len(votes))
				}
				for actionID, proc := range votes {
					if hex.EncodeToString(actionID.TransactionId[:]) != actionTxID {
						t.Fatalf("action tx id mismatch")
					}
					if actionID.GovActionIdx != 3 {
						t.Fatalf("action index = %d, want 3", actionID.GovActionIdx)
					}
					if proc.Vote != tc.wantVote {
						t.Fatalf("vote = %d, want %d", proc.Vote, tc.wantVote)
					}
					if tc.withAnchor {
						if proc.Anchor == nil {
							t.Fatal("expected anchor")
						}
						if proc.Anchor.Url != anchorURL {
							t.Fatalf("anchor url = %q", proc.Anchor.Url)
						}
						if hex.EncodeToString(proc.Anchor.DataHash[:]) != anchorHash {
							t.Fatalf("anchor hash mismatch")
						}
					} else if proc.Anchor != nil {
						t.Fatal("expected no anchor")
					}
					found = true
				}
			}
			if !found {
				t.Fatal("vote not found")
			}
			if got := len(tx.WitnessSet.VkeyWitnesses.Items()); got < 2 {
				t.Fatalf("vkey witness count = %d, want payment + cold witnesses", got)
			}

			// one vkey witness hashes to the pool id (cold vkey)
			coldVKey, err := hex.DecodeString(creds.Cold.VKeyHex)
			if err != nil {
				t.Fatalf("decode cold vkey: %v", err)
			}
			coldHash := lcommon.Blake2b224Hash(coldVKey)
			poolIDBytes, err := hex.DecodeString(poolIDHex)
			if err != nil {
				t.Fatalf("decode pool id: %v", err)
			}
			var poolIDHash [28]byte
			copy(poolIDHash[:], poolIDBytes)
			if coldHash != poolIDHash {
				t.Fatalf("cold vkey hash does not match pool id hash")
			}

			hasCold := false
			for _, w := range tx.WitnessSet.VkeyWitnesses.Items() {
				wHash := lcommon.Blake2b224Hash(w.Vkey)
				if wHash == coldHash {
					hasCold = true
					break
				}
			}
			if !hasCold {
				t.Fatal("expected a vkey witness whose hash matches the pool id (cold vkey)")
			}
		})
	}

	// case without an anchor
	t.Run("no-anchor", func(t *testing.T) {
		chain := newRetirementFakeChain(acct.ReceiveAddresses[0], 5_000_000)
		ks := &fakeKeystore{mnemonic: testMnemonic, password: "spend-password", exists: true}
		s := NewService(chain, ks, fakeGenesis{}, fakeTip{slot: 259200})
		s.SetAccount("wallet-a", acct)

		res, err := s.SubmitPoolVote(context.Background(), "spend-password", PoolVoteParams{
			ActionTxID:  actionTxID,
			ActionIndex: 3,
			Vote:        "yes",
		})
		if err != nil {
			t.Fatalf("SubmitPoolVote: %v", err)
		}
		if res.TxHash == "" {
			t.Fatal("SubmitPoolVote returned empty tx hash")
		}
		var tx conway.ConwayTransaction
		if _, err := cbor.Decode(chain.submitCbor, &tx); err != nil {
			t.Fatalf("decode submitted tx: %v", err)
		}
		for _, votes := range tx.Body.TxVotingProcedures {
			for _, proc := range votes {
				if proc.Anchor != nil {
					t.Fatal("expected anchor to be absent in the no-anchor case")
				}
			}
		}
	})
}

func TestSubmitPoolVoteRejectsInvalidInputs(t *testing.T) {
	acct, err := wallet.Derive(testMnemonic, "preview", 2)
	if err != nil {
		t.Fatalf("derive account: %v", err)
	}
	chain := newRetirementFakeChain(acct.ReceiveAddresses[0], 5_000_000)
	ks := &fakeKeystore{mnemonic: testMnemonic, password: "spend-password", exists: true}
	s := NewService(chain, ks, fakeGenesis{}, fakeTip{slot: 259200})
	s.SetAccount("wallet-a", acct)

	if _, err := s.SubmitPoolVote(context.Background(), "spend-password", PoolVoteParams{
		ActionTxID: strings.Repeat("ab", 31), ActionIndex: 0, Vote: "yes",
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("short txid: %v", err)
	}
	if _, err := s.SubmitPoolVote(context.Background(), "spend-password", PoolVoteParams{
		ActionTxID: "zz" + strings.Repeat("ab", 31), ActionIndex: 0, Vote: "yes",
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("bad hex txid: %v", err)
	}
	if _, err := s.SubmitPoolVote(context.Background(), "spend-password", PoolVoteParams{
		ActionTxID: strings.Repeat("ab", 32), ActionIndex: 0, Vote: "maybe",
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("bad vote: %v", err)
	}
	if _, err := s.SubmitPoolVote(context.Background(), "spend-password", PoolVoteParams{
		ActionTxID: strings.Repeat("ab", 32), ActionIndex: 0, Vote: "yes", AnchorURL: "ipfs://x",
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("anchor url only: %v", err)
	}
	if _, err := s.SubmitPoolVote(context.Background(), "spend-password", PoolVoteParams{
		ActionTxID: strings.Repeat("ab", 32), ActionIndex: 0, Vote: "yes", AnchorHash: strings.Repeat("cd", 32),
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("anchor hash only: %v", err)
	}
	if _, err := s.SubmitPoolVote(context.Background(), "spend-password", PoolVoteParams{
		ActionTxID: strings.Repeat("ab", 32), ActionIndex: 0, Vote: "yes", AnchorURL: "ipfs://x", AnchorHash: strings.Repeat("cd", 31),
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("short anchor hash: %v", err)
	}
	if _, err := s.SubmitPoolVote(context.Background(), "spend-password", PoolVoteParams{
		ActionTxID: strings.Repeat("ab", 32), ActionIndex: 0, Vote: "yes", AnchorURL: "ipfs://x", AnchorHash: "zz" + strings.Repeat("cd", 31),
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("bad hex anchor hash: %v", err)
	}
	if _, err := s.SubmitPoolVote(context.Background(), "spend-password", PoolVoteParams{
		ActionTxID: strings.Repeat("ab", 32), ActionIndex: lcommon.MaxGovActionIdx + 1, Vote: "yes",
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("action index too large: %v", err)
	}

	// 129-byte anchor URL
	longURL := "http://" + strings.Repeat("a", 122) // total > 128
	if _, err := s.SubmitPoolVote(context.Background(), "spend-password", PoolVoteParams{
		ActionTxID: strings.Repeat("ab", 32), ActionIndex: 0, Vote: "yes", AnchorURL: longURL, AnchorHash: strings.Repeat("cd", 32),
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("long anchor url: %v", err)
	}

	if len(chain.submitCbor) != 0 {
		t.Fatal("should not have submitted anything for invalid inputs")
	}
}

func TestSubmitPoolVoteRejectsInvalidInputsNoUtxoFetch(t *testing.T) {
	acct, err := wallet.Derive(testMnemonic, "preview", 2)
	if err != nil {
		t.Fatalf("derive account: %v", err)
	}
	ks := &fakeKeystore{mnemonic: testMnemonic, password: "spend-password", exists: true}
	s := NewService(&noUtxoChain{}, ks, fakeGenesis{}, fakeTip{slot: 259200})
	s.SetAccount("wallet-a", acct)

	if _, err := s.SubmitPoolVote(context.Background(), "spend-password", PoolVoteParams{
		ActionTxID: strings.Repeat("ab", 32), ActionIndex: lcommon.MaxGovActionIdx + 1, Vote: "yes",
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("action index too large: %v", err)
	}
	longURL := "http://" + strings.Repeat("a", 122)
	if _, err := s.SubmitPoolVote(context.Background(), "spend-password", PoolVoteParams{
		ActionTxID: strings.Repeat("ab", 32), ActionIndex: 0, Vote: "yes", AnchorURL: longURL, AnchorHash: strings.Repeat("cd", 32),
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("long anchor url: %v", err)
	}
}

type noUtxoChain struct{}

func (n *noUtxoChain) ProtocolParams() (backend.ProtocolParameters, error) {
	return backend.ProtocolParameters{MinFeeConstant: 155381, MinFeeCoefficient: 44, MaxTxSize: 16384, CoinsPerUtxoByte: "4310", KeyDeposits: "2000000", PoolDeposits: "500000000"}, nil
}
func (n *noUtxoChain) GenesisParams() (backend.GenesisParameters, error) {
	return backend.GenesisParameters{NetworkMagic: 1}, nil
}
func (n *noUtxoChain) NetworkId() uint8              { return 0 }
func (n *noUtxoChain) CurrentEpoch() (uint64, error) { return 500, nil }
func (n *noUtxoChain) MaxTxFee() (uint64, error)     { return 0, nil }
func (n *noUtxoChain) Tip() (uint64, error)          { return 10_000_000, nil }
func (n *noUtxoChain) Utxos(lcommon.Address) ([]lcommon.Utxo, error) {
	panic("Utxos should not be called")
}
func (n *noUtxoChain) SubmitTx([]byte) (lcommon.Blake2b256, error) {
	var h lcommon.Blake2b256
	return h, nil
}
func (n *noUtxoChain) EvaluateTx([]byte, []lcommon.Utxo) (map[lcommon.RedeemerKey]lcommon.ExUnits, error) {
	return nil, nil
}
func (n *noUtxoChain) UtxoByRef(lcommon.Blake2b256, uint32) (*lcommon.Utxo, error) {
	return nil, nil
}
func (n *noUtxoChain) ScriptCbor(lcommon.Blake2b224) ([]byte, error) { return nil, nil }
