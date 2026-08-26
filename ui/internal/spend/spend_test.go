package spend

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	apollo "github.com/Salvionied/apollo/v2"
	"github.com/Salvionied/apollo/v2/backend"
	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/bip32"
	"github.com/blinklabs-io/bursa/ui/internal/chain"
	"github.com/blinklabs-io/bursa/ui/internal/keystore"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/ledger"
	"github.com/blinklabs-io/gouroboros/ledger/babbage"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/conway"
	"github.com/blinklabs-io/gouroboros/ledger/shelley"
	"github.com/blinklabs-io/plutigo/data"
	utxorpc "github.com/utxorpc/go-codegen/utxorpc/v1alpha/cardano"
)

// testMnemonic is the standard BIP-39 test vector mnemonic (24-word "abandon" phrase).
const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

const differentMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// mustDeriveTestAccount derives the preview test account from testMnemonic; fatal on error.
func mustDeriveTestAccount(t *testing.T) *wallet.Account {
	t.Helper()
	acct, err := wallet.Derive(testMnemonic, "preview", 2)
	if err != nil {
		t.Fatalf("wallet.Derive: %v", err)
	}
	return acct
}

// fakeChain is a minimal implementation of backend.ChainContext for unit tests.
type fakeChain struct {
	utxos       map[string][]lcommon.Utxo // keyed by bech32 address
	pp          backend.ProtocolParameters
	maxTxFeeErr error
	submitHash  lcommon.Blake2b256 // canned hash returned by SubmitTx
	submitCalls int                // count of SubmitTx invocations
	submitCbor  []byte
	submitMu    sync.Mutex

	submitStarted chan struct{}
	releaseSubmit chan struct{}
	utxosStarted  chan struct{}
	releaseUtxos  chan struct{}
	utxoBlockOnce sync.Once
}

// cannedSubmitHash is the deterministic tx hash returned by fakeChain.SubmitTx.
var cannedSubmitHash = func() lcommon.Blake2b256 {
	var h lcommon.Blake2b256
	b, _ := hex.DecodeString("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	copy(h[:], b)
	return h
}()

func newFakeChain(lovelace uint64, addr string) *fakeChain {
	// Build a fake UTxO at the given address with the given lovelace amount.
	var txID lcommon.Blake2b256
	// Use a deterministic non-zero tx hash.
	hashBytes, _ := hex.DecodeString("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
	copy(txID[:], hashBytes)

	input := shelley.ShelleyTransactionInput{
		TxId:        txID,
		OutputIndex: 0,
	}

	utxoAddr, _ := lcommon.NewAddress(addr)
	output := &fakeOutput{
		address:  utxoAddr,
		lovelace: lovelace,
	}
	utxo := lcommon.Utxo{
		Id:     input,
		Output: output,
	}

	return &fakeChain{
		utxos: map[string][]lcommon.Utxo{
			addr: {utxo},
		},
		pp: backend.ProtocolParameters{
			MinFeeConstant:    155381,
			MinFeeCoefficient: 44,
			MaxTxSize:         16384,
			CoinsPerUtxoByte:  "4310",
			KeyDeposits:       "2000000",
			PoolDeposits:      "500000000",
		},
		submitHash: cannedSubmitHash,
	}
}

// addUTxO adds a second fake UTxO at a different address (with a distinct tx hash).
func (fc *fakeChain) addUTxO(lovelace uint64, addr string, txHashHex string, outIdx uint32) {
	var txID lcommon.Blake2b256
	b, _ := hex.DecodeString(txHashHex)
	copy(txID[:], b)
	input := shelley.ShelleyTransactionInput{TxId: txID, OutputIndex: outIdx}
	utxoAddr, _ := lcommon.NewAddress(addr)
	output := &fakeOutput{address: utxoAddr, lovelace: lovelace}
	fc.utxos[addr] = append(fc.utxos[addr], lcommon.Utxo{Id: input, Output: output})
}

// fakeOutput implements lcommon.TransactionOutput with lovelace only.
type fakeOutput struct {
	address  lcommon.Address
	lovelace uint64
}

func (o *fakeOutput) Address() lcommon.Address { return o.address }
func (o *fakeOutput) Amount() *big.Int         { return new(big.Int).SetUint64(o.lovelace) }
func (o *fakeOutput) Assets() *lcommon.MultiAsset[lcommon.MultiAssetTypeOutput] {
	return nil
}
func (o *fakeOutput) Datum() *lcommon.Datum               { return nil }
func (o *fakeOutput) DatumHash() *lcommon.Blake2b256      { return nil }
func (o *fakeOutput) Cbor() []byte                        { return nil }
func (o *fakeOutput) Utxorpc() (*utxorpc.TxOutput, error) { return nil, nil }
func (o *fakeOutput) ScriptRef() lcommon.Script           { return nil }
func (o *fakeOutput) ToPlutusData() data.PlutusData       { return nil }
func (o *fakeOutput) String() string                      { return o.address.String() }

// fakeOutputWithAssets is like fakeOutput but also carries native assets — used
// to construct test UTxOs that contain native tokens so apollo can forward them.
type fakeOutputWithAssets struct {
	fakeOutput
	assets *lcommon.MultiAsset[lcommon.MultiAssetTypeOutput]
}

func (o *fakeOutputWithAssets) Assets() *lcommon.MultiAsset[lcommon.MultiAssetTypeOutput] {
	return o.assets
}

// newFakeMultiAsset creates a minimal MultiAsset with one policy/asset entry.
func newFakeMultiAsset(policyHex, assetNameHex string, qty int64) *lcommon.MultiAsset[lcommon.MultiAssetTypeOutput] {
	policyBytes, _ := hex.DecodeString(policyHex)
	assetBytes, _ := hex.DecodeString(assetNameHex)
	var policyID lcommon.Blake2b224
	copy(policyID[:], policyBytes)
	assetName := cbor.NewByteString(assetBytes)
	data := map[lcommon.Blake2b224]map[cbor.ByteString]lcommon.MultiAssetTypeOutput{
		policyID: {assetName: new(big.Int).SetInt64(qty)},
	}
	ma := lcommon.NewMultiAsset(data)
	return &ma
}

// backend.ChainContext implementation for fakeChain.
func (fc *fakeChain) ProtocolParams() (backend.ProtocolParameters, error) {
	return fc.pp, nil
}

func (fc *fakeChain) GenesisParams() (backend.GenesisParameters, error) {
	return backend.GenesisParameters{
		ActiveSlotsCoefficient: 0.05,
		EpochLength:            432000,
		SlotLength:             1,
		NetworkMagic:           1,
	}, nil
}
func (fc *fakeChain) NetworkId() uint8              { return 0 } // preview = 0
func (fc *fakeChain) CurrentEpoch() (uint64, error) { return 500, nil }

func (fc *fakeChain) MaxTxFee() (uint64, error) {
	if fc.maxTxFeeErr != nil {
		return 0, fc.maxTxFeeErr
	}
	return backend.ComputeMaxTxFee(fc.pp)
}
func (fc *fakeChain) Tip() (uint64, error) { return 10_000_000, nil }
func (fc *fakeChain) Utxos(address lcommon.Address) ([]lcommon.Utxo, error) {
	if fc.utxosStarted != nil && fc.releaseUtxos != nil {
		fc.utxoBlockOnce.Do(func() {
			select {
			case fc.utxosStarted <- struct{}{}:
			default:
			}
			<-fc.releaseUtxos
		})
	}
	return fc.utxos[address.String()], nil
}

func (fc *fakeChain) SubmitTx(tx []byte) (lcommon.Blake2b256, error) {
	fc.submitMu.Lock()
	fc.submitCalls++
	fc.submitCbor = append(fc.submitCbor[:0], tx...)
	fc.submitMu.Unlock()
	if fc.submitStarted != nil {
		select {
		case fc.submitStarted <- struct{}{}:
		default:
		}
	}
	if fc.releaseSubmit != nil {
		<-fc.releaseSubmit
	}
	return fc.submitHash, nil
}

func (fc *fakeChain) submittedTxCbor() []byte {
	fc.submitMu.Lock()
	defer fc.submitMu.Unlock()
	return append([]byte(nil), fc.submitCbor...)
}

func (fc *fakeChain) EvaluateTx(_ []byte, _ []lcommon.Utxo) (map[lcommon.RedeemerKey]lcommon.ExUnits, error) {
	return nil, nil
}

func (fc *fakeChain) UtxoByRef(txHash lcommon.Blake2b256, index uint32) (*lcommon.Utxo, error) {
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
func (fc *fakeChain) ScriptCbor(_ lcommon.Blake2b224) ([]byte, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestBuildProducesPreview(t *testing.T) {
	acct := mustDeriveTestAccount(t)
	addr0 := acct.ReceiveAddresses[0]

	// A second preview address to send to (index 1 of the same account).
	recvAddr := acct.ReceiveAddresses[1]

	fc := newFakeChain(5_000_000, addr0)
	s := NewService(fc, nil, acct)

	pv, err := s.Build(context.Background(), SendRequest{To: recvAddr, Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if pv.PendingID == "" {
		t.Fatal("expected non-empty PendingID")
	}
	if pv.Fee == "" || pv.Fee == "0" {
		t.Fatalf("expected non-zero Fee, got %q", pv.Fee)
	}
	if len(pv.Outputs) == 0 {
		t.Fatal("expected at least one Output")
	}
}

func TestBuildInsufficientFunds(t *testing.T) {
	acct := mustDeriveTestAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	recvAddr := acct.ReceiveAddresses[1]

	fc := newFakeChain(100_000, addr0)
	s := NewService(fc, nil, acct)

	_, err := s.Build(context.Background(), SendRequest{To: recvAddr, Lovelace: "1000000"})
	if !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("expected ErrInsufficientFunds, got %v", err)
	}
	t.Logf("got expected error: %v", err)
}

// TestBuildRetriesDustChangeDeadZone reproduces the min-UTxO dust-change
// dead-zone: two ~5-ADA UTxOs with a ~4-ADA send would leave change just below
// the min-UTxO floor if only one input is selected, which makes Apollo's fee
// estimate oscillate and Complete() report "evaluation transaction did not
// converge". Build must detect that, retry forcing the other input in, and
// return a valid, signable transaction whose change clears the floor.
func TestBuildRetriesDustChangeDeadZone(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	recvAddr := acct.ReceiveAddresses[2]

	// Two 5-ADA UTxOs at the same funding address. Selecting one to fund a 4-ADA
	// send leaves ~0.83 ADA change — inside the dead-zone.
	fc := newFakeChain(4_400_000, addr0)
	fc.addUTxO(4_400_000, addr0, "1111111111111111111111111111111111111111111111111111111111111111", 0)
	ks := fakeKeystore{mnemonic: testMnemonic}
	s := NewService(fc, ks, acct)

	ctx := context.Background()
	pv, err := s.Build(ctx, SendRequest{To: recvAddr, Lovelace: "4500000"})
	if err != nil {
		t.Fatalf("Build in dust-change dead-zone should now succeed, got: %v", err)
	}
	// The retry forces the other UTxO in, so both inputs are consumed and the
	// combined change clears the min-UTxO floor.
	if len(pv.Inputs) != 2 {
		t.Fatalf("expected retry to include both inputs, got %d: %v", len(pv.Inputs), pv.Inputs)
	}
	if pv.Fee == "" || pv.Fee == "0" {
		t.Fatalf("expected non-zero Fee, got %q", pv.Fee)
	}
	change, err := strconv.ParseUint(pv.Change, 10, 64)
	if err != nil || change == 0 {
		t.Fatalf("expected non-zero change above the min-UTxO floor, got %q (err %v)", pv.Change, err)
	}

	// The built tx must be signable and submittable, proving it is valid.
	res, err := s.Confirm(ctx, pv.PendingID, "pw")
	if err != nil {
		t.Fatalf("Confirm of dead-zone tx: %v", err)
	}
	if res.TxHash == "" {
		t.Fatal("expected non-empty TxHash")
	}
	if fc.submitCalls != 1 {
		t.Fatalf("expected SubmitTx called once, got %d", fc.submitCalls)
	}
}

// TestBuildDustChangeDeadZoneNoExtraInputs covers the genuinely-unresolvable
// dead-zone: a single UTxO whose only possible change is dust and there is no
// other input to pull in. Build must surface a clear, actionable error rather
// than Apollo's raw non-convergence message.
func TestBuildDustChangeDeadZoneNoExtraInputs(t *testing.T) {
	acct := mustDeriveTestAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	recvAddr := acct.ReceiveAddresses[1]

	// Single 5-ADA UTxO, near-total send: no extra input exists.
	fc := newFakeChain(5_000_000, addr0)
	s := NewService(fc, nil, acct)

	_, err := s.Build(context.Background(), SendRequest{To: recvAddr, Lovelace: "4900000"})
	if !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("expected ErrInsufficientFunds, got %v", err)
	}
}

// fillDeadZoneUTxOs adds n 5-ADA UTxOs at addr with distinct tx hashes. A 4-ADA
// send funded by a single one leaves ~0.83 ADA change — inside the dust-change
// dead-zone — so Build must force additional inputs to clear the min-UTxO floor.
func fillDeadZoneUTxOs(fc *fakeChain, n int, addr string) {
	for i := 0; i < n; i++ {
		// Distinct 32-byte tx hash per UTxO: "0000..<i>" as 64 hex chars.
		h := fmt.Sprintf("%064x", i+1)
		fc.addUTxO(5_000_000, addr, h, 0)
	}
}

// TestBuildDeadZoneForcesBoundedInputs proves the dust-change retry forces only
// the minimum extra inputs (largest-first), not the whole wallet: a 50-UTxO
// wallet whose 4-ADA send lands in the dead-zone must build with a small,
// bounded input set well under the wallet size, produce a tx under MaxTxSize,
// and still sign + submit.
func TestBuildDeadZoneForcesBoundedInputs(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	recvAddr := acct.ReceiveAddresses[2]

	const walletUTxOs = 50
	fc := newFakeChain(5_000_000, addr0)
	fillDeadZoneUTxOs(fc, walletUTxOs-1, addr0) // newFakeChain already seeded one

	ks := fakeKeystore{mnemonic: testMnemonic}
	s := NewService(fc, ks, acct)

	ctx := context.Background()
	pv, err := s.Build(ctx, SendRequest{To: recvAddr, Lovelace: "4000000"})
	if err != nil {
		t.Fatalf("Build in 50-UTxO dead-zone should succeed, got: %v", err)
	}

	// The retry must pull in only a handful of inputs, never the whole wallet.
	if len(pv.Inputs) == 0 || len(pv.Inputs) >= walletUTxOs {
		t.Fatalf("expected a small bounded input set, got %d of %d wallet UTxOs", len(pv.Inputs), walletUTxOs)
	}
	if len(pv.Inputs) > 5 {
		t.Fatalf("input set is not bounded to the minimum needed: got %d inputs", len(pv.Inputs))
	}

	// It must still sign and submit — proving the bounded forced set is valid.
	res, err := s.Confirm(ctx, pv.PendingID, "pw")
	if err != nil {
		t.Fatalf("Confirm of bounded dead-zone tx: %v", err)
	}
	if res.TxHash == "" {
		t.Fatal("expected non-empty TxHash")
	}
	if fc.submitCalls != 1 {
		t.Fatalf("expected SubmitTx called once, got %d", fc.submitCalls)
	}
	// Assert against the REAL signed bytes handed to SubmitTx. Measuring the
	// actual tx — rather than re-deriving guardTxSize's own arithmetic — is what
	// catches a wrong witness projection (an estimate that mirrors the code
	// can't tell you the code is right).
	pp, err := fc.ProtocolParams()
	if err != nil {
		t.Fatalf("ProtocolParams: %v", err)
	}
	if n := len(fc.submittedTxCbor()); n >= pp.MaxTxSize {
		t.Fatalf("signed tx size %d must be under MaxTxSize %d", n, pp.MaxTxSize)
	}
}

// TestBuildDeadZoneForcesLargestFirst proves the retry orders forced inputs by
// lovelace descending: with one large UTxO among many small ones, it converges
// on that single large input (k=1) rather than walking the small ones. Deleting
// the sort in completeForcingPrefix makes this fail (the small UTxOs would be
// forced first); an all-equal-value wallet can't distinguish the two.
func TestBuildDeadZoneForcesLargestFirst(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	recvAddr := acct.ReceiveAddresses[2]

	// Thirty 5-ADA UTxOs (the dead-zone shape) plus one 100-ADA UTxO added last,
	// so it is only reachable first if the retry sorts largest-first.
	fc := newFakeChain(5_000_000, addr0)
	fillDeadZoneUTxOs(fc, 29, addr0) // 30 x 5-ADA total
	fc.addUTxO(100_000_000, addr0, fmt.Sprintf("%064x", 0x1000), 0)

	s := NewService(fc, fakeKeystore{mnemonic: testMnemonic}, acct)
	pv, err := s.Build(context.Background(), SendRequest{To: recvAddr, Lovelace: "4000000"})
	if err != nil {
		t.Fatalf("Build should succeed: %v", err)
	}
	// The lone 100-ADA input covers the send with change well clear of the floor,
	// so convergence is at exactly one input.
	if len(pv.Inputs) != 1 {
		t.Fatalf("expected largest-first to converge at 1 input, got %d: %v", len(pv.Inputs), pv.Inputs)
	}
}

// TestBuildDeadZoneRejectsOversizeTx proves guardTxSize turns a would-be
// oversized transaction into a clear pre-approval error instead of letting it
// reach SubmitTx. The threshold is pinned to the branch's actual completed body
// (measured with the guard disabled) plus one witness, minus a byte — so it
// stays valid regardless of how witnesses are counted, rather than relying on
// the counting method.
func TestBuildDeadZoneRejectsOversizeTx(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	recvAddr := acct.ReceiveAddresses[2]
	req := SendRequest{To: recvAddr, Lovelace: "4000000"}

	// Measure the real completed dead-zone tx with the guard disabled. All UTxOs
	// share addr0, so the signed tx carries exactly one vkey witness.
	measure := newFakeChain(5_000_000, addr0)
	fillDeadZoneUTxOs(measure, 9, addr0)
	measure.pp.MaxTxSize = 0
	ms := NewService(measure, fakeKeystore{mnemonic: testMnemonic}, acct)
	mpv, err := ms.Build(context.Background(), req)
	if err != nil {
		t.Fatalf("measurement build (guard disabled) should succeed: %v", err)
	}
	ms.mu.Lock()
	mp := ms.pending[mpv.PendingID]
	ms.mu.Unlock()
	if mp == nil {
		t.Fatal("measurement pending entry missing")
	}
	cbor, err := mp.tx.GetTxCbor()
	if err != nil {
		t.Fatalf("GetTxCbor: %v", err)
	}
	// One distinct signing address → one vkey witness, plus the one-time
	// witness-set framing the guard accounts for.
	projected := len(cbor) + vkeyWitnessSizeEstimate + witnessSetOverhead

	// Same scenario, but MaxTxSize one byte under the true projection: the guard
	// must reject and nothing may reach SubmitTx.
	fc := newFakeChain(5_000_000, addr0)
	fillDeadZoneUTxOs(fc, 9, addr0) // 10 UTxOs total on addr0
	fc.pp.MaxTxSize = projected - 1

	s := NewService(fc, fakeKeystore{mnemonic: testMnemonic}, acct)

	_, err = s.Build(context.Background(), req)
	if !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("expected ErrInsufficientFunds, got %v", err)
	}
	if !strings.Contains(err.Error(), "exceed the maximum size") {
		t.Fatalf("expected a size-limit message, got: %v", err)
	}
	if fc.submitCalls != 0 {
		t.Fatalf("oversized tx must never be submitted, got %d SubmitTx calls", fc.submitCalls)
	}
}

// TestBuildDeadZoneSizeGuardDisabled pins the documented behaviour that a
// MaxTxSize of 0 disables the guard: the dead-zone retry still succeeds.
func TestBuildDeadZoneSizeGuardDisabled(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	recvAddr := acct.ReceiveAddresses[2]

	fc := newFakeChain(5_000_000, addr0)
	fillDeadZoneUTxOs(fc, 9, addr0)
	fc.pp.MaxTxSize = 0 // guard disabled

	s := NewService(fc, fakeKeystore{mnemonic: testMnemonic}, acct)

	pv, err := s.Build(context.Background(), SendRequest{To: recvAddr, Lovelace: "4000000"})
	if err != nil {
		t.Fatalf("with the size guard disabled, Build should succeed, got: %v", err)
	}
	if len(pv.Inputs) == 0 {
		t.Fatal("expected a built tx with inputs")
	}
}

// TestBuildRejectsOversizeTxOnPlainPath proves the size guard covers the
// ordinary coin-selected build, not only the dust-change retry. A large send
// that never enters the dead-zone can still select enough inputs to exceed
// MaxTxSize; guarding only the retry path would let that reach SubmitTx and be
// rejected by the node after the user had already approved it.
func TestBuildRejectsOversizeTxOnPlainPath(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	recvAddr := acct.ReceiveAddresses[2]

	// 40 x 10 ADA. A 200-ADA send needs ~21 inputs and leaves ~200 ADA change,
	// far clear of the min-UTxO floor, so the first Complete() converges and the
	// dead-zone retry never runs — this exercises the plain path only.
	const utxoValue, walletUTxOs = 10_000_000, 40
	req := SendRequest{To: recvAddr, Lovelace: "200000000"}

	fill := func(fc *fakeChain) {
		for i := 1; i < walletUTxOs; i++ {
			fc.addUTxO(utxoValue, addr0, fmt.Sprintf("%064x", i), 0)
		}
	}

	// Measure the real completed tx with the guard disabled. All UTxOs share
	// addr0, so the signed tx carries exactly one vkey witness.
	measure := newFakeChain(utxoValue, addr0)
	fill(measure)
	measure.pp.MaxTxSize = 0
	ms := NewService(measure, fakeKeystore{mnemonic: testMnemonic}, acct)
	mpv, err := ms.Build(context.Background(), req)
	if err != nil {
		t.Fatalf("measurement build (guard disabled) should succeed: %v", err)
	}
	if len(mpv.Inputs) < 2 {
		t.Fatalf("expected a multi-input coin selection, got %d", len(mpv.Inputs))
	}
	ms.mu.Lock()
	mp := ms.pending[mpv.PendingID]
	ms.mu.Unlock()
	if mp == nil {
		t.Fatal("measurement pending entry missing")
	}
	cbor, err := mp.tx.GetTxCbor()
	if err != nil {
		t.Fatalf("GetTxCbor: %v", err)
	}
	projected := len(cbor) + vkeyWitnessSizeEstimate + witnessSetOverhead

	// Same scenario, MaxTxSize one byte under the true projection.
	fc := newFakeChain(utxoValue, addr0)
	fill(fc)
	fc.pp.MaxTxSize = projected - 1
	s := NewService(fc, fakeKeystore{mnemonic: testMnemonic}, acct)

	_, err = s.Build(context.Background(), req)
	if !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("expected ErrInsufficientFunds for an oversize plain send, got %v", err)
	}
	if !strings.Contains(err.Error(), "exceed the maximum size") {
		t.Fatalf("expected a size-limit message, got: %v", err)
	}
	if fc.submitCalls != 0 {
		t.Fatalf("oversized tx must never be submitted, got %d SubmitTx calls", fc.submitCalls)
	}
}

func TestIsInsufficientFundsError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "coin selection",
			err:  errors.New("coin selection failed: insufficient UTxOs to cover required value"),
			want: true,
		},
		{
			name: "coin underflow",
			err:  errors.New("insufficient funds: coin underflow"),
			want: true,
		},
		{
			name: "asset underflow",
			err:  errors.New("insufficient funds: asset underflow for policy abc"),
			want: true,
		},
		{
			name: "change min utxo",
			err:  errors.New("insufficient funds: need 123 more lovelace for change output min UTxO"),
			want: true,
		},
		{
			name: "burn assets",
			err:  errors.New("insufficient assets in inputs to cover burn: policy abc asset  short by 1"),
			want: true,
		},
		{
			name: "non funding",
			err:  errors.New("failed to compute max tx fee for coin selection: backend down"),
			want: false,
		},
		{
			name: "loose insufficient text",
			err:  errors.New("protocol params insufficiently configured"),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isInsufficientFundsError(tt.err); got != tt.want {
				t.Fatalf("isInsufficientFundsError(%q) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestBuildCompleteErrorDoesNotMapToInsufficientFunds(t *testing.T) {
	acct := mustDeriveTestAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	recvAddr := acct.ReceiveAddresses[1]

	fc := newFakeChain(5_000_000, addr0)
	fc.maxTxFeeErr = errors.New("fee unavailable")
	s := NewService(fc, nil, acct)

	_, err := s.Build(context.Background(), SendRequest{To: recvAddr, Lovelace: "1000000"})
	if err == nil {
		t.Fatal("expected Build error")
	}
	if errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("non-funding Complete error mapped to ErrInsufficientFunds: %v", err)
	}
	if !strings.Contains(err.Error(), "fee unavailable") {
		t.Fatalf("Build error lost underlying cause: %v", err)
	}
}

func TestBuildRejectsLovelaceOverflow(t *testing.T) {
	acct := mustDeriveTestAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	recvAddr := acct.ReceiveAddresses[1]

	fc := newFakeChain(5_000_000, addr0)
	s := NewService(fc, nil, acct)

	_, err := s.Build(context.Background(), SendRequest{
		To: recvAddr,
		// 2^63 = MaxInt64 + 1: parses as a uint64 but exceeds the int64 range
		// Apollo accepts, so Build must reject it.
		Lovelace: "9223372036854775808",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest, got %v", err)
	}
}

func TestBuildRejectsMalformedAssetUnit(t *testing.T) {
	acct := mustDeriveTestAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	recvAddr := acct.ReceiveAddresses[1]

	tests := []struct {
		name string
		unit string
	}{
		{name: "short", unit: "abcd"},
		{name: "bad policy hex", unit: strings.Repeat("z", 56)},
		{name: "bad asset name hex", unit: strings.Repeat("a", 56) + "x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := newFakeChain(5_000_000, addr0)
			s := NewService(fc, nil, acct)

			_, err := s.Build(context.Background(), SendRequest{
				To:       recvAddr,
				Lovelace: "1000000",
				Assets:   []Asset{{Unit: tt.unit, Quantity: "1"}},
			})
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("expected ErrInvalidRequest, got %v", err)
			}
			if strings.Contains(err.Error(), "complete transaction") {
				t.Fatalf("malformed asset reached Complete(): %v", err)
			}
		})
	}
}

// fakeKeystore satisfies the Keystore interface for tests.
type fakeKeystore struct {
	mnemonic string
	err      error
}

func (fk fakeKeystore) Exists() bool             { return false }
func (fk fakeKeystore) Create(_, _ string) error { return nil }
func (fk fakeKeystore) Unlock(_ string) ([]byte, error) {
	if fk.err != nil {
		return nil, fk.err
	}
	return []byte(fk.mnemonic), nil
}

type trackingKeystore struct {
	mnemonic    string
	unlockCalls int
}

func (tk *trackingKeystore) Exists() bool             { return true }
func (tk *trackingKeystore) Create(_, _ string) error { return nil }
func (tk *trackingKeystore) Unlock(_ string) ([]byte, error) {
	tk.unlockCalls++
	return []byte(tk.mnemonic), nil
}

type blockingSeedStore struct {
	mnemonicByID map[string]string
	unlockForID  chan string
	release      chan struct{}
}

func (b *blockingSeedStore) Exists() bool             { return true }
func (b *blockingSeedStore) Create(_, _ string) error { return nil }
func (b *blockingSeedStore) Unlock(string) ([]byte, error) {
	return nil, errors.New("unexpected active-wallet unlock")
}
func (b *blockingSeedStore) UnlockFor(id, _ string) ([]byte, error) {
	b.unlockForID <- id
	<-b.release
	mnemonic, ok := b.mnemonicByID[id]
	if !ok {
		return nil, errors.New("unknown wallet id")
	}
	return []byte(mnemonic), nil
}

// mustDeriveConfirmAccount derives the test account with windowN=5 for Confirm tests.
func mustDeriveConfirmAccount(t *testing.T) *wallet.Account {
	t.Helper()
	acct, err := wallet.Derive(testMnemonic, "preview", 5)
	if err != nil {
		t.Fatalf("wallet.Derive: %v", err)
	}
	return acct
}

func paymentKeyHashForAddress(t *testing.T, addrStr string) string {
	t.Helper()
	addr, err := lcommon.NewAddress(addrStr)
	if err != nil {
		t.Fatalf("NewAddress(%q): %v", addrStr, err)
	}
	return hex.EncodeToString(addr.PaymentKeyHash().Bytes())
}

func hashedSignDataFixture(t *testing.T, acct *wallet.Account) (string, string, []byte, string) {
	t.Helper()
	addrStr := acct.ReceiveAddresses[0]
	addr, err := lcommon.NewAddress(addrStr)
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	addrBytes, err := addr.Bytes()
	if err != nil {
		t.Fatalf("Address.Bytes: %v", err)
	}
	rootKey, err := bursa.GetRootKeyFromMnemonic(testMnemonic, "")
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	acctKey, err := bursa.GetAccountKey(rootKey, 0)
	if err != nil {
		t.Fatalf("account key: %v", err)
	}
	payKey, err := bursa.GetPaymentKey(acctKey, 0)
	if err != nil {
		t.Fatalf("payment key: %v", err)
	}

	payload := []byte("payload signed through CIP-8 hashed mode")
	protected, err := cbor.Encode(map[any]any{
		int64(1):  int64(-8),
		"address": addrBytes,
	})
	if err != nil {
		t.Fatalf("encode protected headers: %v", err)
	}
	hash := lcommon.Blake2b224Hash(payload)
	toBeSigned, err := cbor.Encode([]any{"Signature1", protected, []byte{}, hash[:]})
	if err != nil {
		t.Fatalf("encode Sig_structure: %v", err)
	}
	signature := payKey.Sign(toBeSigned)
	coseSign1Bytes, err := cbor.Encode([]any{
		protected,
		map[any]any{"hashed": true},
		payload,
		signature,
	})
	if err != nil {
		t.Fatalf("encode COSE_Sign1: %v", err)
	}
	coseKey, err := cbor.Encode(map[any]any{
		int64(1):  int64(1),
		int64(3):  int64(-8),
		int64(-1): int64(6),
		int64(-2): payKey.PublicKey(),
	})
	if err != nil {
		t.Fatalf("encode COSE_Key: %v", err)
	}
	return hex.EncodeToString(coseSign1Bytes), hex.EncodeToString(coseKey), payload, addrStr
}

func witnessCount(t *testing.T, wit Witness) int {
	t.Helper()
	return len(decodeWitnesses(t, wit))
}

func decodeWitnesses(t *testing.T, wit Witness) []lcommon.VkeyWitness {
	t.Helper()
	witBytes, err := hex.DecodeString(wit.WitnessCBOR)
	if err != nil {
		t.Fatalf("decode witness hex: %v", err)
	}
	var witnesses []lcommon.VkeyWitness
	if _, err := cbor.Decode(witBytes, &witnesses); err != nil {
		t.Fatalf("decode witnesses: %v", err)
	}
	return witnesses
}

func bodyRequiredSigners(t *testing.T, unsignedTxCBOR string) []lcommon.Blake2b224 {
	t.Helper()
	txBytes, err := hex.DecodeString(unsignedTxCBOR)
	if err != nil {
		t.Fatalf("decode unsigned tx hex: %v", err)
	}
	tx, err := ledger.NewConwayTransactionFromCbor(txBytes)
	if err != nil {
		t.Fatalf("decode unsigned tx: %v", err)
	}
	return tx.Body.RequiredSigners()
}

func stakeKeyHashForAddress(t *testing.T, addrStr string) string {
	t.Helper()
	addr, err := lcommon.NewAddress(addrStr)
	if err != nil {
		t.Fatalf("NewAddress(%q): %v", addrStr, err)
	}
	kh := addr.StakeKeyHash()
	if kh == (lcommon.Blake2b224{}) {
		t.Fatalf("address %q has no stake key hash", addrStr)
	}
	return hex.EncodeToString(kh.Bytes())
}

func unsignedWithRequiredSigners(
	t *testing.T,
	unsignedTxCBOR string,
	required []lcommon.Blake2b224,
) string {
	t.Helper()
	txBytes, err := hex.DecodeString(unsignedTxCBOR)
	if err != nil {
		t.Fatalf("decode unsigned tx hex: %v", err)
	}
	tx, err := ledger.NewConwayTransactionFromCbor(txBytes)
	if err != nil {
		t.Fatalf("decode unsigned tx: %v", err)
	}
	tx.Body.TxRequiredSigners = cbor.NewSetType(required, true)
	tx.SetCbor(nil)
	tx.Body.SetCbor(nil)
	encoded, err := cbor.Encode(tx)
	if err != nil {
		t.Fatalf("encode unsigned tx: %v", err)
	}
	return hex.EncodeToString(encoded)
}

func unsignedWithIndefiniteBodyMap(t *testing.T, unsignedTxCBOR string) string {
	t.Helper()
	txBytes, err := hex.DecodeString(unsignedTxCBOR)
	if err != nil {
		t.Fatalf("decode unsigned tx hex: %v", err)
	}
	var arr []cbor.RawMessage
	if _, err := cbor.Decode(txBytes, &arr); err != nil {
		t.Fatalf("decode unsigned tx array: %v", err)
	}
	if len(arr) != 4 {
		t.Fatalf("unsigned tx array length = %d, want 4", len(arr))
	}
	body := []byte(arr[0])
	if len(body) == 0 || body[0] < 0xa0 || body[0] > 0xb7 {
		t.Fatalf("body CBOR does not start with a definite map header: %x", body[:min(len(body), 8)])
	}
	driftedBody := make([]byte, 0, len(body)+1)
	driftedBody = append(driftedBody, 0xbf)
	driftedBody = append(driftedBody, body[1:]...)
	driftedBody = append(driftedBody, 0xff)
	arr[0] = cbor.RawMessage(driftedBody)
	encoded, err := cbor.Encode(arr)
	if err != nil {
		t.Fatalf("encode drifted unsigned tx: %v", err)
	}
	return hex.EncodeToString(encoded)
}

func TestConfirmSignsAndSubmits(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	// Send to address index 2 (not index 0 or 1 which are funding addresses).
	recvAddr := acct.ReceiveAddresses[2]

	fc := newFakeChain(5_000_000, addr0)
	ks := fakeKeystore{mnemonic: testMnemonic}
	s := NewService(fc, ks, acct)

	ctx := context.Background()
	pv, err := s.Build(ctx, SendRequest{To: recvAddr, Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	res, err := s.Confirm(ctx, pv.PendingID, "pw")
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if res.TxHash == "" {
		t.Fatal("expected non-empty TxHash")
	}
	if fc.submitCalls != 1 {
		t.Fatalf("expected SubmitTx called once, got %d", fc.submitCalls)
	}

	// Second Confirm with same id must fail (single-use).
	_, err = s.Confirm(ctx, pv.PendingID, "pw")
	if err == nil {
		t.Fatal("expected error on second Confirm with same pending id, got nil")
	}
	t.Logf("second Confirm correctly rejected: %v", err)
}

func TestBuildRejectsWalletChangedBeforeStore(t *testing.T) {
	acctA := mustDeriveConfirmAccount(t)
	acctB, err := wallet.Derive(differentMnemonic, "preview", 5)
	if err != nil {
		t.Fatalf("derive account B: %v", err)
	}
	fc := newFakeChain(5_000_000, acctA.ReceiveAddresses[0])
	fc.utxosStarted = make(chan struct{}, 1)
	fc.releaseUtxos = make(chan struct{})

	s := NewService(fc, nil, nil)
	s.SetAccount("a", acctA)

	done := make(chan error, 1)
	go func() {
		_, err := s.Build(context.Background(), SendRequest{To: acctA.ReceiveAddresses[2], Lovelace: "1000000"})
		done <- err
	}()

	select {
	case <-fc.utxosStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("Build did not reach Utxos")
	}
	s.SetAccount("b", acctB)
	close(fc.releaseUtxos)

	err = <-done
	if !errors.Is(err, ErrWalletChanged) {
		t.Fatalf("Build after wallet switch = %v, want ErrWalletChanged", err)
	}
}

func TestConfirmUsesPendingWalletAfterAccountSwitch(t *testing.T) {
	acctA := mustDeriveConfirmAccount(t)
	acctB, err := wallet.Derive(differentMnemonic, "preview", 5)
	if err != nil {
		t.Fatalf("derive account B: %v", err)
	}
	fc := newFakeChain(5_000_000, acctA.ReceiveAddresses[0])
	ks := &blockingSeedStore{
		mnemonicByID: map[string]string{"a": testMnemonic, "b": differentMnemonic},
		unlockForID:  make(chan string, 1),
		release:      make(chan struct{}),
	}
	s := NewService(fc, ks, nil)
	s.SetAccount("a", acctA)

	pv, err := s.Build(context.Background(), SendRequest{To: acctA.ReceiveAddresses[2], Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := s.Confirm(context.Background(), pv.PendingID, "pw")
		done <- err
	}()

	var unlockID string
	select {
	case unlockID = <-ks.unlockForID:
	case <-time.After(2 * time.Second):
		t.Fatal("Confirm did not request seed unlock")
	}
	if unlockID != "a" {
		t.Fatalf("Confirm unlocked wallet %q, want pending wallet a", unlockID)
	}

	s.SetAccount("b", acctB)
	close(ks.release)
	if err := <-done; err != nil {
		t.Fatalf("Confirm after account switch: %v", err)
	}
	if fc.submitCalls != 1 {
		t.Fatalf("SubmitTx calls = %d, want 1", fc.submitCalls)
	}
}

func TestSignTxUsesActiveWalletBindingAfterAccountSwitch(t *testing.T) {
	acctA := mustDeriveConfirmAccount(t)
	acctB, err := wallet.Derive(differentMnemonic, "preview", 5)
	if err != nil {
		t.Fatalf("derive account B: %v", err)
	}
	fc := newFakeChain(5_000_000, acctA.ReceiveAddresses[0])
	ks := &blockingSeedStore{
		mnemonicByID: map[string]string{"a": testMnemonic, "b": differentMnemonic},
		unlockForID:  make(chan string, 1),
		release:      make(chan struct{}),
	}
	s := NewService(fc, ks, nil)
	s.SetAccount("a", acctA)

	pv, err := s.Build(context.Background(), SendRequest{To: acctA.ReceiveAddresses[2], Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	unsigned, err := s.ExportUnsigned(pv.PendingID)
	if err != nil {
		t.Fatalf("ExportUnsigned: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := s.SignTx(unsigned.UnsignedTxCBOR, "pw", unsigned.RequiredSigners)
		done <- err
	}()

	var unlockID string
	select {
	case unlockID = <-ks.unlockForID:
	case <-time.After(2 * time.Second):
		t.Fatal("SignTx did not request seed unlock")
	}
	if unlockID != "a" {
		t.Fatalf("SignTx unlocked wallet %q, want active wallet a", unlockID)
	}

	s.SetAccount("b", acctB)
	close(ks.release)
	if err := <-done; err != nil {
		t.Fatalf("SignTx after account switch: %v", err)
	}
}

func TestWalletBoundUnlockRequiresUnlockFor(t *testing.T) {
	ks := &trackingKeystore{mnemonic: testMnemonic}
	s := NewService(nil, ks, nil)

	if _, err := s.unlockSeed("wallet-a", "pw"); err == nil {
		t.Fatal("wallet-bound unlock with generic keystore succeeded, want error")
	} else if !strings.Contains(err.Error(), "UnlockFor") {
		t.Fatalf("wallet-bound unlock error = %v, want UnlockFor support error", err)
	}
	if ks.unlockCalls != 0 {
		t.Fatalf("generic Unlock calls = %d, want 0 for wallet-bound unlock", ks.unlockCalls)
	}

	mnemonic, err := s.unlockSeed("", "pw")
	if err != nil {
		t.Fatalf("legacy unlock: %v", err)
	}
	if string(mnemonic) != testMnemonic {
		t.Fatal("legacy unlock returned wrong mnemonic")
	}
	if ks.unlockCalls != 1 {
		t.Fatalf("generic Unlock calls after legacy unlock = %d, want 1", ks.unlockCalls)
	}
}

func TestSignDataRoundTrip(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	ks := fakeKeystore{mnemonic: testMnemonic}
	s := NewService(newFakeChain(0, addr0), ks, acct)

	msg := []byte("I own this address — proof for dApp login")
	sig, key, err := s.SignData(addr0, msg, "pw")
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}
	if sig == "" || key == "" {
		t.Fatalf("expected non-empty signature and key, got sig=%q key=%q", sig, key)
	}
	// The COSE_Sign1 must verify against the COSE_Key + payload via the keys layer.
	ok, err := bursa.VerifyData(sig, key, msg)
	if err != nil {
		t.Fatalf("VerifyData: %v", err)
	}
	if !ok {
		t.Fatal("CIP-8 signature failed verification")
	}
	// A different payload must NOT verify against the same signature.
	if tampered, _ := bursa.VerifyData(sig, key, []byte("tampered")); tampered {
		t.Fatal("signature verified against the wrong payload")
	}
}

func TestSignDataHardwareRequest(t *testing.T) {
	acct := mustDeriveConfirmAccount(t) // preview network, account index 0
	addr0 := acct.ReceiveAddresses[0]
	s := NewService(newFakeChain(0, addr0), fakeKeystore{mnemonic: testMnemonic}, acct)

	req, err := s.SignDataHardwareRequest(addr0)
	if err != nil {
		t.Fatalf("SignDataHardwareRequest: %v", err)
	}
	if req.SigningPath != "1852'/1815'/0'/0/0" {
		t.Fatalf("SigningPath = %q, want 1852'/1815'/0'/0/0", req.SigningPath)
	}
	if req.StakePath != "1852'/1815'/0'/2/0" {
		t.Fatalf("StakePath = %q, want 1852'/1815'/0'/2/0", req.StakePath)
	}
	if req.NetworkID != 0 || req.ProtocolMagic != 2 { // preview
		t.Fatalf("network = (id %d, magic %d), want (0, 2)", req.NetworkID, req.ProtocolMagic)
	}
	if req.AddressBech32 != addr0 {
		t.Fatalf("AddressBech32 = %q, want %q", req.AddressBech32, addr0)
	}
	// AddressHex must decode to the same raw address bytes.
	addr, err := lcommon.NewAddress(addr0)
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	b, err := addr.Bytes()
	if err != nil {
		t.Fatalf("addr.Bytes: %v", err)
	}
	if req.AddressHex != hex.EncodeToString(b) {
		t.Fatalf("AddressHex = %q, want %q", req.AddressHex, hex.EncodeToString(b))
	}

	// A later receive address resolves to its window index in the payment path.
	req3, err := s.SignDataHardwareRequest(acct.ReceiveAddresses[3])
	if err != nil {
		t.Fatalf("SignDataHardwareRequest[3]: %v", err)
	}
	if req3.SigningPath != "1852'/1815'/0'/0/3" {
		t.Fatalf("SigningPath[3] = %q, want 1852'/1815'/0'/0/3", req3.SigningPath)
	}
}

func TestSignDataHardwareRequestRejectsForeignAddress(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	s := NewService(newFakeChain(0, acct.ReceiveAddresses[0]), fakeKeystore{mnemonic: testMnemonic}, acct)
	foreign, err := wallet.Derive(differentMnemonic, "preview", 5)
	if err != nil {
		t.Fatalf("derive foreign: %v", err)
	}
	if _, err := s.SignDataHardwareRequest(foreign.ReceiveAddresses[0]); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest for a foreign address, got %v", err)
	}
}

func TestSignDataHardwareRequestNoWallet(t *testing.T) {
	s := NewService(newFakeChain(0, ""), fakeKeystore{}, nil)
	if _, err := s.SignDataHardwareRequest("addr_test1xyz"); !errors.Is(err, ErrNoWallet) {
		t.Fatalf("expected ErrNoWallet with no bound account, got %v", err)
	}
}

func TestVerifyDataRoundTrip(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	ks := fakeKeystore{mnemonic: testMnemonic}
	s := NewService(newFakeChain(0, addr0), ks, acct)

	msg := []byte("prove I control this address")
	sig, key, err := s.SignData(addr0, msg, "pw")
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}

	// Verifies, and reports the signer address from the COSE protected header.
	valid, gotAddr, err := s.VerifyData(sig, key, msg, false, "")
	if err != nil {
		t.Fatalf("VerifyData: %v", err)
	}
	if !valid {
		t.Fatal("expected signature to verify")
	}
	if gotAddr != addr0 {
		t.Fatalf("reported signer %q, want %q", gotAddr, addr0)
	}

	// expected_address matching the signer keeps it valid.
	if v, _, _ := s.VerifyData(sig, key, msg, false, addr0); !v {
		t.Fatal("expected valid when expected_address matches signer")
	}
	// A different expected_address makes it invalid (not an error).
	if v, _, err := s.VerifyData(sig, key, msg, false, acct.ReceiveAddresses[1]); err != nil || v {
		t.Fatalf("expected invalid for mismatched expected_address, got valid=%v err=%v", v, err)
	}
	// A tampered message must not verify.
	if v, _, _ := s.VerifyData(sig, key, []byte("tampered"), false, ""); v {
		t.Fatal("tampered message verified")
	}
}

func TestVerifyDataHashedPayload(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	sig, key, msg, addr := hashedSignDataFixture(t, acct)
	s := NewService(newFakeChain(0, addr), fakeKeystore{mnemonic: testMnemonic}, acct)

	valid, gotAddr, err := s.VerifyData(sig, key, msg, true, addr)
	if err != nil {
		t.Fatalf("VerifyData: %v", err)
	}
	if !valid {
		t.Fatal("expected hashed payload signature to verify")
	}
	if gotAddr != addr {
		t.Fatalf("reported signer %q, want %q", gotAddr, addr)
	}
}

func TestVerifyDataRejectsHashedFlagMismatch(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	addr := acct.ReceiveAddresses[0]
	s := NewService(newFakeChain(0, addr), fakeKeystore{mnemonic: testMnemonic}, acct)

	msg := []byte("prove I control this address")
	sig, key, err := s.SignData(addr, msg, "pw")
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}
	if _, _, err := s.VerifyData(sig, key, msg, true, ""); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest for unhashed signature with hashed=true, got %v", err)
	}

	hashedSig, hashedKey, hashedMsg, _ := hashedSignDataFixture(t, acct)
	if _, _, err := s.VerifyData(hashedSig, hashedKey, hashedMsg, false, ""); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest for hashed signature with hashed=false, got %v", err)
	}
}

func TestVerifyDataMalformedReturnsInvalidRequest(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	s := NewService(newFakeChain(0, acct.ReceiveAddresses[0]), fakeKeystore{mnemonic: testMnemonic}, acct)
	if _, _, err := s.VerifyData("zz", "a4", []byte("x"), false, ""); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest for bad hex, got %v", err)
	}
}

// TestAirGapRoundTrip exercises the split flow: Build → ExportUnsigned (online)
// → SignTx (offline) → SubmitSigned (online). The submitted tx must carry the
// exact witnesses the inputs require and submit once.
func TestAirGapRoundTrip(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	recvAddr := acct.ReceiveAddresses[2]

	fc := newFakeChain(5_000_000, addr0)
	ks := fakeKeystore{mnemonic: testMnemonic}
	s := NewService(fc, ks, acct)

	ctx := context.Background()
	pv, err := s.Build(ctx, SendRequest{To: recvAddr, Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Export the unsigned tx + required signers (online instance).
	unsigned, err := s.ExportUnsigned(pv.PendingID)
	if err != nil {
		t.Fatalf("ExportUnsigned: %v", err)
	}
	if unsigned.UnsignedTxCBOR == "" {
		t.Fatal("expected non-empty unsigned tx cbor")
	}
	if len(unsigned.RequiredSigners) != 1 {
		t.Fatalf("required signers = %d (%v), want 1", len(unsigned.RequiredSigners), unsigned.RequiredSigners)
	}

	// Sign offline (keystore + password, no chain access used).
	wit, err := s.SignTx(unsigned.UnsignedTxCBOR, "pw", unsigned.RequiredSigners)
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}
	if wit.WitnessCBOR == "" {
		t.Fatal("expected non-empty witness cbor")
	}
	if got := witnessCount(t, wit); got != len(unsigned.RequiredSigners) {
		t.Fatalf("offline witnesses = %d, want %d", got, len(unsigned.RequiredSigners))
	}

	// Submit on the online instance: attaches only the needed witness.
	res, err := s.SubmitSigned(ctx, unsigned.UnsignedTxCBOR, wit.WitnessCBOR)
	if err != nil {
		t.Fatalf("SubmitSigned: %v", err)
	}
	if res.TxHash == "" {
		t.Fatal("expected non-empty tx hash")
	}
	if fc.submitCalls != 1 {
		t.Fatalf("SubmitTx calls = %d, want 1", fc.submitCalls)
	}

	// The broadcast tx must carry exactly one vkey witness (the single input
	// address).
	submitted, err := ledger.NewConwayTransactionFromCbor(fc.submittedTxCbor())
	if err != nil {
		t.Fatalf("decode submitted tx: %v", err)
	}
	if got := len(submitted.WitnessSet.VkeyWitnesses.Items()); got != 1 {
		t.Fatalf("submitted vkey witnesses = %d, want 1", got)
	}
}

func TestExportUnsignedBindsRequiredSignersInBody(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	fc := newFakeChain(5_000_000, acct.ReceiveAddresses[0])
	s := NewService(fc, fakeKeystore{mnemonic: testMnemonic}, acct)

	pv, err := s.Build(context.Background(), SendRequest{
		To:       acct.ReceiveAddresses[2],
		Lovelace: "1000000",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	unsigned, err := s.ExportUnsigned(pv.PendingID)
	if err != nil {
		t.Fatalf("ExportUnsigned: %v", err)
	}

	sidecar, err := parseRequiredSignerHashes(unsigned.RequiredSigners)
	if err != nil {
		t.Fatalf("parse exported required signers: %v", err)
	}
	body := bodyRequiredSigners(t, unsigned.UnsignedTxCBOR)
	if !sameKeyHashSet(sidecar, body) {
		t.Fatalf("body required signers %v do not match sidecar %v", keyHashesHex(body), unsigned.RequiredSigners)
	}
}

func TestSignTxRejectsSidecarMismatchBeforeUnlock(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	fc := newFakeChain(5_000_000, acct.ReceiveAddresses[0])
	ks := &trackingKeystore{mnemonic: testMnemonic}
	s := NewService(fc, ks, acct)

	pv, err := s.Build(context.Background(), SendRequest{
		To:       acct.ReceiveAddresses[2],
		Lovelace: "1000000",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	unsigned, err := s.ExportUnsigned(pv.PendingID)
	if err != nil {
		t.Fatalf("ExportUnsigned: %v", err)
	}

	tests := []struct {
		name    string
		signers []string
	}{
		{
			name: "extra wallet payment key",
			signers: append(
				append([]string(nil), unsigned.RequiredSigners...),
				paymentKeyHashForAddress(t, acct.ReceiveAddresses[1]),
			),
		},
		{
			name:    "stake key only",
			signers: []string{stakeKeyHashForAddress(t, acct.ReceiveAddresses[0])},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := s.SignTx(unsigned.UnsignedTxCBOR, "pw", tt.signers); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("expected ErrInvalidRequest, got %v", err)
			}
		})
	}
	if ks.unlockCalls != 0 {
		t.Fatalf("SignTx unlocked keystore %d times for mismatched sidecar", ks.unlockCalls)
	}
}

func TestSignTxHashesOriginalBodyCbor(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	fc := newFakeChain(5_000_000, acct.ReceiveAddresses[0])
	s := NewService(fc, fakeKeystore{mnemonic: testMnemonic}, acct)

	pv, err := s.Build(context.Background(), SendRequest{
		To:       acct.ReceiveAddresses[2],
		Lovelace: "1000000",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	unsigned, err := s.ExportUnsigned(pv.PendingID)
	if err != nil {
		t.Fatalf("ExportUnsigned: %v", err)
	}

	driftedTx := unsignedWithIndefiniteBodyMap(t, unsigned.UnsignedTxCBOR)
	txBytes, err := hex.DecodeString(driftedTx)
	if err != nil {
		t.Fatalf("decode drifted tx hex: %v", err)
	}
	tx, err := ledger.NewConwayTransactionFromCbor(txBytes)
	if err != nil {
		t.Fatalf("decode drifted tx: %v", err)
	}
	originalBodyHash := lcommon.Blake2b256Hash(tx.Body.Cbor())
	reencodedBody, err := cbor.Encode(&tx.Body)
	if err != nil {
		t.Fatalf("re-encode drifted body: %v", err)
	}
	reencodedBodyHash := lcommon.Blake2b256Hash(reencodedBody)
	if originalBodyHash == reencodedBodyHash {
		t.Fatal("test fixture did not create a body CBOR hash drift")
	}

	wit, err := s.SignTx(driftedTx, "pw", unsigned.RequiredSigners)
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}
	witnesses := decodeWitnesses(t, wit)
	if len(witnesses) != 1 {
		t.Fatalf("offline witnesses = %d, want 1", len(witnesses))
	}
	if err := lcommon.VerifyVKeySignature(witnesses[0].Vkey, witnesses[0].Signature, originalBodyHash.Bytes()); err != nil {
		t.Fatalf("witness does not verify against original body hash: %v", err)
	}
	if err := lcommon.VerifyVKeySignature(witnesses[0].Vkey, witnesses[0].Signature, reencodedBodyHash.Bytes()); err == nil {
		t.Fatal("witness unexpectedly verifies against re-encoded body hash")
	}
}

func TestSubmitSignedAttachesBodyRequiredSigner(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	fc := newFakeChain(5_000_000, acct.ReceiveAddresses[0])
	s := NewService(fc, fakeKeystore{mnemonic: testMnemonic}, acct)

	ctx := context.Background()
	pv, err := s.Build(ctx, SendRequest{To: acct.ReceiveAddresses[2], Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	unsigned, err := s.ExportUnsigned(pv.PendingID)
	if err != nil {
		t.Fatalf("ExportUnsigned: %v", err)
	}

	required := bodyRequiredSigners(t, unsigned.UnsignedTxCBOR)
	stakeRequired, err := parseRequiredSignerHashes([]string{stakeKeyHashForAddress(t, acct.ReceiveAddresses[0])})
	if err != nil {
		t.Fatalf("parse stake signer: %v", err)
	}
	required = append(required, stakeRequired...)
	mutatedTx := unsignedWithRequiredSigners(t, unsigned.UnsignedTxCBOR, required)
	wit, err := s.SignTx(mutatedTx, "pw", keyHashesHex(required))
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}
	if got := witnessCount(t, wit); got != 2 {
		t.Fatalf("offline witnesses = %d, want 2", got)
	}
	if _, err := s.SubmitSigned(ctx, mutatedTx, wit.WitnessCBOR); err != nil {
		t.Fatalf("SubmitSigned: %v", err)
	}
	submitted, err := ledger.NewConwayTransactionFromCbor(fc.submittedTxCbor())
	if err != nil {
		t.Fatalf("decode submitted tx: %v", err)
	}
	if got := len(submitted.WitnessSet.VkeyWitnesses.Items()); got != 2 {
		t.Fatalf("submitted vkey witnesses = %d, want 2", got)
	}
}

// TestAirGapMultiInput checks the split flow attaches one witness per distinct
// input address when coin selection spans two addresses.
func TestAirGapMultiInput(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	addr1 := acct.ReceiveAddresses[1]
	recvAddr := acct.ReceiveAddresses[2]

	fc := newFakeChain(3_000_000, addr0)
	fc.addUTxO(3_000_000, addr1, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0", 0)
	s := NewService(fc, fakeKeystore{mnemonic: testMnemonic}, acct)

	ctx := context.Background()
	pv, err := s.Build(ctx, SendRequest{To: recvAddr, Lovelace: "4000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	unsigned, err := s.ExportUnsigned(pv.PendingID)
	if err != nil {
		t.Fatalf("ExportUnsigned: %v", err)
	}
	if len(unsigned.RequiredSigners) != 2 {
		t.Fatalf("required signers = %d, want 2", len(unsigned.RequiredSigners))
	}
	wit, err := s.SignTx(unsigned.UnsignedTxCBOR, "pw", unsigned.RequiredSigners)
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}
	if got := witnessCount(t, wit); got != len(unsigned.RequiredSigners) {
		t.Fatalf("offline witnesses = %d, want %d", got, len(unsigned.RequiredSigners))
	}
	if _, err := s.SubmitSigned(ctx, unsigned.UnsignedTxCBOR, wit.WitnessCBOR); err != nil {
		t.Fatalf("SubmitSigned: %v", err)
	}
	submitted, err := ledger.NewConwayTransactionFromCbor(fc.submittedTxCbor())
	if err != nil {
		t.Fatalf("decode submitted tx: %v", err)
	}
	if got := len(submitted.WitnessSet.VkeyWitnesses.Items()); got != 2 {
		t.Fatalf("submitted vkey witnesses = %d, want 2", got)
	}
}

func TestExportUnsignedUnknownPending(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	s := NewService(newFakeChain(5_000_000, acct.ReceiveAddresses[0]), fakeKeystore{mnemonic: testMnemonic}, acct)
	if _, err := s.ExportUnsigned("nope"); !errors.Is(err, ErrUnknownPending) {
		t.Fatalf("expected ErrUnknownPending, got %v", err)
	}
}

func TestSignTxWrongPassword(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	fc := newFakeChain(5_000_000, addr0)
	s := NewService(fc, fakeKeystore{mnemonic: testMnemonic}, acct)

	ctx := context.Background()
	pv, err := s.Build(ctx, SendRequest{To: acct.ReceiveAddresses[2], Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	unsigned, err := s.ExportUnsigned(pv.PendingID)
	if err != nil {
		t.Fatalf("ExportUnsigned: %v", err)
	}
	// A service whose keystore rejects the password.
	bad := NewService(fc, fakeKeystore{err: keystore.ErrDecryptFailed}, acct)
	if _, err := bad.SignTx(unsigned.UnsignedTxCBOR, "wrong", unsigned.RequiredSigners); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("expected ErrWrongPassword, got %v", err)
	}
}

func TestSignTxInvalidCbor(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	s := NewService(newFakeChain(0, acct.ReceiveAddresses[0]), fakeKeystore{mnemonic: testMnemonic}, acct)
	if _, err := s.SignTx("zzzz", "pw", nil); !errors.Is(err, ErrInvalidTx) {
		t.Fatalf("expected ErrInvalidTx, got %v", err)
	}
}

func TestSubmitSignedRejectsMismatchedWitness(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	fc := newFakeChain(5_000_000, addr0)
	s := NewService(fc, fakeKeystore{mnemonic: testMnemonic}, acct)

	ctx := context.Background()
	pv, err := s.Build(ctx, SendRequest{To: acct.ReceiveAddresses[2], Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	unsigned, err := s.ExportUnsigned(pv.PendingID)
	if err != nil {
		t.Fatalf("ExportUnsigned: %v", err)
	}

	// Sign with a DIFFERENT wallet's keys: the witnesses won't match the inputs'
	// required signers, so SubmitSigned must reject and never broadcast. The
	// foreign service uses a different wallet and emits that wallet's witness,
	// so SubmitSigned must reject it against acct's input signer set.
	foreignAcct, err := wallet.Derive(differentMnemonic, "preview", 5)
	if err != nil {
		t.Fatalf("derive foreign account: %v", err)
	}
	foreign := NewService(fc, fakeKeystore{mnemonic: differentMnemonic}, foreignAcct)
	foreignRequired, err := parseRequiredSignerHashes([]string{
		paymentKeyHashForAddress(t, foreignAcct.ReceiveAddresses[0]),
	})
	if err != nil {
		t.Fatalf("parse foreign required signer: %v", err)
	}
	foreignTx := unsignedWithRequiredSigners(t, unsigned.UnsignedTxCBOR, foreignRequired)
	wit, err := foreign.SignTx(
		foreignTx,
		"pw",
		keyHashesHex(foreignRequired),
	)
	if err != nil {
		t.Fatalf("foreign SignTx: %v", err)
	}
	if _, err := s.SubmitSigned(ctx, unsigned.UnsignedTxCBOR, wit.WitnessCBOR); !errors.Is(err, ErrInvalidWitness) {
		t.Fatalf("expected ErrInvalidWitness for foreign witness, got %v", err)
	}
	if fc.submitCalls != 0 {
		t.Fatalf("foreign witness reached SubmitTx (%d calls)", fc.submitCalls)
	}
}

func TestSignDataRejectsForeignAddress(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	ks := fakeKeystore{mnemonic: testMnemonic}
	s := NewService(newFakeChain(0, acct.ReceiveAddresses[0]), ks, acct)
	// An address the wallet does not own (outside the derived window) is rejected
	// before any signing.
	_, _, err := s.SignData("addr_test1qqqqqforeignnotours", []byte("x"), "pw")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest for a foreign address, got %v", err)
	}
}

func TestSignDataWrongPassword(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	ks := fakeKeystore{err: keystore.ErrDecryptFailed}
	s := NewService(newFakeChain(0, addr0), ks, acct)
	_, _, err := s.SignData(addr0, []byte("x"), "wrong")
	if !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("expected ErrWrongPassword, got %v", err)
	}
}

func TestConfirmConsumesPendingBeforeSubmit(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	recvAddr := acct.ReceiveAddresses[2]

	fc := newFakeChain(5_000_000, addr0)
	fc.submitStarted = make(chan struct{}, 2)
	fc.releaseSubmit = make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			close(fc.releaseSubmit)
		})
	}
	defer release()

	s := NewService(fc, fakeKeystore{mnemonic: testMnemonic}, acct)
	pv, err := s.Build(context.Background(), SendRequest{To: recvAddr, Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	firstDone := make(chan error, 1)
	go func() {
		_, err := s.Confirm(context.Background(), pv.PendingID, "pw")
		firstDone <- err
	}()

	select {
	case <-fc.submitStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("first Confirm did not reach SubmitTx")
	}

	secondDone := make(chan error, 1)
	go func() {
		_, err := s.Confirm(context.Background(), pv.PendingID, "pw")
		secondDone <- err
	}()

	var secondErr error
	select {
	case secondErr = <-secondDone:
		if !errors.Is(secondErr, ErrUnknownPending) {
			t.Fatalf("second Confirm error = %v, want ErrUnknownPending", secondErr)
		}
	case <-fc.submitStarted:
		release()
		firstErr := <-firstDone
		secondErr = <-secondDone
		t.Fatalf("second Confirm reached SubmitTx; first err=%v second err=%v", firstErr, secondErr)
	case <-time.After(2 * time.Second):
		release()
		firstErr := <-firstDone
		t.Fatalf("second Confirm did not return while first was submitting; first err=%v", firstErr)
	}

	release()
	if err := <-firstDone; err != nil {
		t.Fatalf("first Confirm: %v", err)
	}
	if fc.submitCalls != 1 {
		t.Fatalf("SubmitTx calls = %d, want 1", fc.submitCalls)
	}
}

func TestConfirmWrongPassword(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	recvAddr := acct.ReceiveAddresses[2]

	fc := newFakeChain(5_000_000, addr0)
	ks := fakeKeystore{err: keystore.ErrDecryptFailed}
	s := NewService(fc, ks, acct)

	ctx := context.Background()
	pv, err := s.Build(ctx, SendRequest{To: recvAddr, Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	_, err = s.Confirm(ctx, pv.PendingID, "wrongpw")
	if !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("expected ErrWrongPassword, got %v", err)
	}
	if fc.submitCalls != 0 {
		t.Fatalf("expected SubmitTx not called, got %d calls", fc.submitCalls)
	}
	t.Logf("correctly rejected with: %v", err)
}

func TestConfirmUnlockInfrastructureErrorIsNotWrongPassword(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	recvAddr := acct.ReceiveAddresses[2]

	fc := newFakeChain(5_000_000, addr0)
	ks := fakeKeystore{err: errors.New("keystore read failed")}
	s := NewService(fc, ks, acct)

	ctx := context.Background()
	pv, err := s.Build(ctx, SendRequest{To: recvAddr, Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	_, err = s.Confirm(ctx, pv.PendingID, "pw")
	if err == nil {
		t.Fatal("expected Confirm error")
	}
	if errors.Is(err, ErrWrongPassword) {
		t.Fatalf("infrastructure unlock error mapped to ErrWrongPassword: %v", err)
	}
	if fc.submitCalls != 0 {
		t.Fatalf("expected SubmitTx not called, got %d calls", fc.submitCalls)
	}
}

func TestConfirmUnknownPending(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	fc := newFakeChain(5_000_000, acct.ReceiveAddresses[0])
	s := NewService(fc, fakeKeystore{mnemonic: testMnemonic}, acct)

	_, err := s.Confirm(context.Background(), "does-not-exist", "pw")
	if !errors.Is(err, ErrUnknownPending) {
		t.Fatalf("expected ErrUnknownPending, got %v", err)
	}
}

func TestConfirmExpiredPending(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	fc := newFakeChain(5_000_000, acct.ReceiveAddresses[0])
	s := NewService(fc, fakeKeystore{mnemonic: testMnemonic}, acct)

	pv, err := s.Build(context.Background(), SendRequest{To: acct.ReceiveAddresses[2], Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// Advance the service clock past the pending TTL so Confirm sees it expired.
	s.now = func() time.Time { return time.Now().Add(pendingTTL + time.Second) }

	_, err = s.Confirm(context.Background(), pv.PendingID, "pw")
	if !errors.Is(err, ErrExpiredPending) {
		t.Fatalf("expected ErrExpiredPending, got %v", err)
	}
	if fc.submitCalls != 0 {
		t.Fatalf("expected no submit on an expired pending, got %d", fc.submitCalls)
	}
}

func TestConfirmMultiInput(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	addr1 := acct.ReceiveAddresses[1]
	recvAddr := acct.ReceiveAddresses[2]

	// Fund both addr0 and addr1 with 3 ADA each so coin selection uses both.
	fc := newFakeChain(3_000_000, addr0)
	fc.addUTxO(3_000_000, addr1, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0", 0)

	ks := fakeKeystore{mnemonic: testMnemonic}
	s := NewService(fc, ks, acct)

	ctx := context.Background()
	// Request 4 ADA to force use of both UTxOs (each addr only has 3 ADA).
	pv, err := s.Build(ctx, SendRequest{To: recvAddr, Lovelace: "4000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(pv.Inputs) != 2 {
		t.Fatalf("Build selected %d inputs (%v), want 2", len(pv.Inputs), pv.Inputs)
	}

	res, err := s.Confirm(ctx, pv.PendingID, "pw")
	if err != nil {
		t.Fatalf("Confirm multi-input: %v", err)
	}
	if res.TxHash == "" {
		t.Fatal("expected non-empty TxHash")
	}
	if fc.submitCalls != 1 {
		t.Fatalf("expected SubmitTx called once, got %d", fc.submitCalls)
	}

	submitted, err := ledger.NewConwayTransactionFromCbor(fc.submittedTxCbor())
	if err != nil {
		t.Fatalf("decode submitted tx: %v", err)
	}
	if got := len(submitted.Body.TxInputs.Items()); got != 2 {
		t.Fatalf("submitted tx inputs = %d, want 2", got)
	}
	if got := len(submitted.WitnessSet.VkeyWitnesses.Items()); got != 2 {
		t.Fatalf("submitted tx vkey witnesses = %d, want 2", got)
	}
}

func TestWitnessTxRequiredSignerIncludesStakeAndDRepKeys(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)

	rootKey, err := bursa.GetRootKeyFromMnemonic(testMnemonic, "")
	if err != nil {
		t.Fatalf("GetRootKeyFromMnemonic: %v", err)
	}
	acctKey, err := bursa.GetAccountKey(rootKey, 0)
	if err != nil {
		t.Fatalf("GetAccountKey: %v", err)
	}
	stakeKey, err := bursa.GetStakeKey(acctKey, 0)
	if err != nil {
		t.Fatalf("GetStakeKey: %v", err)
	}
	drepKey, err := bursa.GetDRepKey(acctKey, 0)
	if err != nil {
		t.Fatalf("GetDRepKey: %v", err)
	}
	stakeVkey := append([]byte(nil), bip32.XPrv(stakeKey).Public().PublicKey()...)
	drepVkey := append([]byte(nil), bip32.XPrv(drepKey).Public().PublicKey()...)
	bodyCbor, err := cbor.Encode(conway.ConwayTransactionBody{
		TxRequiredSigners: cbor.NewSetType([]lcommon.Blake2b224{
			lcommon.Blake2b224Hash(stakeVkey),
			lcommon.Blake2b224Hash(drepVkey),
		}, true),
	})
	if err != nil {
		t.Fatalf("encode body: %v", err)
	}

	s := NewService(nil, fakeKeystore{mnemonic: testMnemonic}, acct)
	wsCbor, err := s.WitnessTx(
		"",
		bodyCbor,
		[]lcommon.Blake2b224{
			lcommon.Blake2b224Hash(stakeVkey),
			lcommon.Blake2b224Hash(drepVkey),
		},
		nil,
		"pw",
		false,
	)
	if err != nil {
		t.Fatalf("WitnessTx: %v", err)
	}

	var ws conway.ConwayTransactionWitnessSet
	if _, err := cbor.Decode(wsCbor, &ws); err != nil {
		t.Fatalf("decode witness set: %v", err)
	}
	got := map[string]bool{}
	for _, w := range ws.VkeyWitnesses.Items() {
		got[hex.EncodeToString(w.Vkey)] = true
	}
	if !got[hex.EncodeToString(stakeVkey)] {
		t.Fatalf("missing stake key witness; got %v", got)
	}
	if !got[hex.EncodeToString(drepVkey)] {
		t.Fatalf("missing DRep key witness; got %v", got)
	}
}

func TestWitnessTxIncludesCertificateAndWithdrawalKeysWithoutRequiredSigners(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)

	rootKey, err := bursa.GetRootKeyFromMnemonic(testMnemonic, "")
	if err != nil {
		t.Fatalf("GetRootKeyFromMnemonic: %v", err)
	}
	acctKey, err := bursa.GetAccountKey(rootKey, 0)
	if err != nil {
		t.Fatalf("GetAccountKey: %v", err)
	}
	stakeKey, err := bursa.GetStakeKey(acctKey, 0)
	if err != nil {
		t.Fatalf("GetStakeKey: %v", err)
	}
	drepKey, err := bursa.GetDRepKey(acctKey, 0)
	if err != nil {
		t.Fatalf("GetDRepKey: %v", err)
	}
	stakeVkey := append([]byte(nil), bip32.XPrv(stakeKey).Public().PublicKey()...)
	drepVkey := append([]byte(nil), bip32.XPrv(drepKey).Public().PublicKey()...)
	drepHash := lcommon.Blake2b224Hash(drepVkey)

	stakeAddr, err := lcommon.NewAddress(acct.StakeAddress)
	if err != nil {
		t.Fatalf("NewAddress(stake): %v", err)
	}
	bodyCbor, err := cbor.Encode(conway.ConwayTransactionBody{
		TxWithdrawals: map[*lcommon.Address]uint64{
			&stakeAddr: 1,
		},
		TxCertificates: []lcommon.CertificateWrapper{{
			Type: uint(lcommon.CertificateTypeUpdateDrep),
			Certificate: &lcommon.UpdateDrepCertificate{
				CertType: uint(lcommon.CertificateTypeUpdateDrep),
				DrepCredential: lcommon.Credential{
					CredType:   lcommon.CredentialTypeAddrKeyHash,
					Credential: drepHash,
				},
			},
		}},
	})
	if err != nil {
		t.Fatalf("encode body: %v", err)
	}

	s := NewService(nil, fakeKeystore{mnemonic: testMnemonic}, acct)
	wsCbor, err := s.WitnessTx("", bodyCbor, nil, nil, "pw", false)
	if err != nil {
		t.Fatalf("WitnessTx: %v", err)
	}

	var ws conway.ConwayTransactionWitnessSet
	if _, err := cbor.Decode(wsCbor, &ws); err != nil {
		t.Fatalf("decode witness set: %v", err)
	}
	got := map[string]bool{}
	for _, w := range ws.VkeyWitnesses.Items() {
		got[hex.EncodeToString(w.Vkey)] = true
	}
	if !got[hex.EncodeToString(stakeVkey)] {
		t.Fatalf("missing withdrawal stake key witness; got %v", got)
	}
	if !got[hex.EncodeToString(drepVkey)] {
		t.Fatalf("missing certificate DRep key witness; got %v", got)
	}
}

// TestWitnessTxNonPartialRejectsCommitteeCertColdKey verifies that a committee
// authorization/resignation certificate whose cold credential the wallet cannot
// witness does not slip through the non-partial completeness check just because
// the transaction also has a wallet-owned payment input. The wallet never
// derives committee cold keys, so with partialSign=false the request must fail
// closed rather than return a witness set that silently omits the required
// committee witness. With partialSign=true the wallet may still return the
// payment witness it can provide.
func TestWitnessTxNonPartialRejectsCommitteeCertColdKey(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	// A foreign committee cold credential the wallet does not own.
	committeeColdHash := lcommon.Blake2b224Hash([]byte("committee cold key"))

	certCases := []struct {
		name string
		cert lcommon.CertificateWrapper
	}{
		{
			name: "AuthCommitteeHot",
			cert: lcommon.CertificateWrapper{
				Type: uint(lcommon.CertificateTypeAuthCommitteeHot),
				Certificate: &lcommon.AuthCommitteeHotCertificate{
					CertType: uint(lcommon.CertificateTypeAuthCommitteeHot),
					ColdCredential: lcommon.Credential{
						CredType:   lcommon.CredentialTypeAddrKeyHash,
						Credential: committeeColdHash,
					},
					HotCredential: lcommon.Credential{
						CredType:   lcommon.CredentialTypeAddrKeyHash,
						Credential: lcommon.Blake2b224Hash([]byte("committee hot key")),
					},
				},
			},
		},
		{
			name: "ResignCommitteeCold",
			cert: lcommon.CertificateWrapper{
				Type: uint(lcommon.CertificateTypeResignCommitteeCold),
				Certificate: &lcommon.ResignCommitteeColdCertificate{
					CertType: uint(lcommon.CertificateTypeResignCommitteeCold),
					ColdCredential: lcommon.Credential{
						CredType:   lcommon.CredentialTypeAddrKeyHash,
						Credential: committeeColdHash,
					},
				},
			},
		},
	}

	for _, tc := range certCases {
		t.Run(tc.name, func(t *testing.T) {
			bodyCbor, err := cbor.Encode(conway.ConwayTransactionBody{
				TxCertificates: []lcommon.CertificateWrapper{tc.cert},
			})
			if err != nil {
				t.Fatalf("encode body: %v", err)
			}

			s := NewService(nil, fakeKeystore{mnemonic: testMnemonic}, acct)
			// A wallet-owned input provides a payment witness. Before the fix this
			// alone satisfied the completeness check while the committee cold-key
			// witness was silently dropped.
			inputAddrs := []string{acct.ReceiveAddresses[0]}

			if _, err := s.WitnessTx("", bodyCbor, nil, inputAddrs, "pw", false); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("WitnessTx(partialSign=false) = %v, want ErrInvalidRequest", err)
			}

			wsCbor, err := s.WitnessTx("", bodyCbor, nil, inputAddrs, "pw", true)
			if err != nil {
				t.Fatalf("WitnessTx(partialSign=true): %v", err)
			}
			var ws conway.ConwayTransactionWitnessSet
			if _, err := cbor.Decode(wsCbor, &ws); err != nil {
				t.Fatalf("decode witness set: %v", err)
			}
			if got := len(ws.VkeyWitnesses.Items()); got != 1 {
				t.Fatalf("partial witness count = %d, want 1 (payment key only)", got)
			}
		})
	}
}

func TestWitnessTxNonPartialRejectsUnmatchedRequiredSigner(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)

	rootKey, err := bursa.GetRootKeyFromMnemonic(testMnemonic, "")
	if err != nil {
		t.Fatalf("GetRootKeyFromMnemonic: %v", err)
	}
	acctKey, err := bursa.GetAccountKey(rootKey, 0)
	if err != nil {
		t.Fatalf("GetAccountKey: %v", err)
	}
	payKey, err := bursa.GetPaymentKey(acctKey, 0)
	if err != nil {
		t.Fatalf("GetPaymentKey: %v", err)
	}
	ownedHash := lcommon.Blake2b224Hash(bip32.XPrv(payKey).Public().PublicKey())
	foreignHash := lcommon.Blake2b224Hash([]byte("foreign required signer"))
	required := []lcommon.Blake2b224{ownedHash, foreignHash}
	bodyCbor, err := cbor.Encode(conway.ConwayTransactionBody{
		TxRequiredSigners: cbor.NewSetType(required, true),
	})
	if err != nil {
		t.Fatalf("encode body: %v", err)
	}

	s := NewService(nil, fakeKeystore{mnemonic: testMnemonic}, acct)
	if _, err := s.WitnessTx("", bodyCbor, required, nil, "pw", false); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("WitnessTx(partialSign=false) = %v, want ErrInvalidRequest", err)
	}

	wsCbor, err := s.WitnessTx("", bodyCbor, required, nil, "pw", true)
	if err != nil {
		t.Fatalf("WitnessTx(partialSign=true): %v", err)
	}
	var ws conway.ConwayTransactionWitnessSet
	if _, err := cbor.Decode(wsCbor, &ws); err != nil {
		t.Fatalf("decode witness set: %v", err)
	}
	if got := len(ws.VkeyWitnesses.Items()); got != 1 {
		t.Fatalf("partial witness count = %d, want 1", got)
	}
}

// TestWitnessTxRejectsWalletChanged verifies that WitnessTx fails closed with
// ErrWalletChanged when the walletID passed by the caller (captured when it
// resolved inputAddrs/requiredSignerHashes) no longer matches the currently
// active wallet. This guards the connector signing path: if the active wallet
// changes while a dApp signTx approval is pending, WitnessTx must not silently
// derive witnesses from the newly active wallet.
func TestWitnessTxRejectsWalletChanged(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	s := NewService(nil, fakeKeystore{mnemonic: testMnemonic}, nil)
	s.SetAccount("a", acct)

	_, err := s.WitnessTx(
		"b", // caller's stale binding; "a" is now the active wallet.
		[]byte("tx-body"),
		nil,
		nil,
		"pw",
		true,
	)
	if !errors.Is(err, ErrWalletChanged) {
		t.Fatalf("WitnessTx with stale walletID = %v, want ErrWalletChanged", err)
	}
}

// mustNewAddress is a test helper that converts a bech32 address string and
// fails the test if it cannot be parsed.
func mustNewAddress(t *testing.T, addr string) lcommon.Address {
	t.Helper()
	a, err := lcommon.NewAddress(addr)
	if err != nil {
		t.Fatalf("lcommon.NewAddress(%q): %v", addr, err)
	}
	return a
}

// TestSetWalletCreatesKeystoreAndEnablesBuild exercises the SetWallet lifecycle
// against a real keystore: before SetWallet, Build reports ErrNoWallet; after,
// the keystore exists and Build works; re-attaching needs the correct password.
func TestSetWalletCreatesKeystoreAndEnablesBuild(t *testing.T) {
	ks := keystore.New(filepath.Join(t.TempDir(), "keystore.json"))
	acct := mustDeriveConfirmAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	recvAddr := acct.ReceiveAddresses[2]
	fc := newFakeChain(5_000_000, addr0)

	// No account yet: Build must report ErrNoWallet.
	s := NewService(fc, ks, nil)
	if _, err := s.Build(context.Background(), SendRequest{To: recvAddr, Lovelace: "1000000"}); !errors.Is(err, ErrNoWallet) {
		t.Fatalf("Build before SetWallet: got %v, want ErrNoWallet", err)
	}

	// SetWallet derives the account and creates the keystore.
	got, err := s.SetWallet(testMnemonic, "preview", "spend-password-1")
	if err != nil {
		t.Fatalf("SetWallet: %v", err)
	}
	if !ks.Exists() {
		t.Fatal("keystore should exist after SetWallet")
	}
	if len(got.ReceiveAddresses) == 0 || got.ReceiveAddresses[0] != addr0 {
		t.Fatalf("derived account mismatch: %+v", got)
	}

	// Build now succeeds.
	if pv, err := s.Build(context.Background(), SendRequest{To: recvAddr, Lovelace: "1000000"}); err != nil {
		t.Fatalf("Build after SetWallet: %v", err)
	} else if pv.PendingID == "" {
		t.Fatal("expected non-empty pending id")
	}

	// Re-attach: correct password unlocks the existing keystore; wrong fails.
	if _, err := s.SetWallet(testMnemonic, "preview", "spend-password-1"); err != nil {
		t.Fatalf("SetWallet re-attach with correct password: %v", err)
	}
	if _, err := s.SetWallet(testMnemonic, "preview", "wrong-password-9"); err == nil {
		t.Fatal("SetWallet re-attach with wrong password should fail")
	}
	if _, err := s.SetWallet(differentMnemonic, "preview", "spend-password-1"); err == nil {
		t.Fatal("SetWallet re-attach with different mnemonic should fail")
	}
}

func TestHardwareSignRequest(t *testing.T) {
	acct := mustDeriveTestAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	recipientAcct, err := wallet.Derive(differentMnemonic, "preview", 1)
	if err != nil {
		t.Fatalf("derive recipient account: %v", err)
	}
	recipientAddr := recipientAcct.ReceiveAddresses[0]

	fc := newFakeChain(10_000_000, addr0)
	s := NewService(fc, nil, acct)

	// Build a pending transaction.
	pv, err := s.Build(context.Background(), SendRequest{To: recipientAddr, Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Get the hardware sign request.
	req, err := s.HardwareSignRequest(pv.PendingID)
	if err != nil {
		t.Fatalf("HardwareSignRequest: %v", err)
	}

	// Verify basic fields.
	if req.Network != "preview" {
		t.Fatalf("Network = %q, want preview", req.Network)
	}
	if req.NetworkID != 0 {
		t.Fatalf("NetworkID = %d, want 0", req.NetworkID)
	}
	if req.ProtocolMagic != 2 {
		t.Fatalf("ProtocolMagic = %d, want 2", req.ProtocolMagic)
	}
	if req.BodySetTagPolicy != "untagged" {
		t.Fatalf("BodySetTagPolicy = %q, want untagged", req.BodySetTagPolicy)
	}
	if !req.IncludeNetworkID {
		t.Fatal("IncludeNetworkID must preserve the network-id field from the payment body")
	}
	if req.Unsupported != "" {
		t.Fatalf("Unsupported must be empty for simple payment, got %q", req.Unsupported)
	}
	if req.Fee == "" || req.Fee == "0" {
		t.Fatalf("Fee = %q, want non-zero", req.Fee)
	}
	if req.UnsignedTxCBOR == "" {
		t.Fatal("UnsignedTxCBOR must not be empty")
	}
	wantRequired := keyHashesHex(bodyRequiredSigners(t, req.UnsignedTxCBOR))
	if !equalStringSets(req.RequiredSigners, wantRequired) || len(req.RequiredSigners) == 0 {
		t.Fatalf("RequiredSigners = %v, want body required signers %v", req.RequiredSigners, wantRequired)
	}

	// Verify inputs have paths (payment tx funds from addr0 at index 0).
	if len(req.Inputs) == 0 {
		t.Fatal("expected at least one input")
	}
	hasPath := false
	for _, inp := range req.Inputs {
		if inp.Path != "" {
			hasPath = true
			// Path must follow CIP-1852 format.
			if inp.Path != "1852'/1815'/0'/0/0" {
				t.Fatalf("unexpected path %q for index 0 payment key", inp.Path)
			}
		}
		// Each owned input must carry its resolved value + address so an
		// air-gapped signer can display the inputs and compute the fee. The
		// single fake UTxO holds 10_000_000 lovelace at addr0.
		if inp.Lovelace != "10000000" {
			t.Fatalf("input Lovelace = %q, want 10000000 (resolved from coin selection)", inp.Lovelace)
		}
		if inp.AddressBech32 != addr0 {
			t.Fatalf("input AddressBech32 = %q, want %q", inp.AddressBech32, addr0)
		}
		if len(inp.Assets) != 0 {
			t.Fatalf("ADA-only input must carry no assets, got %+v", inp.Assets)
		}
	}
	if !hasPath {
		t.Fatal("at least one input should have a derivation path")
	}

	// Verify outputs are present with lovelace.
	if len(req.Outputs) == 0 {
		t.Fatal("expected at least one output")
	}
	sawRecipient := false
	sawChange := false
	for _, out := range req.Outputs {
		if out.Lovelace == "" || out.Lovelace == "0" {
			t.Fatalf("output lovelace must be non-zero: %+v", out)
		}
		if out.AddressHex == "" {
			t.Fatalf("output AddressHex must not be empty: %+v", out)
		}
		if out.AddressBech32 == "" {
			t.Fatalf("output AddressBech32 must not be empty: %+v", out)
		}
		switch out.AddressBech32 {
		case recipientAddr:
			sawRecipient = true
			if out.PaymentPath != "" || out.StakePath != "" {
				t.Fatalf("third-party recipient must not have device paths: %+v", out)
			}
		case addr0:
			sawChange = true
			if out.PaymentPath != "1852'/1815'/0'/0/0" {
				t.Fatalf("change payment path = %q, want account 0 external index 0", out.PaymentPath)
			}
			if out.StakePath != "1852'/1815'/0'/2/0" {
				t.Fatalf("change stake path = %q, want account 0 stake index 0", out.StakePath)
			}
		}
	}
	if !sawRecipient || !sawChange {
		t.Fatalf("outputs must include recipient and change: %+v", req.Outputs)
	}
}

func TestHardwareSignRequestPreprodProtocolMagic(t *testing.T) {
	acct, err := wallet.Derive(testMnemonic, "preprod", 2)
	if err != nil {
		t.Fatalf("derive preprod account: %v", err)
	}
	fc := newFakeChain(10_000_000, acct.ReceiveAddresses[0])
	s := NewService(fc, nil, acct)

	pv, err := s.Build(context.Background(), SendRequest{
		To:       acct.ReceiveAddresses[1],
		Lovelace: "1000000",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	req, err := s.HardwareSignRequest(pv.PendingID)
	if err != nil {
		t.Fatalf("HardwareSignRequest: %v", err)
	}

	if req.NetworkID != 0 {
		t.Fatalf("NetworkID = %d, want 0", req.NetworkID)
	}
	if req.ProtocolMagic != 1 {
		t.Fatalf("ProtocolMagic = %d, want 1", req.ProtocolMagic)
	}
}

func TestHardwareSignRequestUsesAccountIndex(t *testing.T) {
	root, err := bursa.GetRootKeyFromMnemonic(testMnemonic, "")
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	accountKey, err := bursa.GetAccountKey(root, 2)
	if err != nil {
		t.Fatalf("account key: %v", err)
	}
	acct, err := wallet.DeriveFromAccountXpub(accountKey.Public().String(), "preview", 2, 3)
	if err != nil {
		t.Fatalf("derive account 2: %v", err)
	}
	fc := newFakeChain(10_000_000, acct.ReceiveAddresses[0])
	s := NewService(fc, nil, acct)
	pv, err := s.Build(context.Background(), SendRequest{
		To: acct.ReceiveAddresses[1], Lovelace: "1000000",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	req, err := s.HardwareSignRequest(pv.PendingID)
	if err != nil {
		t.Fatalf("HardwareSignRequest: %v", err)
	}
	if got := req.Inputs[0].Path; got != "1852'/1815'/2'/0/0" {
		t.Fatalf("input path = %q, want account 2", got)
	}
	for _, out := range req.Outputs {
		if out.PaymentPath != "" && !strings.HasPrefix(out.PaymentPath, "1852'/1815'/2'/") {
			t.Fatalf("owned output payment path = %q, want account 2", out.PaymentPath)
		}
		if out.StakePath != "" && out.StakePath != "1852'/1815'/2'/2/0" {
			t.Fatalf("owned output stake path = %q, want account 2", out.StakePath)
		}
	}
}

func TestHardwareSignRequestUnknownPending(t *testing.T) {
	acct := mustDeriveTestAccount(t)
	fc := newFakeChain(10_000_000, acct.ReceiveAddresses[0])
	s := NewService(fc, nil, acct)

	_, err := s.HardwareSignRequest("does-not-exist")
	if err == nil {
		t.Fatal("expected error for unknown pending id")
	}
	if !errors.Is(err, ErrUnknownPending) {
		t.Fatalf("expected ErrUnknownPending, got %v", err)
	}
}

// TestHardwareSignRequestGuard verifies the safety property: txs with
// native-asset outputs (which a device cannot yet express) set Unsupported and
// do NOT leak signing inputs/paths (the guard fires before inputs are built).
// Certificates, withdrawals, and votes are no longer rejected — see the
// signer-path tests below.
func TestHardwareSignRequestGuard(t *testing.T) {
	acct, err := wallet.Derive(testMnemonic, "preview", 5)
	if err != nil {
		t.Fatalf("wallet.Derive: %v", err)
	}
	addr0 := acct.ReceiveAddresses[0]
	recvAddr := acct.ReceiveAddresses[4]

	t.Run("native-asset output is rejected", func(t *testing.T) {
		// Fund addr0 with 5 ADA + 1 native token. Apollo needs the token in the
		// input UTxO before it can route it to an output (coin selection enforces
		// asset conservation). We inject a fakeOutputWithAssets for that UTxO so
		// the builder can construct a tx whose outputs carry the native asset.
		const (
			policyHex    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 28 bytes
			assetNameHex = "74657374"                                                 // "test"
		)
		nativeAssets := newFakeMultiAsset(policyHex, assetNameHex, 1) //nolint:gomnd
		nativeToken := apollo.NewUnit(policyHex, assetNameHex, 1)

		// Build the input UTxO manually with native assets.
		var txIDBytes lcommon.Blake2b256
		copy(txIDBytes[:], make([]byte, 32)) // all-zero hash
		inputID := shelley.ShelleyTransactionInput{TxId: txIDBytes, OutputIndex: 0}
		addr0Parsed, _ := lcommon.NewAddress(addr0)
		inputOutput := &fakeOutputWithAssets{
			fakeOutput: fakeOutput{address: addr0Parsed, lovelace: 5_000_000},
			assets:     nativeAssets,
		}
		inputUTxO := lcommon.Utxo{Id: inputID, Output: inputOutput}

		// Construct a fakeChain with the asset-bearing UTxO.
		fc := &fakeChain{utxos: map[string][]lcommon.Utxo{addr0: {inputUTxO}}}
		s := NewService(fc, nil, acct)

		pv, err := s.Build(context.Background(), SendRequest{To: recvAddr, Lovelace: "1000000"})
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		s.mu.Lock()
		p := s.pending[pv.PendingID]
		s.mu.Unlock()

		changeAddr, _ := lcommon.NewAddress(addr0)
		// Build a tx that sends 2 ADA + the native token to recvAddr.
		a := apollo.New(fc).
			SetWallet(apollo.NewExternalWallet(changeAddr)).
			SetChangeAddress(changeAddr).
			SetFeePadding(feePaddingLovelace).
			AddLoadedUTxOs(inputUTxO).
			PayToAddress(mustNewAddress(t, recvAddr), 2_000_000, nativeToken)
		a, err = a.WithContext(context.Background()).Complete()
		if err != nil {
			t.Fatalf("Complete with native asset: %v", err)
		}
		ref := hex.EncodeToString(txIDBytes.Bytes()) + "#0"
		utxoAddr := map[string]string{ref: addr0}
		s.mu.Lock()
		s.pending[pv.PendingID] = &pending{
			tx:       a,
			utxoAddr: utxoAddr,
			created:  p.created,
			walletID: p.walletID,
			account:  p.account,
		}
		s.mu.Unlock()

		req, err := s.HardwareSignRequest(pv.PendingID)
		if err != nil {
			t.Fatalf("HardwareSignRequest: %v", err)
		}
		if req.Unsupported == "" {
			t.Fatal("expected Unsupported to be set for a native-asset output tx")
		}
		// Guard fires before inputs are built: no inputs should leak.
		if len(req.Inputs) > 0 {
			t.Fatalf("native-asset guard: expected no inputs in result, got %d", len(req.Inputs))
		}
	})
}

func TestHardwareSignRequestRejectsOtherConwayFeatures(t *testing.T) {
	type mutateBody func(*conway.ConwayTransactionBody)
	var hash lcommon.Blake2b256
	hash[0] = 1
	networkID := uint8(1)
	tests := []struct {
		name   string
		mutate mutateBody
	}{
		{"protocol update", func(b *conway.ConwayTransactionBody) { b.Update = &conway.ConwayTransactionPparamUpdate{} }},
		{"auxiliary data hash", func(b *conway.ConwayTransactionBody) { b.TxAuxDataHash = &hash }},
		{"validity interval start", func(b *conway.ConwayTransactionBody) { b.TxValidityIntervalStart = 1 }},
		{"mint", func(b *conway.ConwayTransactionBody) { b.TxMint = &lcommon.MultiAsset[lcommon.MultiAssetTypeMint]{} }},
		{"script data hash", func(b *conway.ConwayTransactionBody) { b.TxScriptDataHash = &hash }},
		{"collateral", func(b *conway.ConwayTransactionBody) { b.TxCollateral = cbor.NewSetType(b.TxInputs.Items(), true) }},
		{"mismatched network id", func(b *conway.ConwayTransactionBody) { b.TxNetworkId = &networkID }},
		{"collateral return", func(b *conway.ConwayTransactionBody) { out := b.TxOutputs[0]; b.TxCollateralReturn = &out }},
		{"total collateral", func(b *conway.ConwayTransactionBody) { b.TxTotalCollateral = 1 }},
		{"reference inputs", func(b *conway.ConwayTransactionBody) { b.TxReferenceInputs = cbor.NewSetType(b.TxInputs.Items(), true) }},
		{"proposal procedures", func(b *conway.ConwayTransactionBody) { b.TxProposalProcedures = []conway.ConwayProposalProcedure{{}} }},
		{"current treasury value", func(b *conway.ConwayTransactionBody) { b.TxCurrentTreasuryValue = 1 }},
		{"donation", func(b *conway.ConwayTransactionBody) { b.TxDonation = 1 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acct := mustDeriveTestAccount(t)
			fc := newFakeChain(10_000_000, acct.ReceiveAddresses[0])
			s := NewService(fc, nil, acct)
			pv, err := s.Build(context.Background(), SendRequest{To: acct.ReceiveAddresses[1], Lovelace: "1000000"})
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			tx := s.pending[pv.PendingID].tx.GetTx()
			tt.mutate(&tx.Body)

			req, err := s.HardwareSignRequest(pv.PendingID)
			if err != nil {
				t.Fatalf("HardwareSignRequest: %v", err)
			}
			if req.Unsupported == "" {
				t.Fatal("expected unsupported body feature to be rejected")
			}
			if len(req.Inputs) != 0 {
				t.Fatalf("guard returned %d signing inputs", len(req.Inputs))
			}
		})
	}

	datumOptionCBOR, err := cbor.Encode([]any{babbage.DatumOptionTypeHash, hash})
	if err != nil {
		t.Fatalf("encode datum option: %v", err)
	}
	var datumOption babbage.BabbageTransactionOutputDatumOption
	if _, err := cbor.Decode(datumOptionCBOR, &datumOption); err != nil {
		t.Fatalf("decode datum option: %v", err)
	}
	outputTests := []struct {
		name   string
		mutate func(*babbage.BabbageTransactionOutput)
	}{
		{"output datum", func(out *babbage.BabbageTransactionOutput) {
			out.DatumOption = &datumOption
		}},
		{"output script reference", func(out *babbage.BabbageTransactionOutput) {
			out.TxOutScriptRef = &lcommon.ScriptRef{
				Type:   lcommon.ScriptRefTypePlutusV1,
				Script: lcommon.PlutusV1Script{0x01},
			}
		}},
	}
	for _, tt := range outputTests {
		t.Run(tt.name, func(t *testing.T) {
			acct := mustDeriveTestAccount(t)
			fc := newFakeChain(10_000_000, acct.ReceiveAddresses[0])
			s := NewService(fc, nil, acct)
			pv, err := s.Build(context.Background(), SendRequest{To: acct.ReceiveAddresses[1], Lovelace: "1000000"})
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			tx := s.pending[pv.PendingID].tx.GetTx()
			tt.mutate(&tx.Body.TxOutputs[0])

			req, err := s.HardwareSignRequest(pv.PendingID)
			if err != nil {
				t.Fatalf("HardwareSignRequest: %v", err)
			}
			if req.Unsupported == "" {
				t.Fatal("expected unsupported output feature to be rejected")
			}
			if len(req.Inputs) != 0 {
				t.Fatalf("guard returned %d signing inputs", len(req.Inputs))
			}
		})
	}
}

// TestHardwareSignRequestStakeDelegationCarriesCertSigners verifies a
// stake-delegation transaction is signable on hardware (not Unsupported) and
// that the request carries the wallet's stake-key derivation path for every
// certificate it must witness, plus the change-output path.
func TestHardwareSignRequestStakeDelegationCarriesCertSigners(t *testing.T) {
	acct := mustDeriveTestAccount(t)
	fc := newFakeChain(10_000_000, acct.ReceiveAddresses[0])
	s := NewService(fc, nil, acct)
	s.SetChainQuerier(newFakeQuerier()) // fresh wallet → stake registration + delegation

	pv, err := s.BuildDelegation(context.Background(), DelegationRequest{PoolID: validPoolID})
	if err != nil {
		t.Fatalf("BuildDelegation: %v", err)
	}
	req, err := s.HardwareSignRequest(pv.PendingID)
	if err != nil {
		t.Fatalf("HardwareSignRequest: %v", err)
	}
	if req.Unsupported != "" {
		t.Fatalf("staking tx must be signable, got Unsupported = %q", req.Unsupported)
	}

	addr0 := mustNewAddress(t, acct.ReceiveAddresses[0])
	wantStakeHash := hex.EncodeToString(addr0.StakeKeyHash().Bytes())
	const wantStakePath = "1852'/1815'/0'/2/0"
	seen := map[string]bool{}
	for _, cs := range req.CertificateSigners {
		seen[cs.CertKind] = true
		if cs.Role != "stake" {
			t.Fatalf("cert signer role = %q, want stake", cs.Role)
		}
		if cs.Path != wantStakePath {
			t.Fatalf("cert signer path = %q, want %q", cs.Path, wantStakePath)
		}
		if cs.KeyHashHex != wantStakeHash {
			t.Fatalf("cert signer key hash = %q, want stake key hash %q", cs.KeyHashHex, wantStakeHash)
		}
	}
	for _, want := range []string{"stake_registration", "stake_delegation"} {
		if !seen[want] {
			t.Fatalf("missing cert signer for %q; got %+v", want, req.CertificateSigners)
		}
	}
	// Change returns to the wallet → a change-output path is surfaced.
	if len(req.ChangeOutputs) == 0 {
		t.Fatalf("expected at least one change output path; outputs=%+v", req.Outputs)
	}
	for _, co := range req.ChangeOutputs {
		if co.Path == "" || co.StakePath != wantStakePath {
			t.Fatalf("change output = %+v, want non-empty path and stake path %q", co, wantStakePath)
		}
		if co.Index < 0 || co.Index >= len(req.Outputs) {
			t.Fatalf("change output index %d out of range (%d outputs)", co.Index, len(req.Outputs))
		}
		if req.Outputs[co.Index].PaymentPath != co.Path {
			t.Fatalf("change output index %d path %q != output payment path %q", co.Index, co.Path, req.Outputs[co.Index].PaymentPath)
		}
	}
}

// TestHardwareSignRequestSelfDRepRegistrationCarriesDRepSigner verifies a
// self-DRep registration surfaces the wallet's DRep-key path (role 3) for the
// drep_registration certificate.
func TestHardwareSignRequestSelfDRepRegistrationCarriesDRepSigner(t *testing.T) {
	acct := mustDeriveTestAccount(t)
	fc := newFakeChain(700_000_000, acct.ReceiveAddresses[0]) // cover 2₳ + 500₳ deposits + fee
	s := NewService(fc, nil, acct)
	q := newFakeQuerier()
	q.account = chain.AccountInfo{Registered: true, Active: true, WithdrawableAmount: "0"}
	q.drepErr = chain.ErrNotFound // own DRep not yet registered → emit the reg cert
	s.SetChainQuerier(q)

	pv, err := s.BuildDelegation(context.Background(), DelegationRequest{Vote: &Vote{Type: VoteRegisterSelf}})
	if err != nil {
		t.Fatalf("BuildDelegation register self: %v", err)
	}
	req, err := s.HardwareSignRequest(pv.PendingID)
	if err != nil {
		t.Fatalf("HardwareSignRequest: %v", err)
	}
	if req.Unsupported != "" {
		t.Fatalf("governance tx must be signable, got Unsupported = %q", req.Unsupported)
	}
	const wantDRepPath = "1852'/1815'/0'/3/0"
	wantDRepHash := strings.ToLower(acct.DRepKeyHash)
	found := false
	for _, cs := range req.CertificateSigners {
		if cs.CertKind != "registration_drep" {
			continue
		}
		found = true
		if cs.Role != "drep" || cs.Path != wantDRepPath {
			t.Fatalf("drep cert signer = %+v, want role drep path %q", cs, wantDRepPath)
		}
		if cs.KeyHashHex != wantDRepHash {
			t.Fatalf("drep cert signer key hash = %q, want %q", cs.KeyHashHex, wantDRepHash)
		}
	}
	if !found {
		t.Fatalf("no registration_drep cert signer; got %+v", req.CertificateSigners)
	}
}

// TestHardwareSignRequestWithdrawalCarriesStakeSigner verifies a reward
// withdrawal surfaces the wallet's stake-key path as a withdrawal signer.
func TestHardwareSignRequestWithdrawalCarriesStakeSigner(t *testing.T) {
	acct, err := wallet.Derive(testMnemonic, "preview", 5)
	if err != nil {
		t.Fatalf("wallet.Derive: %v", err)
	}
	addr0 := acct.ReceiveAddresses[0]
	recvAddr := acct.ReceiveAddresses[4]

	fc := newFakeChain(5_000_000, addr0)
	s := NewService(fc, nil, acct)
	pv, err := s.Build(context.Background(), SendRequest{To: recvAddr, Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	s.mu.Lock()
	p := s.pending[pv.PendingID]
	s.mu.Unlock()

	stakeAddr, err := lcommon.NewAddress(acct.StakeAddress)
	if err != nil {
		t.Fatalf("NewAddress(stake): %v", err)
	}
	changeAddr, _ := lcommon.NewAddress(addr0)
	a := apollo.New(fc).
		SetWallet(apollo.NewExternalWallet(changeAddr)).
		SetChangeAddress(changeAddr).
		SetFeePadding(feePaddingLovelace).
		AddLoadedUTxOs(fc.utxos[addr0]...).
		PayToAddress(mustNewAddress(t, recvAddr), 1_000_000).
		AddWithdrawal(stakeAddr, 500_000, nil, nil)
	a, err = a.WithContext(context.Background()).Complete()
	if err != nil {
		t.Fatalf("Complete with withdrawal: %v", err)
	}
	utxoAddr := make(map[string]string)
	for _, u := range fc.utxos[addr0] {
		utxoAddr[makeUtxoRef(u)] = addr0
	}
	s.mu.Lock()
	s.pending[pv.PendingID] = &pending{
		tx:       a,
		utxoAddr: utxoAddr,
		created:  p.created,
		walletID: p.walletID,
		account:  p.account,
	}
	s.mu.Unlock()

	req, err := s.HardwareSignRequest(pv.PendingID)
	if err != nil {
		t.Fatalf("HardwareSignRequest: %v", err)
	}
	if req.Unsupported != "" {
		t.Fatalf("withdrawal tx must be signable, got Unsupported = %q", req.Unsupported)
	}
	if len(req.WithdrawalSigners) != 1 {
		t.Fatalf("want exactly one withdrawal signer, got %+v", req.WithdrawalSigners)
	}
	ws := req.WithdrawalSigners[0]
	addr0Parsed := mustNewAddress(t, addr0)
	wantStakeHash := hex.EncodeToString(addr0Parsed.StakeKeyHash().Bytes())
	if ws.Role != "stake" || ws.Path != "1852'/1815'/0'/2/0" || ws.KeyHashHex != wantStakeHash {
		t.Fatalf("withdrawal signer = %+v, want stake role, path 1852'/1815'/0'/2/0, key hash %q", ws, wantStakeHash)
	}
	if ws.RewardAddressBech32 != acct.StakeAddress {
		t.Fatalf("withdrawal reward address = %q, want %q", ws.RewardAddressBech32, acct.StakeAddress)
	}
}

// TestHardwareSignRequestDRepVoteCarriesVoteSigner verifies a Conway
// governance vote (a voting procedure whose voter is the wallet's DRep key)
// surfaces the DRep-key path as a vote signer.
func TestHardwareSignRequestDRepVoteCarriesVoteSigner(t *testing.T) {
	acct := mustDeriveTestAccount(t)
	fc := newFakeChain(10_000_000, acct.ReceiveAddresses[0])
	s := NewService(fc, nil, acct)
	pv, err := s.Build(context.Background(), SendRequest{To: acct.ReceiveAddresses[1], Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Attach a DRep-key-hash voter for the wallet's own DRep credential.
	drepHash, err := hex.DecodeString(acct.DRepKeyHash)
	if err != nil {
		t.Fatalf("decode drep key hash: %v", err)
	}
	var voter lcommon.Voter
	voter.Type = lcommon.VoterTypeDRepKeyHash
	copy(voter.Hash[:], drepHash)
	tx := s.pending[pv.PendingID].tx.GetTx()
	tx.Body.TxVotingProcedures = lcommon.VotingProcedures{
		&voter: {new(lcommon.GovActionId): lcommon.VotingProcedure{}},
	}

	req, err := s.HardwareSignRequest(pv.PendingID)
	if err != nil {
		t.Fatalf("HardwareSignRequest: %v", err)
	}
	if req.Unsupported != "" {
		t.Fatalf("vote tx must be signable, got Unsupported = %q", req.Unsupported)
	}
	if len(req.VoteSigners) != 1 {
		t.Fatalf("want exactly one vote signer, got %+v", req.VoteSigners)
	}
	vs := req.VoteSigners[0]
	if vs.Voter != "drep" || vs.Role != "drep" || vs.Path != "1852'/1815'/0'/3/0" {
		t.Fatalf("vote signer = %+v, want drep voter/role, path 1852'/1815'/0'/3/0", vs)
	}
	if vs.KeyHashHex != strings.ToLower(acct.DRepKeyHash) {
		t.Fatalf("vote signer key hash = %q, want %q", vs.KeyHashHex, acct.DRepKeyHash)
	}
}

// TestHardwareSignRequestMultisigExtraSigners verifies a native-multisig-style
// spend — where the transaction requires an extra key (body key 14) that is not
// already an input signer — surfaces that participant key as an extra signer,
// while inputs the wallet spends keep their own paths (and are not repeated).
func TestHardwareSignRequestMultisigExtraSigners(t *testing.T) {
	acct := mustDeriveTestAccount(t)
	fc := newFakeChain(10_000_000, acct.ReceiveAddresses[0])
	s := NewService(fc, nil, acct)
	pv, err := s.Build(context.Background(), SendRequest{To: acct.ReceiveAddresses[1], Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	addr0 := mustNewAddress(t, acct.ReceiveAddresses[0])
	stakeHash := addr0.StakeKeyHash()
	tx := s.pending[pv.PendingID].tx.GetTx()
	// Add the wallet's stake key as an explicit required signer — standing in
	// for a CIP-1854 multisig participant that is not one of the tx inputs.
	items := append(tx.Body.TxRequiredSigners.Items(), stakeHash)
	tx.Body.TxRequiredSigners = cbor.NewSetType[lcommon.Blake2b224](items, true)

	req, err := s.HardwareSignRequest(pv.PendingID)
	if err != nil {
		t.Fatalf("HardwareSignRequest: %v", err)
	}
	if req.Unsupported != "" {
		t.Fatalf("multisig-style tx must be signable, got Unsupported = %q", req.Unsupported)
	}

	// Inputs the wallet spends still carry their derivation path.
	hasInputPath := false
	for _, inp := range req.Inputs {
		if inp.Path == "1852'/1815'/0'/0/0" {
			hasInputPath = true
		}
	}
	if !hasInputPath {
		t.Fatalf("expected the owned input to keep its path; inputs=%+v", req.Inputs)
	}

	// The stake key (not an input signer) is surfaced as an extra signer.
	wantStakeHash := hex.EncodeToString(stakeHash.Bytes())
	found := false
	for _, es := range req.ExtraSigners {
		if es.KeyHashHex == wantStakeHash {
			found = true
			if es.Role != "stake" || es.Path != "1852'/1815'/0'/2/0" {
				t.Fatalf("extra signer = %+v, want stake role, path 1852'/1815'/0'/2/0", es)
			}
		}
		// A payment key already covered by an input must NOT be duplicated here.
		if es.Path == "1852'/1815'/0'/0/0" {
			t.Fatalf("extra signer duplicated an input path: %+v", es)
		}
	}
	if !found {
		t.Fatalf("stake participant key not surfaced as extra signer; got %+v", req.ExtraSigners)
	}
}

// TestHardwareSignRequestForeignDRepVoteUnsupported verifies the safety property
// behind the vote path: a governance vote whose voter is a DRep key hash the
// wallet does NOT own must not be presented as signable. resolveSignerData has
// no derivation path for it, so it must set Unsupported (the device can never
// produce that witness) rather than return an empty VoteSigners slice — which
// the SPA would treat as a signable payment with the vote witness silently
// missing.
func TestHardwareSignRequestForeignDRepVoteUnsupported(t *testing.T) {
	acct := mustDeriveTestAccount(t)
	fc := newFakeChain(10_000_000, acct.ReceiveAddresses[0])
	s := NewService(fc, nil, acct)
	pv, err := s.Build(context.Background(), SendRequest{To: acct.ReceiveAddresses[1], Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// A DRep key-hash voter whose hash is NOT this wallet's DRep key.
	var voter lcommon.Voter
	voter.Type = lcommon.VoterTypeDRepKeyHash
	for i := range voter.Hash {
		voter.Hash[i] = 0x11
	}
	tx := s.pending[pv.PendingID].tx.GetTx()
	tx.Body.TxVotingProcedures = lcommon.VotingProcedures{
		&voter: {new(lcommon.GovActionId): lcommon.VotingProcedure{}},
	}

	req, err := s.HardwareSignRequest(pv.PendingID)
	if err != nil {
		t.Fatalf("HardwareSignRequest: %v", err)
	}
	if req.Unsupported == "" {
		t.Fatal("foreign DRep vote must set Unsupported, not be presented as signable")
	}
	if len(req.VoteSigners) != 0 {
		t.Fatalf("no vote signer may be fabricated for a foreign DRep; got %+v", req.VoteSigners)
	}
}

// TestHardwareSignRequestForeignCertCredentialUnsupported verifies the safety
// property behind the certificate path: a certificate whose signing credential
// is a stake key the wallet does NOT own (a co-signer's key, or — via the same
// branch — a script hash) must set Unsupported rather than resolve to an empty
// CertificateSigners slice the SPA would treat as signable.
func TestHardwareSignRequestForeignCertCredentialUnsupported(t *testing.T) {
	acct := mustDeriveTestAccount(t)
	fc := newFakeChain(10_000_000, acct.ReceiveAddresses[0])
	s := NewService(fc, nil, acct)
	pv, err := s.Build(context.Background(), SendRequest{To: acct.ReceiveAddresses[1], Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// A stake-delegation certificate keyed on a credential this wallet does not
	// own — it can never witness it.
	foreignCred := lcommon.Credential{
		CredType:   lcommon.CredentialTypeAddrKeyHash,
		Credential: lcommon.Blake2b224Hash([]byte("foreign stake key")),
	}
	tx := s.pending[pv.PendingID].tx.GetTx()
	tx.Body.TxCertificates = []lcommon.CertificateWrapper{{
		Type: uint(lcommon.CertificateTypeStakeDelegation),
		Certificate: &lcommon.StakeDelegationCertificate{
			CertType:        uint(lcommon.CertificateTypeStakeDelegation),
			StakeCredential: &foreignCred,
		},
	}}

	req, err := s.HardwareSignRequest(pv.PendingID)
	if err != nil {
		t.Fatalf("HardwareSignRequest: %v", err)
	}
	if req.Unsupported == "" {
		t.Fatal("foreign certificate credential must set Unsupported, not be presented as signable")
	}
	if len(req.CertificateSigners) != 0 {
		t.Fatalf("no cert signer may be fabricated for a foreign credential; got %+v", req.CertificateSigners)
	}
}
