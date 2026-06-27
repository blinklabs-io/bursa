package spend

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blinklabs-io/apollo/v2/backend"
	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/ui/internal/keystore"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
	"github.com/blinklabs-io/gouroboros/ledger"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
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

// backend.ChainContext implementation for fakeChain.
func (fc *fakeChain) ProtocolParams(_ context.Context) (backend.ProtocolParameters, error) {
	return fc.pp, nil
}

func (fc *fakeChain) GenesisParams(_ context.Context) (backend.GenesisParameters, error) {
	return backend.GenesisParameters{
		ActiveSlotsCoefficient: 0.05,
		EpochLength:            432000,
		SlotLength:             1,
		NetworkMagic:           1,
	}, nil
}
func (fc *fakeChain) NetworkId() uint8                               { return 0 } // preview = 0
func (fc *fakeChain) CurrentEpoch(_ context.Context) (uint64, error) { return 500, nil }

func (fc *fakeChain) MaxTxFee(_ context.Context) (uint64, error) {
	if fc.maxTxFeeErr != nil {
		return 0, fc.maxTxFeeErr
	}
	return backend.ComputeMaxTxFee(fc.pp)
}
func (fc *fakeChain) Tip(_ context.Context) (uint64, error) { return 10_000_000, nil }
func (fc *fakeChain) Utxos(_ context.Context, address lcommon.Address) ([]lcommon.Utxo, error) {
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

func (fc *fakeChain) SubmitTx(_ context.Context, tx []byte) (lcommon.Blake2b256, error) {
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

func (fc *fakeChain) EvaluateTx(_ context.Context, _ []byte, _ []lcommon.Utxo) (map[lcommon.RedeemerKey]lcommon.ExUnits, error) {
	return nil, nil
}

func (fc *fakeChain) UtxoByRef(_ context.Context, txHash lcommon.Blake2b256, index uint32) (*lcommon.Utxo, error) {
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
func (fc *fakeChain) ScriptCbor(_ context.Context, _ lcommon.Blake2b224) ([]byte, error) {
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
