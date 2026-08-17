package spend

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"testing"

	apollo "github.com/Salvionied/apollo/v2"
	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/conway"

	"github.com/blinklabs-io/bursa/ui/internal/keystore"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
)

// foreignWitness builds a valid vkey witness over unsignedCbor's body bytes
// from a fresh, unrelated Ed25519 key (i.e. a co-signer that is not this
// wallet). Because CosignTx verifies and dedupes witnesses by signature, a
// retained witness must be genuinely valid — a zero/garbage witness would be
// (correctly) dropped, so it could not prove retention.
func foreignWitness(t *testing.T, unsignedCbor string) (lcommon.VkeyWitness, string) {
	t.Helper()
	txBytes, err := hex.DecodeString(unsignedCbor)
	if err != nil {
		t.Fatalf("decode unsigned cbor: %v", err)
	}
	body, err := extractTxBodyCbor(txBytes)
	if err != nil {
		t.Fatalf("extract body: %v", err)
	}
	bodyHash := lcommon.Blake2b256Hash(body)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	w := lcommon.VkeyWitness{Vkey: pub, Signature: ed25519.Sign(priv, bodyHash.Bytes())}
	kh := hex.EncodeToString(lcommon.Blake2b224Hash(pub).Bytes())
	return w, kh
}

// attachWitness re-serializes unsignedCbor with w merged into its witness set,
// preserving the original body bytes (the SubmitSigned/CosignTx pattern), and
// returns the new tx CBOR hex.
func attachWitness(t *testing.T, s *Service, unsignedCbor string, w lcommon.VkeyWitness) string {
	t.Helper()
	a, err := apollo.New(s.chain).LoadTxCbor(unsignedCbor)
	if err != nil {
		t.Fatalf("LoadTxCbor: %v", err)
	}
	if a, err = a.AddVerificationKeyWitness(w); err != nil {
		t.Fatalf("AddVerificationKeyWitness: %v", err)
	}
	lt := a.GetTx()
	lt.SetCbor(nil)
	lt.WitnessSet.SetCbor(nil)
	b, err := a.GetTxCbor()
	if err != nil {
		t.Fatalf("GetTxCbor: %v", err)
	}
	return hex.EncodeToString(b)
}

// testPassword is the spending password used by the CosignTx fixtures below.
// fakeKeystore.Unlock ignores the supplied password entirely (it always
// succeeds unless constructed with an err), so its value is arbitrary; a
// dedicated fakeKeystore{err: keystore.ErrDecryptFailed} service is used to
// exercise the wrong-password path instead (see TestCosignTx_WrongPassword).
const testPassword = "cosign-test-password"

// buildUnsignedSendFixture builds a real unsigned send transaction (via the
// same Build -> ExportUnsigned path exercised in spend_test.go's air-gap
// tests) and returns the Service it was built against, the active account,
// and the resulting unsigned tx CBOR (hex).
func buildUnsignedSendFixture(t *testing.T) (*Service, *wallet.Account, string) {
	t.Helper()
	acct := mustDeriveConfirmAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	recvAddr := acct.ReceiveAddresses[2]

	fc := newFakeChain(5_000_000, addr0)
	s := NewService(fc, fakeKeystore{mnemonic: testMnemonic}, acct)

	pv, err := s.Build(context.Background(), SendRequest{To: recvAddr, Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	unsigned, err := s.ExportUnsigned(pv.PendingID)
	if err != nil {
		t.Fatalf("ExportUnsigned: %v", err)
	}
	return s, acct, unsigned.UnsignedTxCBOR
}

// newBuildOnlyService returns a minimal Service with no wallet/keystore/chain
// configured, suitable for exercising DecodeTx's input-validation paths that
// never need an active account.
func newBuildOnlyService(t *testing.T) *Service {
	t.Helper()
	return NewService(nil, nil, nil)
}

func TestDecodeTx_VkeySummary(t *testing.T) {
	svc, acct, unsignedCbor := buildUnsignedSendFixture(t)
	got, err := svc.DecodeTx(context.Background(), unsignedCbor)
	if err != nil {
		t.Fatalf("DecodeTx: %v", err)
	}
	if got.Kind != "vkey" {
		t.Errorf("kind = %q, want vkey", got.Kind)
	}
	if len(got.Outputs) == 0 {
		t.Error("expected at least one output")
	}
	if got.Fee == "" || got.Fee == "0" {
		t.Errorf("fee = %q, want a non-zero decimal string", got.Fee)
	}
	if got.IsComplete {
		t.Error("unsigned tx must not be complete")
	}
	if len(got.ExistingSignatures) != 0 {
		t.Errorf("unsigned tx has %d existing sigs, want 0", len(got.ExistingSignatures))
	}

	// WalletCanAdd must name the actual payment key hash this wallet owns for
	// the spent input (buildUnsignedSendFixture funds the tx from
	// acct.ReceiveAddresses[0]), derived the same way walletPaymentKeyHashes
	// does -- not hardcoded -- so a subtly-wrong key hash in DecodeTx would
	// fail this test.
	if len(got.WalletCanAdd) == 0 {
		t.Fatal("expected at least one wallet_can_add entry for the unsigned send tx's input signer")
	}
	fundingAddr, err := lcommon.NewAddress(acct.ReceiveAddresses[0])
	if err != nil {
		t.Fatalf("parse funding address: %v", err)
	}
	wantKeyHash := hex.EncodeToString(fundingAddr.PaymentKeyHash().Bytes())

	found := false
	for _, signer := range got.WalletCanAdd {
		if signer.KeyHash == wantKeyHash {
			found = true
			if signer.Role != "payment" {
				t.Errorf("wallet_can_add entry for %s: role = %q, want payment", wantKeyHash, signer.Role)
			}
		}
	}
	if !found {
		t.Errorf("wallet_can_add %+v does not contain expected payment key hash %s", got.WalletCanAdd, wantKeyHash)
	}
}

// TestDecodeTx_WithdrawalsSortedByAddress covers a transaction with multiple
// reward withdrawals. TxWithdrawals is a Go map (randomized iteration order),
// so without an explicit sort the rendered summary's Withdrawals would come
// back in a different order on every call. This builds a fixture with two
// withdrawals whose reward addresses are deliberately out of lexical order
// as constructed, and asserts DecodeTx always reports them sorted.
func TestDecodeTx_WithdrawalsSortedByAddress(t *testing.T) {
	svc, _, unsignedCbor := buildUnsignedSendFixture(t)
	txBytes, err := hex.DecodeString(unsignedCbor)
	if err != nil {
		t.Fatalf("decode unsigned cbor: %v", err)
	}

	var outer []cbor.RawMessage
	if _, err := cbor.Decode(txBytes, &outer); err != nil {
		t.Fatalf("decode tx as CBOR array: %v", err)
	}
	if len(outer) < 1 {
		t.Fatal("tx array has no body element")
	}

	var body conway.ConwayTransactionBody
	if _, err := cbor.Decode(outer[0], &body); err != nil {
		t.Fatalf("decode tx body: %v", err)
	}

	addrHi, err := lcommon.NewAddressFromParts(lcommon.AddressTypeNoneKey, lcommon.AddressNetworkTestnet, nil, bytesRepeat(0xff, 28))
	if err != nil {
		t.Fatalf("NewAddressFromParts(hi): %v", err)
	}
	addrLo, err := lcommon.NewAddressFromParts(lcommon.AddressTypeNoneKey, lcommon.AddressNetworkTestnet, nil, bytesRepeat(0x00, 28))
	if err != nil {
		t.Fatalf("NewAddressFromParts(lo): %v", err)
	}
	// Insert the map entries "backwards" (higher address first) so a naive
	// unsorted append would very likely fail a strict order check; the real
	// guard is the assertion against a lexically-sorted `want` below, which
	// holds regardless of map iteration order.
	body.TxWithdrawals = map[*lcommon.Address]uint64{
		&addrHi: 3_000_000,
		&addrLo: 1_500_000,
	}

	newBodyBytes, err := cbor.Encode(&body)
	if err != nil {
		t.Fatalf("encode modified tx body: %v", err)
	}
	outer[0] = cbor.RawMessage(newBodyBytes)

	newTxBytes, err := cbor.Encode(outer)
	if err != nil {
		t.Fatalf("encode modified tx: %v", err)
	}

	want := []string{addrHi.String(), addrLo.String()}
	sort.Strings(want)

	// DecodeTx re-parses TxWithdrawals from the tx body on every call, and Go
	// randomizes map iteration order per-run, so a single call would only
	// catch a dropped sort about half the time. Repeat the decode so the test
	// reliably fails if the production sort is ever removed.
	txHex := hex.EncodeToString(newTxBytes)
	for attempt := 0; attempt < 32; attempt++ {
		got, err := svc.DecodeTx(context.Background(), txHex)
		if err != nil {
			t.Fatalf("DecodeTx (attempt %d): %v", attempt, err)
		}
		if len(got.Withdrawals) != 2 {
			t.Fatalf("attempt %d: got %d withdrawals, want 2: %+v", attempt, len(got.Withdrawals), got.Withdrawals)
		}
		gotAddrs := []string{got.Withdrawals[0].Address, got.Withdrawals[1].Address}
		if gotAddrs[0] != want[0] || gotAddrs[1] != want[1] {
			t.Fatalf("attempt %d: withdrawals order = %v, want sorted %v", attempt, gotAddrs, want)
		}
	}
}

// bytesRepeat returns an n-byte slice with every byte set to b, for
// constructing distinct fixed-length key hashes in tests.
func bytesRepeat(b byte, n int) []byte {
	s := make([]byte, n)
	for i := range s {
		s[i] = b
	}
	return s
}

func TestCosignTx_MergesPreservingExisting(t *testing.T) {
	svc, acct, unsignedCbor := buildUnsignedSendFixture(t)
	_ = acct

	// Seed the fixture with a valid witness from an unrelated co-signer, so this
	// test actually exercises retention: a regression that drops or replaces
	// existing co-signer witnesses would now fail.
	foreign, foreignKH := foreignWitness(t, unsignedCbor)
	preSigned := attachWitness(t, svc, unsignedCbor, foreign)

	// Sanity: the foreign witness is present before we cosign.
	pre, err := svc.DecodeTx(context.Background(), preSigned)
	if err != nil {
		t.Fatalf("DecodeTx(preSigned): %v", err)
	}
	if !hasSigner(pre.ExistingSignatures, foreignKH) {
		t.Fatalf("pre-signed fixture missing the foreign witness %s", foreignKH)
	}

	// First co-sign: wallet adds its own witness on top of the foreign one.
	res, err := svc.CosignTx(context.Background(), preSigned, testPassword, true)
	if err != nil {
		t.Fatalf("CosignTx: %v", err)
	}
	if len(res.Added) == 0 {
		t.Fatal("expected at least one added witness")
	}
	for _, a := range res.Added {
		if a.KeyHash == foreignKH {
			t.Fatalf("cosign re-added the foreign witness %s instead of preserving it", foreignKH)
		}
	}

	// The updated tx must decode, retain the foreign witness, and carry ours.
	summary, err := svc.DecodeTx(context.Background(), res.TxCBOR)
	if err != nil {
		t.Fatalf("DecodeTx(updated): %v", err)
	}
	if !hasSigner(summary.ExistingSignatures, foreignKH) {
		t.Errorf("cosign dropped the pre-existing foreign witness %s", foreignKH)
	}
	if len(summary.ExistingSignatures) < len(res.Added)+1 {
		t.Errorf("updated tx has %d sigs, want >= %d (foreign + added)",
			len(summary.ExistingSignatures), len(res.Added)+1)
	}

	// Body-hash stability: re-cosigning must be idempotent (no duplicate witnesses).
	res2, err := svc.CosignTx(context.Background(), res.TxCBOR, testPassword, true)
	if err != nil {
		t.Fatalf("CosignTx (2nd): %v", err)
	}
	if len(res2.Added) != 0 {
		t.Errorf("second cosign added %d witnesses, want 0 (already present)", len(res2.Added))
	}
}

// hasSigner reports whether signers contains one with the given key hash.
func hasSigner(signers []TxSummarySigner, keyHash string) bool {
	for _, s := range signers {
		if s.KeyHash == keyHash {
			return true
		}
	}
	return false
}

func TestCosignTx_WrongPassword(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	addr0 := acct.ReceiveAddresses[0]
	fc := newFakeChain(5_000_000, addr0)
	good := NewService(fc, fakeKeystore{mnemonic: testMnemonic}, acct)

	pv, err := good.Build(context.Background(), SendRequest{To: acct.ReceiveAddresses[2], Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	unsigned, err := good.ExportUnsigned(pv.PendingID)
	if err != nil {
		t.Fatalf("ExportUnsigned: %v", err)
	}

	// A service bound to the same account whose keystore rejects the password.
	bad := NewService(fc, fakeKeystore{err: keystore.ErrDecryptFailed}, acct)
	_, err = bad.CosignTx(context.Background(), unsigned.UnsignedTxCBOR, "wrong", true)
	if !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("err = %v, want ErrWrongPassword", err)
	}
}

func TestSubmitTxCbor_Broadcasts(t *testing.T) {
	svc, _, unsignedCbor := buildUnsignedSendFixture(t) // fake chain records SubmitTx

	// The import flow submits a fully assembled tx, not raw unsigned CBOR: cosign
	// first, then broadcast the CosignResult's CBOR. Asserting the witness was
	// added keeps this test honest — it would otherwise pass even if submission
	// wrongly accepted an unsigned transaction.
	cos, err := svc.CosignTx(context.Background(), unsignedCbor, testPassword, true)
	if err != nil {
		t.Fatalf("CosignTx: %v", err)
	}
	if len(cos.Added) == 0 {
		t.Fatal("expected cosign to add at least one witness")
	}
	summary, err := svc.DecodeTx(context.Background(), cos.TxCBOR)
	if err != nil {
		t.Fatalf("DecodeTx(cosigned): %v", err)
	}
	if len(summary.ExistingSignatures) < len(cos.Added) {
		t.Fatalf("cosigned tx has %d sigs, want >= %d", len(summary.ExistingSignatures), len(cos.Added))
	}

	res, err := svc.SubmitTxCbor(context.Background(), cos.TxCBOR)
	if err != nil {
		t.Fatalf("SubmitTxCbor: %v", err)
	}
	if res.TxHash == "" {
		t.Error("expected a tx hash")
	}
}

func TestSubmitTxCbor_BadHex(t *testing.T) {
	svc := newBuildOnlyService(t)
	if _, err := svc.SubmitTxCbor(context.Background(), "nothex"); !errors.Is(err, ErrInvalidTx) {
		t.Fatalf("err = %v, want ErrInvalidTx", err)
	}
}

func TestDecodeTx_Malformed(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{name: "non-hex", in: "zzzz"},
		{name: "valid-hex-invalid-cbor", in: "00"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newBuildOnlyService(t)
			_, err := svc.DecodeTx(context.Background(), tt.in)
			if err == nil {
				t.Fatalf("expected error for input %q", tt.in)
			}
			if !errors.Is(err, ErrInvalidTx) {
				t.Errorf("err = %v, want it to wrap ErrInvalidTx", err)
			}
		})
	}
}
