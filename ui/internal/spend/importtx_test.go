package spend

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"

	"github.com/blinklabs-io/bursa/ui/internal/keystore"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
)

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
	got, err := svc.DecodeTx(unsignedCbor)
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

func TestCosignTx_MergesPreservingExisting(t *testing.T) {
	svc, acct, unsignedCbor := buildUnsignedSendFixture(t)
	_ = acct

	// First co-sign: wallet adds its payment witness.
	res, err := svc.CosignTx(context.Background(), unsignedCbor, testPassword, true)
	if err != nil {
		t.Fatalf("CosignTx: %v", err)
	}
	if len(res.Added) == 0 {
		t.Fatal("expected at least one added witness")
	}

	// The updated tx must decode and now carry the witness(es).
	summary, err := svc.DecodeTx(res.TxCBOR)
	if err != nil {
		t.Fatalf("DecodeTx(updated): %v", err)
	}
	if len(summary.ExistingSignatures) < len(res.Added) {
		t.Errorf("updated tx has %d sigs, want >= %d", len(summary.ExistingSignatures), len(res.Added))
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
			_, err := svc.DecodeTx(tt.in)
			if err == nil {
				t.Fatalf("expected error for input %q", tt.in)
			}
			if !errors.Is(err, ErrInvalidTx) {
				t.Errorf("err = %v, want it to wrap ErrInvalidTx", err)
			}
		})
	}
}
