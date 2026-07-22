package spend

import (
	"context"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/wallet"
)

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
	svc, _, unsignedCbor := buildUnsignedSendFixture(t)
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
}

func TestDecodeTx_Malformed(t *testing.T) {
	svc := newBuildOnlyService(t)
	if _, err := svc.DecodeTx("zzzz"); err == nil {
		t.Fatal("expected error for non-hex CBOR")
	}
}
