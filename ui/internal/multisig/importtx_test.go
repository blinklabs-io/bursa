package multisig

import (
	"context"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	apollo "github.com/blinklabs-io/apollo/v2"
	"github.com/blinklabs-io/bursa"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

func TestPolicyFromScript_RoundTrip(t *testing.T) {
	kh := func(b byte) string { return hex.EncodeToString(bytesRepeat(b, 28)) }
	in := Policy{
		Threshold: 2,
		Participants: []Participant{
			{KeyHashHex: kh(1)}, {KeyHashHex: kh(2)}, {KeyHashHex: kh(3)},
		},
	}
	script, err := composeScript(in)
	if err != nil {
		t.Fatalf("composeScript: %v", err)
	}
	got, err := PolicyFromScript(script)
	if err != nil {
		t.Fatalf("PolicyFromScript: %v", err)
	}
	if got.Threshold != 2 || len(got.Participants) != 3 {
		t.Fatalf("got %d-of-%d, want 2-of-3", got.Threshold, len(got.Participants))
	}
	for i, part := range got.Participants {
		if part.KeyHashHex != in.Participants[i].KeyHashHex {
			t.Errorf("participant %d key hash = %s, want %s", i, part.KeyHashHex, in.Participants[i].KeyHashHex)
		}
	}
}

func TestPolicyFromScript_TimeLocked(t *testing.T) {
	before, after := uint64(100), uint64(200)
	kh := func(b byte) string { return hex.EncodeToString(bytesRepeat(b, 28)) }
	in := Policy{
		Threshold: 1, Participants: []Participant{{KeyHashHex: kh(1)}},
		InvalidBefore: &before, InvalidAfter: &after,
	}
	script, err := composeScript(in)
	if err != nil {
		t.Fatalf("composeScript: %v", err)
	}
	got, err := PolicyFromScript(script)
	if err != nil {
		t.Fatalf("PolicyFromScript: %v", err)
	}
	if got.InvalidBefore == nil || *got.InvalidBefore != before {
		t.Errorf("invalid_before = %v, want %d", got.InvalidBefore, before)
	}
	if got.InvalidAfter == nil || *got.InvalidAfter != after {
		t.Errorf("invalid_after = %v, want %d", got.InvalidAfter, after)
	}
	if got.Threshold != 1 || len(got.Participants) != 1 {
		t.Fatalf("got %d-of-%d, want 1-of-1", got.Threshold, len(got.Participants))
	}
}

// TestPolicyFromScript_UnsupportedShape covers a script shape composeScript
// never emits (a bare pubkey script, with no threshold clause at all): it
// must be rejected as ErrInvalidTx, not silently accepted or panicked on.
func TestPolicyFromScript_UnsupportedShape(t *testing.T) {
	kh := bytesRepeat(1, 28)
	script, err := bursa.NewScriptSig(kh)
	if err != nil {
		t.Fatalf("NewScriptSig: %v", err)
	}
	_, err = PolicyFromScript(script)
	if !errors.Is(err, ErrInvalidTx) {
		t.Fatalf("PolicyFromScript() error = %v, want ErrInvalidTx", err)
	}
}

func bytesRepeat(b byte, n int) []byte {
	s := make([]byte, n)
	for i := range s {
		s[i] = b
	}
	return s
}

// --- InspectTx / FindByScriptHash ------------------------------------------

// TestInspectTx_EmbeddedScript builds a real 2-of-3 multisig account, funds
// its script address, and Build()s an unsigned spend (which attaches the
// native script to the witness set per Build's contract). InspectTx must
// recover the embedded script's policy and report zero signatures collected
// so far, plus pick up the saved account's label via FindByScriptHash.
func TestInspectTx_EmbeddedScript(t *testing.T) {
	fc := newFakeChain()
	svc := NewService(fc, nil, filepath.Join(t.TempDir(), "multisig.json"))
	_, khA, _ := multiSigKeyHash(t, mnemonicA)
	_, khB, _ := multiSigKeyHash(t, mnemonicB)
	khC := hex.EncodeToString(bytesRepeat(3, 28))

	acct, err := svc.Create(CreateRequest{
		Label:   "treasury",
		Network: "preview",
		Policy: Policy{
			Threshold: 2,
			Participants: []Participant{
				{KeyHashHex: khA}, {KeyHashHex: khB}, {KeyHashHex: khC},
			},
		},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	fc.addUTxO(acct.ScriptAddress, strings.Repeat("11", 32), 0, 10_000_000)

	built, err := svc.Build(context.Background(), acct.ID, BuildRequest{To: externalAddr(t), Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	info, err := svc.InspectTx(built.UnsignedTxCBOR)
	if err != nil {
		t.Fatalf("InspectTx: %v", err)
	}
	if !info.IsMultiSig {
		t.Fatal("expected IsMultiSig")
	}
	if info.Threshold != 2 || len(info.Participants) != 3 {
		t.Errorf("got %d-of-%d, want 2-of-3", info.Threshold, len(info.Participants))
	}
	if info.SignedCount != 0 {
		t.Errorf("signed_count = %d, want 0", info.SignedCount)
	}
	if !info.ScriptEmbedded {
		t.Error("Build attaches the script, so ScriptEmbedded should be true")
	}
	if info.Label != acct.Label {
		t.Errorf("label = %q, want %q (recovered via FindByScriptHash)", info.Label, acct.Label)
	}
	if info.ScriptHash == "" {
		t.Error("expected a non-empty script hash")
	}
	for _, p := range info.Participants {
		if p.Signed {
			t.Errorf("participant %s reported signed on an unsigned tx", p.KeyHash)
		}
	}
}

// TestInspectTx_NotMultiSig feeds InspectTx an ordinary (no native script)
// unsigned tx CBOR and asserts it is not classified as multisig.
func TestInspectTx_NotMultiSig(t *testing.T) {
	fc := newFakeChain()
	svc := NewService(fc, nil, filepath.Join(t.TempDir(), "multisig.json"))

	info, err := svc.InspectTx(ordinaryUnsignedTxHex(t, fc))
	if err != nil {
		t.Fatalf("InspectTx: %v", err)
	}
	if info.IsMultiSig {
		t.Error("ordinary tx must not be classified multisig")
	}
	if info.ScriptEmbedded {
		t.Error("ordinary tx must not report an embedded script")
	}
}

// TestInspectTx_MalformedHex covers the ErrInvalidTx wrapping requirement for
// hex that doesn't even decode.
func TestInspectTx_MalformedHex(t *testing.T) {
	fc := newFakeChain()
	svc := NewService(fc, nil, filepath.Join(t.TempDir(), "multisig.json"))
	if _, err := svc.InspectTx("not-hex-at-all"); !errors.Is(err, ErrInvalidTx) {
		t.Fatalf("InspectTx(bad hex) error = %v, want ErrInvalidTx", err)
	}
}

// TestFindByScriptHash_SkipsDecodeErrors saves one account with a corrupt
// ScriptCBOR (so decodeScript fails) and one valid account, and asserts the
// search still finds the valid one rather than aborting on the bad record.
func TestFindByScriptHash_SkipsDecodeErrors(t *testing.T) {
	fc := newFakeChain()
	svc := NewService(fc, nil, filepath.Join(t.TempDir(), "multisig.json"))
	_, khA, _ := multiSigKeyHash(t, mnemonicA)

	acct, err := svc.Create(CreateRequest{
		Label:   "good",
		Network: "preview",
		Policy:  Policy{Threshold: 1, Participants: []Participant{{KeyHashHex: khA}}},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	script, err := decodeScript(acct.ScriptCBOR)
	if err != nil {
		t.Fatalf("decodeScript: %v", err)
	}
	wantHash := hex.EncodeToString(script.Hash().Bytes())

	// Inject a second, corrupt account directly into the store (bypassing
	// Create, which would validate the script).
	corrupt := Account{ID: "corrupt", Label: "corrupt", Network: "preview", ScriptCBOR: "zz-not-hex"}
	if err := svc.store.add(corrupt); err != nil {
		t.Fatalf("add corrupt account: %v", err)
	}

	got, ok, err := svc.FindByScriptHash(wantHash)
	if err != nil {
		t.Fatalf("FindByScriptHash: %v", err)
	}
	if !ok || got.ID != acct.ID {
		t.Fatalf("FindByScriptHash = %+v, %v, want %s, true", got, ok, acct.ID)
	}

	if _, ok, err := svc.FindByScriptHash(strings.Repeat("ab", 28)); err != nil || ok {
		t.Fatalf("FindByScriptHash(unknown) = %v, %v, want false, nil", ok, err)
	}
}

// --- CosignImported ----------------------------------------------------------

// TestCosignImported_AddsAndMerges builds a 1-of-1 account whose sole
// participant is this wallet's own CIP-1854 key, funds it, builds a spend, and
// cosigns the resulting pasted (unsigned) tx CBOR. The first cosign must
// attach the wallet's witness (Added=true, SignedCount=1); re-cosigning the
// returned CBOR must not attach a duplicate (Added=false, idempotent).
func TestCosignImported_AddsAndMerges(t *testing.T) {
	fc := newFakeChain()
	ks := newTestKeystore(t, mnemonicA)
	svc := NewService(fc, ks, filepath.Join(t.TempDir(), "multisig.json"))

	mk, err := svc.MyKey("test-password-123")
	if err != nil {
		t.Fatalf("MyKey: %v", err)
	}
	acct, err := svc.Create(CreateRequest{
		Label:   "solo",
		Network: "preview",
		Policy:  Policy{Threshold: 1, Participants: []Participant{{KeyHashHex: mk.KeyHashHex}}},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	fc.addUTxO(acct.ScriptAddress, strings.Repeat("22", 32), 0, 10_000_000)

	built, err := svc.Build(context.Background(), acct.ID, BuildRequest{To: externalAddr(t), Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	res, err := svc.CosignImported(built.UnsignedTxCBOR, "test-password-123")
	if err != nil {
		t.Fatalf("CosignImported: %v", err)
	}
	if !res.Added || res.SignedCount != 1 || res.Threshold != 1 {
		t.Fatalf("CosignImported = %+v, want Added=true SignedCount=1 Threshold=1", res)
	}
	if res.TxCBOR == "" {
		t.Fatal("expected non-empty tx_cbor")
	}

	// Re-cosigning the returned (already-signed) CBOR is idempotent: no
	// duplicate witness gets added.
	res2, err := svc.CosignImported(res.TxCBOR, "test-password-123")
	if err != nil {
		t.Fatalf("CosignImported (2nd): %v", err)
	}
	if res2.Added {
		t.Error("second cosign should not add a duplicate witness")
	}
	if res2.SignedCount != 1 {
		t.Errorf("SignedCount after re-cosign = %d, want 1", res2.SignedCount)
	}
}

// TestCosignImported_NotAParticipant builds an account whose sole participant
// is a foreign key-hash the wallet does not own, and asserts CosignImported
// refuses with ErrInvalidRequest rather than silently signing a script it
// isn't party to.
func TestCosignImported_NotAParticipant(t *testing.T) {
	fc := newFakeChain()
	ks := newTestKeystore(t, mnemonicA)
	svc := NewService(fc, ks, filepath.Join(t.TempDir(), "multisig.json"))

	acct, err := svc.Create(CreateRequest{
		Label:   "foreign",
		Network: "preview",
		Policy:  Policy{Threshold: 1, Participants: []Participant{{KeyHashHex: strings.Repeat("ab", 28)}}},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	fc.addUTxO(acct.ScriptAddress, strings.Repeat("33", 32), 0, 10_000_000)

	built, err := svc.Build(context.Background(), acct.ID, BuildRequest{To: externalAddr(t), Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if _, err := svc.CosignImported(built.UnsignedTxCBOR, "test-password-123"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("CosignImported error = %v, want ErrInvalidRequest", err)
	}
}

// ordinaryUnsignedTxHex builds a plain (non-script) unsigned spend directly
// through apollo — no AttachScript call — so the resulting Conway tx's
// witness set carries zero native scripts. It exercises the same
// build/complete path as Service.Build minus the script attachment, giving a
// realistic (not hand-crafted) "not multisig" fixture.
func ordinaryUnsignedTxHex(t *testing.T, fc *fakeChain) string {
	t.Helper()
	root, err := bursa.GetRootKeyFromMnemonic(mnemonicA, "")
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	acctKey, err := bursa.GetAccountKey(root, 0)
	if err != nil {
		t.Fatalf("account key: %v", err)
	}
	pay, err := bursa.GetPaymentKey(acctKey, 0)
	if err != nil {
		t.Fatalf("payment key: %v", err)
	}
	stake, err := bursa.GetStakeKey(acctKey, 0)
	if err != nil {
		t.Fatalf("stake key: %v", err)
	}
	addr, err := lcommon.NewAddressFromParts(
		lcommon.AddressTypeKeyKey, lcommon.AddressNetworkTestnet,
		pay.Public().PublicKey().Hash(), stake.Public().PublicKey().Hash(),
	)
	if err != nil {
		t.Fatalf("plain addr: %v", err)
	}
	fc.addUTxO(addr.String(), strings.Repeat("cc", 32), 0, 10_000_000)

	a := apollo.New(fc).
		SetWallet(apollo.NewExternalWallet(addr)).
		SetChangeAddress(addr)
	utxos, err := fc.Utxos(context.Background(), addr)
	if err != nil {
		t.Fatalf("utxos: %v", err)
	}
	a = a.AddLoadedUTxOs(utxos...)
	a = a.PayToAddress(addr, 1_000_000)

	a, err = a.CompleteContext(context.Background())
	if err != nil {
		t.Fatalf("complete ordinary tx: %v", err)
	}
	cborBytes, err := a.GetTxCbor()
	if err != nil {
		t.Fatalf("encode ordinary tx: %v", err)
	}
	return hex.EncodeToString(cborBytes)
}
