package spend

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/conway"
)

// buildMessageTx returns a service and an unsigned transaction carrying a
// CIP-20 style message under label 674.
func buildMessageTx(t *testing.T, msg string) (*Service, string) {
	t.Helper()
	acct := mustDeriveConfirmAccount(t)
	s := NewService(newFakeChain(10_000_000, acct.ReceiveAddresses[0]), nil, acct)
	value := lcommon.MetaMap{Pairs: []lcommon.MetaPair{{
		Key:   lcommon.MetaText{Value: "msg"},
		Value: lcommon.MetaList{Items: []lcommon.TransactionMetadatum{lcommon.MetaText{Value: msg}}},
	}}}
	pv, err := s.BuildMetadata(context.Background(), MetadataRequest{
		Label: 674, Value: value, Signer: SignerPayment,
		ExpectedSignerCredential: expectedCredential(t, acct, SignerPayment),
	})
	if err != nil {
		t.Fatalf("BuildMetadata: %v", err)
	}
	unsigned, err := s.ExportUnsigned(pv.PendingID)
	if err != nil {
		t.Fatalf("ExportUnsigned: %v", err)
	}
	return s, unsigned.UnsignedTxCBOR
}

// setAuxData replaces the transaction's auxiliary data element, leaving the
// body (and so the hash a witness signs) untouched.
func setAuxData(t *testing.T, txHex string, aux []byte) string {
	t.Helper()
	raw, err := hex.DecodeString(txHex)
	if err != nil {
		t.Fatal(err)
	}
	var parts []cbor.RawMessage
	if _, err := cbor.Decode(raw, &parts); err != nil || len(parts) != 4 {
		t.Fatalf("decode tx: %v (%d parts)", err, len(parts))
	}
	parts[3] = aux
	out, err := cbor.Encode(parts)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(out)
}

func TestDecodeTxShowsTheMetadataItSigns(t *testing.T) {
	s, txHex := buildMessageTx(t, "swap 125 ADA")
	got, err := s.DecodeTx(context.Background(), txHex)
	if err != nil {
		t.Fatalf("DecodeTx: %v", err)
	}
	if err := got.ValidateForSigning(); err != nil {
		t.Fatalf("ValidateForSigning: %v", err)
	}
	if len(got.Metadata) != 1 || got.Metadata[0].Label != "674" {
		t.Fatalf("metadata = %+v, want one entry under label 674", got.Metadata)
	}
	if v := got.Metadata[0].Value; !strings.Contains(v, `"msg"`) || !strings.Contains(v, `"swap 125 ADA"`) {
		t.Errorf("metadata value = %q, want the message text", v)
	}
}

// A witness covers only the body, which carries the auxiliary data hash. If
// the wallet cannot show bytes matching that hash, approving would sign
// metadata the user never saw.
func TestDecodeTxRefusesMetadataItCannotShow(t *testing.T) {
	_, other := buildMessageTx(t, "something else")
	otherRaw, _ := hex.DecodeString(other)
	var otherParts []cbor.RawMessage
	if _, err := cbor.Decode(otherRaw, &otherParts); err != nil {
		t.Fatal(err)
	}
	// Tag 259 auxiliary data: {0: {674: "x"}, 1: [all-of []]}.
	withScript, _ := hex.DecodeString("d90103a200a11902a261780181820180")

	tests := []struct {
		name string
		tx   func(*testing.T, string) string
		want string
	}{
		{
			name: "missing",
			tx:   func(t *testing.T, tx string) string { return setAuxData(t, tx, []byte{0xf6}) },
			want: "auxiliary data not included",
		},
		{
			name: "different from the signed hash",
			tx:   func(t *testing.T, tx string) string { return setAuxData(t, tx, otherParts[3]) },
			want: "auxiliary data does not match its hash",
		},
		{
			name: "carrying scripts",
			tx: func(t *testing.T, tx string) string {
				hash := lcommon.Blake2b256Hash(withScript)
				tx = mutateConwayBody(t, tx, func(b *conway.ConwayTransactionBody) { b.TxAuxDataHash = &hash })
				return setAuxData(t, tx, withScript)
			},
			want: "auxiliary scripts",
		},
		{
			name: "present but not committed to by the body",
			tx: func(t *testing.T, tx string) string {
				return mutateConwayBody(t, tx, func(b *conway.ConwayTransactionBody) { b.TxAuxDataHash = nil })
			},
			want: "auxiliary data without a body hash",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, txHex := buildMessageTx(t, "swap 125 ADA")
			got, err := s.DecodeTx(context.Background(), tc.tx(t, txHex))
			if err != nil {
				t.Fatalf("DecodeTx: %v", err)
			}
			if len(got.Metadata) != 0 {
				t.Errorf("metadata = %+v, want none shown", got.Metadata)
			}
			err = got.ValidateForSigning()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateForSigning = %v, want %q", err, tc.want)
			}
		})
	}
}

// The decoder refuses auxiliary data with fields it does not know, so an
// extension cannot reach the signing gate unseen.
func TestDecodeTxRejectsUnknownAuxiliaryField(t *testing.T) {
	// Tag 259 auxiliary data: {0: {674: "x"}, 6: []}.
	withUnknownField, _ := hex.DecodeString("d90103a200a11902a2617806" + "80")
	s, txHex := buildMessageTx(t, "swap 125 ADA")
	hash := lcommon.Blake2b256Hash(withUnknownField)
	txHex = mutateConwayBody(t, txHex, func(b *conway.ConwayTransactionBody) { b.TxAuxDataHash = &hash })
	txHex = setAuxData(t, txHex, withUnknownField)
	if _, err := s.DecodeTx(context.Background(), txHex); err == nil ||
		!strings.Contains(err.Error(), "unknown auxiliary-data field 6") {
		t.Fatalf("DecodeTx error = %v, want unknown auxiliary-data field 6", err)
	}
}
