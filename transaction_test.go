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

package bursa

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"testing"

	"github.com/blinklabs-io/bursa/bip32"
	"github.com/blinklabs-io/gouroboros/ledger"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

func mustTestTx(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/conway-unsigned.tx")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	raw, err := ReadCborInput(data)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return raw
}

func mustTxVkeyWitnesses(t *testing.T, txBytes []byte) []lcommon.VkeyWitness {
	t.Helper()
	txType, err := ledger.DetermineTransactionType(txBytes)
	if err != nil {
		t.Fatalf("determine tx type: %v", err)
	}
	tx, err := ledger.NewTransactionFromCbor(txType, txBytes)
	if err != nil {
		t.Fatalf("decode tx: %v", err)
	}
	witnesses := tx.Witnesses()
	if witnesses == nil {
		t.Fatalf("expected witness set")
	}
	return witnesses.Vkey()
}

func TestVkeyWitnessFieldRoundTrip_Array(t *testing.T) {
	in := []lcommon.VkeyWitness{{Vkey: make([]byte, 32), Signature: make([]byte, 64)}}
	encoded, err := encodeVkeyWitnessField(in, false)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out, hadTag, err := decodeVkeyWitnessField(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if hadTag {
		t.Fatalf("expected no tag for array form")
	}
	if len(out) != 1 {
		t.Fatalf("got %d witnesses want 1", len(out))
	}
}

func TestVkeyWitnessFieldRoundTrip_Set(t *testing.T) {
	in := []lcommon.VkeyWitness{{Vkey: make([]byte, 32), Signature: make([]byte, 64)}}
	encoded, err := encodeVkeyWitnessField(in, true)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out, hadTag, err := decodeVkeyWitnessField(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !hadTag {
		t.Fatalf("expected tag-258 set form")
	}
	if len(out) != 1 {
		t.Fatalf("got %d witnesses want 1", len(out))
	}
}

func TestDecodeVkeyWitnessField_Empty(t *testing.T) {
	out, hadTag, err := decodeVkeyWitnessField(nil)
	if err != nil {
		t.Fatalf("decode nil: %v", err)
	}
	if hadTag || len(out) != 0 {
		t.Fatalf("expected empty result for nil input")
	}
}

func TestInjectVkeyWitnesses_PreservesTxId(t *testing.T) {
	txBytes := mustTestTx(t)
	txType, err := ledger.DetermineTransactionType(txBytes)
	if err != nil {
		t.Fatalf("determine type: %v", err)
	}
	before, err := ledger.NewTransactionFromCbor(txType, txBytes)
	if err != nil {
		t.Fatalf("decode before: %v", err)
	}
	wit := lcommon.VkeyWitness{Vkey: make([]byte, 32), Signature: make([]byte, 64)}
	signed, err := injectVkeyWitnesses(txBytes, []lcommon.VkeyWitness{wit}, true)
	if err != nil {
		t.Fatalf("inject: %v", err)
	}
	after, err := ledger.NewTransactionFromCbor(txType, signed)
	if err != nil {
		t.Fatalf("decode after: %v", err)
	}
	if before.Hash().String() != after.Hash().String() {
		t.Fatalf("txid changed: %s -> %s", before.Hash(), after.Hash())
	}
	afterWits := after.Witnesses()
	if afterWits == nil {
		t.Fatalf("expected witness set after injection")
	}
	afterVkeys := afterWits.Vkey()
	if len(afterVkeys) != 1 {
		t.Fatalf("expected 1 vkey witness, got %d", len(afterVkeys))
	}
}

func TestCreateWitness_Extended(t *testing.T) {
	root := bip32.FromBip39Entropy(make([]byte, 32), nil)
	xprv := bip32.XPrv(root)
	lk := &LoadedKey{SKey: []byte(xprv), VKey: xprv.PublicKey()}
	txid := make([]byte, 32)
	for i := range txid {
		txid[i] = byte(i)
	}
	wit, err := CreateWitness(txid, lk)
	if err != nil {
		t.Fatalf("CreateWitness: %v", err)
	}
	if len(wit.Vkey) != 32 || len(wit.Signature) != 64 {
		t.Fatalf("bad witness sizes: vkey=%d sig=%d", len(wit.Vkey), len(wit.Signature))
	}
	if !ed25519.Verify(ed25519.PublicKey(xprv.PublicKey()), txid, wit.Signature) {
		t.Fatalf("extended-key signature does not verify with standard ed25519")
	}
}

func TestCreateWitness_Ed25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	lk := &LoadedKey{SKey: []byte(priv), VKey: pub}
	txid := make([]byte, 32)
	wit, err := CreateWitness(txid, lk)
	if err != nil {
		t.Fatalf("CreateWitness: %v", err)
	}
	if !ed25519.Verify(pub, txid, wit.Signature) {
		t.Fatalf("signature does not verify")
	}
}

func TestCreateWitness_Ed25519DerivesVKeyFromSKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	wrongPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("wrong keygen: %v", err)
	}
	txid := make([]byte, 32)
	wit, err := CreateWitness(txid, &LoadedKey{SKey: []byte(priv), VKey: wrongPub})
	if err != nil {
		t.Fatalf("CreateWitness: %v", err)
	}
	if !bytes.Equal(wit.Vkey, pub) {
		t.Fatalf("witness vkey was not derived from signing key")
	}
	if !ed25519.Verify(pub, txid, wit.Signature) {
		t.Fatalf("signature does not verify with derived public key")
	}
}

func TestCreateWitness_NilKeyFails(t *testing.T) {
	if _, err := CreateWitness(make([]byte, 32), nil); err == nil {
		t.Fatalf("expected error for nil signing key")
	}
}

func TestSignTransaction_RoundTrip(t *testing.T) {
	txBytes := mustTestTx(t)
	root := bip32.FromBip39Entropy(make([]byte, 32), nil)
	xprv := bip32.XPrv(root)
	lk := &LoadedKey{SKey: []byte(xprv), VKey: xprv.PublicKey()}
	signed, err := SignTransaction(txBytes, []*LoadedKey{lk})
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	txType, err := ledger.DetermineTransactionType(signed)
	if err != nil {
		t.Fatalf("determine signed type: %v", err)
	}
	tx, err := ledger.NewTransactionFromCbor(txType, signed)
	if err != nil {
		t.Fatalf("decode signed: %v", err)
	}
	witnesses := tx.Witnesses()
	if witnesses == nil {
		t.Fatalf("expected witness set")
	}
	wits := witnesses.Vkey()
	if len(wits) != 1 {
		t.Fatalf("expected 1 witness, got %d", len(wits))
	}
	if !ed25519.Verify(ed25519.PublicKey(xprv.PublicKey()), tx.Hash().Bytes(), wits[0].Signature) {
		t.Fatalf("witness signature does not verify against txid")
	}
}

func TestSignTransaction_DeduplicatesDuplicateSigners(t *testing.T) {
	txBytes := mustTestTx(t)
	root := bip32.FromBip39Entropy(make([]byte, 32), nil)
	xprv := bip32.XPrv(root)
	lk := &LoadedKey{SKey: []byte(xprv), VKey: xprv.PublicKey()}
	signed, err := SignTransaction(txBytes, []*LoadedKey{lk, lk})
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	wits := mustTxVkeyWitnesses(t, signed)
	if len(wits) != 1 {
		t.Fatalf("expected duplicate signer to produce 1 witness, got %d", len(wits))
	}
}

func TestAssembleTransaction_MergesWitnesses(t *testing.T) {
	txBytes := mustTestTx(t)
	r1 := bip32.FromBip39Entropy(make([]byte, 32), nil)
	r2 := bip32.FromBip39Entropy(append(make([]byte, 31), 1), nil)
	w1, err := WitnessTransaction(txBytes, &LoadedKey{SKey: []byte(r1), VKey: bip32.XPrv(r1).PublicKey()})
	if err != nil {
		t.Fatalf("witness 1: %v", err)
	}
	w2, err := WitnessTransaction(txBytes, &LoadedKey{SKey: []byte(r2), VKey: bip32.XPrv(r2).PublicKey()})
	if err != nil {
		t.Fatalf("witness 2: %v", err)
	}
	signed, err := AssembleTransaction(txBytes, []lcommon.VkeyWitness{w1, w2})
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	txType, err := ledger.DetermineTransactionType(signed)
	if err != nil {
		t.Fatalf("determine signed type: %v", err)
	}
	tx, err := ledger.NewTransactionFromCbor(txType, signed)
	if err != nil {
		t.Fatalf("decode signed: %v", err)
	}
	witnesses := tx.Witnesses()
	if witnesses == nil {
		t.Fatalf("expected witness set")
	}
	wits := witnesses.Vkey()
	if len(wits) != 2 {
		t.Fatalf("expected 2 witnesses, got %d", len(wits))
	}
}

func TestAssembleTransaction_DeduplicatesRepeatedWitnesses(t *testing.T) {
	txBytes := mustTestTx(t)
	r1 := bip32.FromBip39Entropy(make([]byte, 32), nil)
	r2 := bip32.FromBip39Entropy(append(make([]byte, 31), 1), nil)
	w1, err := WitnessTransaction(txBytes, &LoadedKey{SKey: []byte(r1), VKey: bip32.XPrv(r1).PublicKey()})
	if err != nil {
		t.Fatalf("witness 1: %v", err)
	}
	w2, err := WitnessTransaction(txBytes, &LoadedKey{SKey: []byte(r2), VKey: bip32.XPrv(r2).PublicKey()})
	if err != nil {
		t.Fatalf("witness 2: %v", err)
	}
	signed, err := AssembleTransaction(txBytes, []lcommon.VkeyWitness{w1, w1, w2, w2})
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	wits := mustTxVkeyWitnesses(t, signed)
	if len(wits) != 2 {
		t.Fatalf("expected repeated witnesses to dedupe to 2, got %d", len(wits))
	}
	if !bytes.Equal(wits[0].Vkey, w1.Vkey) || !bytes.Equal(wits[1].Vkey, w2.Vkey) {
		t.Fatalf("deduplication did not preserve witness order")
	}
}

func TestAssembleTransaction_DeduplicatesExistingWitnesses(t *testing.T) {
	txBytes := mustTestTx(t)
	root := bip32.FromBip39Entropy(make([]byte, 32), nil)
	lk := &LoadedKey{SKey: []byte(root), VKey: bip32.XPrv(root).PublicKey()}
	wit, err := WitnessTransaction(txBytes, lk)
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	signed, err := AssembleTransaction(txBytes, []lcommon.VkeyWitness{wit})
	if err != nil {
		t.Fatalf("first assemble: %v", err)
	}
	signed, err = AssembleTransaction(signed, []lcommon.VkeyWitness{wit})
	if err != nil {
		t.Fatalf("second assemble: %v", err)
	}
	wits := mustTxVkeyWitnesses(t, signed)
	if len(wits) != 1 {
		t.Fatalf("expected existing duplicate witness to remain 1, got %d", len(wits))
	}
}

func TestSignDigest_Standard(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	lk := &LoadedKey{SKey: []byte(priv), VKey: pub}
	msg := make([]byte, 32)
	for i := range msg {
		msg[i] = byte(i)
	}
	sig, err := SignDigest(lk, msg)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatalf("signature does not verify")
	}
	gotPub, err := PublicKeyOf(lk)
	if err != nil {
		t.Fatalf("PublicKeyOf: %v", err)
	}
	if !bytes.Equal(gotPub, pub) {
		t.Fatalf("PublicKeyOf mismatch: got %x, want %x", gotPub, pub)
	}
}

func TestSignDigest_Extended(t *testing.T) {
	root := bip32.FromBip39Entropy(make([]byte, 32), nil)
	x := bip32.XPrv(root)
	lk := &LoadedKey{SKey: []byte(x), VKey: x.PublicKey()}
	msg := make([]byte, 32)
	sig, err := SignDigest(lk, msg)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("expected 64-byte sig, got %d", len(sig))
	}
	pub, err := PublicKeyOf(lk)
	if err != nil {
		t.Fatalf("PublicKeyOf: %v", err)
	}
	// Extended-key signatures verify against the 32-byte public key with standard ed25519.
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		t.Fatalf("extended signature does not verify against pubkey")
	}
}

func testVkeyWitnesses(t *testing.T, n int) []lcommon.VkeyWitness {
	t.Helper()
	wits := make([]lcommon.VkeyWitness, 0, n)
	for range n {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		wits = append(wits, lcommon.VkeyWitness{
			Vkey:      pub,
			Signature: ed25519.Sign(priv, []byte("estimate")),
		})
	}
	return wits
}

func TestEstimateWitnessedTxSize_MatchesAssembledVkeyWitnesses(t *testing.T) {
	tx := mustTestTx(t)
	// 24 witnesses grow the array header from one byte to two.
	for _, n := range []int{1, 4, 24} {
		got, err := EstimateWitnessedTxSize(tx, uint(n), 0)
		if err != nil {
			t.Fatalf("estimate %d: %v", n, err)
		}
		signed, err := AssembleTransactionForEra(tx, ledger.TxTypeConway, testVkeyWitnesses(t, n))
		if err != nil {
			t.Fatalf("assemble %d: %v", n, err)
		}
		if got != len(signed) {
			t.Errorf("%d witnesses: estimate %d, signed size %d", n, got, len(signed))
		}
	}
}

func TestEstimateWitnessedTxSize_ExistingVkeyWitnesses(t *testing.T) {
	base, err := AssembleTransactionForEra(mustTestTx(t), ledger.TxTypeConway, testVkeyWitnesses(t, 2))
	if err != nil {
		t.Fatalf("assemble base: %v", err)
	}
	got, err := EstimateWitnessedTxSize(base, 3, 0)
	if err != nil {
		t.Fatalf("estimate: %v", err)
	}
	signed, err := AssembleTransactionForEra(base, ledger.TxTypeConway, testVkeyWitnesses(t, 3))
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if got != len(signed) {
		t.Errorf("estimate %d, signed size %d", got, len(signed))
	}
}

func TestEstimateWitnessedTxSize_SetFraming(t *testing.T) {
	tx := mustTestTx(t)
	// Conway adds the witness-set map key (1 byte), the tag-258 set tag (3)
	// and the array header (1) once, plus 101 bytes per vkey witness and 136
	// per bootstrap witness with empty attributes.
	for _, tc := range []struct {
		name            string
		vkey, bootstrap uint
		added           int
	}{
		{name: "vkey", vkey: 4, added: 5 + 4*101},
		{name: "bootstrap", bootstrap: 2, added: 5 + 2*136},
		{name: "both", vkey: 1, bootstrap: 1, added: 5 + 101 + 5 + 136},
	} {
		got, err := EstimateWitnessedTxSize(tx, tc.vkey, tc.bootstrap)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got-len(tx) != tc.added {
			t.Errorf("%s: added %d bytes, want %d", tc.name, got-len(tx), tc.added)
		}
	}
}

func TestEstimateWitnessedTxSize_CoversPreConwayEncoding(t *testing.T) {
	// Valid as Alonzo, Babbage and Conway; the estimate assumes Conway framing.
	tx, err := hex.DecodeString("84a3008001800200a0f5f6")
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	got, err := EstimateWitnessedTxSize(tx, 4, 0)
	if err != nil {
		t.Fatalf("estimate: %v", err)
	}
	signed, err := AssembleTransactionForEra(tx, ledger.TxTypeBabbage, testVkeyWitnesses(t, 4))
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if got < len(signed) {
		t.Errorf("estimate %d below Babbage signed size %d", got, len(signed))
	}
}

func TestEstimateWitnessedTxSize_RejectsExcessiveCount(t *testing.T) {
	if _, err := EstimateWitnessedTxSize(mustTestTx(t), MaxEstimatedWitnesses+1, 0); err == nil {
		t.Fatal("expected an error for an excessive witness count")
	}
}
