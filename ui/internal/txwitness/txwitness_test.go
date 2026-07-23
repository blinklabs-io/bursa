package txwitness

import (
	"crypto/ed25519"
	"testing"

	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

func TestValid(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg := []byte("transaction body hash bytes")
	sig := ed25519.Sign(priv, msg)

	good := lcommon.VkeyWitness{Vkey: pub, Signature: sig}
	if !Valid(good, msg) {
		t.Error("a genuine signature over msg must be valid")
	}

	// Wrong message: the same key/signature over a different body must fail.
	if Valid(good, []byte("a different body")) {
		t.Error("signature over a different message must be rejected")
	}

	// Foreign/tampered signature bearing the same key must fail.
	tampered := sig[:]
	tampered = append([]byte(nil), tampered...)
	tampered[0] ^= 0xff
	if Valid(lcommon.VkeyWitness{Vkey: pub, Signature: tampered}, msg) {
		t.Error("a tampered signature must be rejected")
	}

	// Malformed sizes are rejected without attempting verification.
	if Valid(lcommon.VkeyWitness{Vkey: pub[:16], Signature: sig}, msg) {
		t.Error("a short vkey must be rejected")
	}
	if Valid(lcommon.VkeyWitness{Vkey: pub, Signature: sig[:32]}, msg) {
		t.Error("a short signature must be rejected")
	}
}
