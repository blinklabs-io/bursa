// Package txwitness holds transaction-signing validation shared by the import
// flow's ordinary vkey and native-script paths.
package txwitness

import (
	"crypto/ed25519"
	"errors"

	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/conway"
)

// ErrImportedAuxiliaryData marks an imported transaction whose auxiliary data
// was not built and reviewed through a structured Bursa flow.
var ErrImportedAuxiliaryData = errors.New("imported transactions with auxiliary data are unsupported")

// RejectImportedAuxiliaryData keeps imported signing paths from authorizing
// opaque metadata. Callers wrap the result with their own invalid-transaction
// sentinel so their existing API error mapping remains intact.
func RejectImportedAuxiliaryData(body *conway.ConwayTransactionBody) error {
	if body.TxAuxDataHash != nil {
		return ErrImportedAuxiliaryData
	}
	return nil
}

// Valid reports whether w is a genuine Ed25519 signature by w.Vkey over msg —
// the transaction body hash bytes the witness is meant to sign. Cardano's
// BIP32-Ed25519 witnesses verify under standard Ed25519 against the 32-byte
// public key, so a pasted tx carrying a malformed or foreign witness (even one
// bearing this wallet's own pubkey) is rejected here rather than being trusted
// by key-hash alone.
func Valid(w lcommon.VkeyWitness, msg []byte) bool {
	if len(w.Vkey) != ed25519.PublicKeySize || len(w.Signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(w.Vkey), msg, w.Signature)
}
