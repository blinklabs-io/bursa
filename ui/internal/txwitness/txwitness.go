// Package txwitness holds transaction-witness validation shared by the import
// flow's two code paths (the ordinary vkey path in internal/spend and the
// native-script path in internal/multisig). Keeping the Ed25519 check in one
// place means a future validation fix cannot make the two paths diverge and
// silently accept different witness sets.
package txwitness

import (
	"crypto/ed25519"

	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

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
