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
	"crypto/ed25519"
	"errors"
	"testing"
)

// An honest signer's output is returned unchanged and reports no error.
func TestVerifyingSigner_PassesHonestSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	msg := []byte("the 32-byte transaction id-ish")

	sign := verifyingSigner(pub, func(m []byte) []byte { return ed25519.Sign(priv, m) })
	sig, err := sign(msg)
	if err != nil {
		t.Fatalf("honest signer rejected: %v", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatalf("returned signature does not verify")
	}
}

// A signer whose output is corrupted after signing (modeling a fault-injection
// glitch or memory corruption) is caught before the signature leaves the func.
func TestVerifyingSigner_DetectsCorruptedSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	msg := []byte("message")

	sign := verifyingSigner(pub, func(m []byte) []byte {
		s := ed25519.Sign(priv, m)
		s[0] ^= 0xff // flip a bit in the nonce point
		return s
	})
	sig, err := sign(msg)
	if !errors.Is(err, ErrSignatureVerification) {
		t.Fatalf("want ErrSignatureVerification, got err=%v sig=%x", err, sig)
	}
	if sig != nil {
		t.Fatalf("a bad signature must not be returned, got %x", sig)
	}
}

// A signer that signs with a different key than the public key it is paired
// with is caught (guards against key/closure mismatch in signerForKey).
func TestVerifyingSigner_DetectsWrongKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	_, otherPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	msg := []byte("message")

	sign := verifyingSigner(pub, func(m []byte) []byte { return ed25519.Sign(otherPriv, m) })
	if _, err := sign(msg); !errors.Is(err, ErrSignatureVerification) {
		t.Fatalf("want ErrSignatureVerification, got %v", err)
	}
}

// A malformed (non-32-byte) public key cannot silently pass verification.
func TestVerifyingSigner_RejectsMalformedPublicKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sign := verifyingSigner([]byte{0x01, 0x02}, func(m []byte) []byte { return ed25519.Sign(priv, m) })
	if _, err := sign([]byte("message")); !errors.Is(err, ErrSignatureVerification) {
		t.Fatalf("want ErrSignatureVerification for short pubkey, got %v", err)
	}
}
