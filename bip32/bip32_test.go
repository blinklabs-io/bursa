// Copyright 2025 Blink Labs Software
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

package bip32

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/bech32"
)

func TestFromBip39Entropy(t *testing.T) {
	// Test with zero entropy and empty password
	entropy := make([]byte, 32)
	password := []byte{}
	xprv := FromBip39Entropy(entropy, password)

	if len(xprv) != 96 {
		t.Errorf("Expected XPrv length 96, got %d", len(xprv))
	}

	// Check that private key is clamped
	priv := xprv[:64]
	if len(priv) != 64 {
		t.Errorf("Expected private key length 64, got %d", len(priv))
	}
	if (priv[0] & 0b0000_0111) != 0 {
		t.Errorf("Private key not clamped: first byte %x", priv[0])
	}
	if (priv[31] & 0b1110_0000) != 0b0100_0000 {
		t.Errorf("Private key not clamped: last byte %x", priv[31])
	}
}

func TestDerive(t *testing.T) {
	// Start with a known root key
	entropy := []byte{
		0x00,
		0x01,
		0x02,
		0x03,
		0x04,
		0x05,
		0x06,
		0x07,
		0x08,
		0x09,
		0x0a,
		0x0b,
		0x0c,
		0x0d,
		0x0e,
		0x0f,
		0x10,
		0x11,
		0x12,
		0x13,
		0x14,
		0x15,
		0x16,
		0x17,
		0x18,
		0x19,
		0x1a,
		0x1b,
		0x1c,
		0x1d,
		0x1e,
		0x1f,
	}
	password := []byte{}
	root := FromBip39Entropy(entropy, password)

	// Derive hardened child
	child := root.Derive(0x80000000)

	if len(child) != 96 {
		t.Errorf("Expected child length 96, got %d", len(child))
	}

	// Check that child is different from parent
	if bytes.Equal(child, root) {
		t.Error("Child key should be different from parent")
	}

	// Derive non-hardened
	child2 := root.Derive(0)

	if bytes.Equal(child2, root) {
		t.Error("Non-hardened child should be different from parent")
	}
}

func TestPublicKey(t *testing.T) {
	entropy := make([]byte, 32)
	xprv := FromBip39Entropy(entropy, []byte{})

	pub := xprv.Public()
	if len(pub) != 64 {
		t.Errorf("Expected XPub length 64, got %d", len(pub))
	}

	publicKey := pub.PublicKey()
	if len(publicKey) != 32 {
		t.Errorf("Expected PublicKey length 32, got %d", len(publicKey))
	}

	// Check that public key matches the one in XPrv
	if !bytes.Equal(publicKey, xprv.PublicKey()) {
		t.Error("Public key from XPub should match XPrv")
	}
}

func TestHash(t *testing.T) {
	entropy := make([]byte, 32)
	xprv := FromBip39Entropy(entropy, []byte{})

	pub := xprv.Public()
	hash := pub.Hash()

	if len(hash) != 28 {
		t.Errorf("Expected hash length 28, got %d", len(hash))
	}

	publicKey := pub.PublicKey()
	hash2 := publicKey.Hash()

	if !bytes.Equal(hash, hash2) {
		t.Error("Hash from XPub and PublicKey should be the same")
	}
}

// TestCardanoWalletVectors validates CIP-1852 HD wallet derivation paths.
// Uses test vectors based on the CIP-1852 specification.
func TestCardanoWalletVectors(t *testing.T) {
	// Test vector 1: Entropy: all zeros
	entropy1 := make([]byte, 32) // 32 bytes of zeros
	password1 := []byte{}

	rootKey1 := FromBip39Entropy(entropy1, password1)

	// Verify root key has correct length and properties
	if len(rootKey1) != 96 {
		t.Errorf("Expected root key length 96, got %d", len(rootKey1))
	}

	rootPubKey1 := rootKey1.PublicKey()
	if len(rootPubKey1) != 32 {
		t.Errorf("Expected root public key length 32, got %d", len(rootPubKey1))
	}

	// Derive account key: m/1852'/1815'/0'
	accountKey1 := rootKey1.
		Derive(HardenedIndex(1852)).
		Derive(HardenedIndex(1815)).
		Derive(HardenedIndex(0))

	// Verify account key
	if len(accountKey1) != 96 {
		t.Errorf("Expected account key length 96, got %d", len(accountKey1))
	}

	// Derive payment key: m/1852'/1815'/0'/0/0
	paymentKey1 := accountKey1.Derive(0).Derive(0)
	paymentPubKey1 := paymentKey1.PublicKey()
	if len(paymentPubKey1) != 32 {
		t.Errorf(
			"Expected payment public key length 32, got %d",
			len(paymentPubKey1),
		)
	}

	// Derive stake key: m/1852'/1815'/0'/2/0
	stakeKey1 := accountKey1.Derive(2).Derive(0)
	stakePubKey1 := stakeKey1.PublicKey()
	if len(stakePubKey1) != 32 {
		t.Errorf(
			"Expected stake public key length 32, got %d",
			len(stakePubKey1),
		)
	}

	// Verify that payment and stake keys are different
	if bytes.Equal(paymentPubKey1, stakePubKey1) {
		t.Error("Payment and stake keys should be different")
	}

	// Verify that all derived keys are different from root
	if bytes.Equal(rootPubKey1, paymentPubKey1) {
		t.Error("Root and payment keys should be different")
	}
	if bytes.Equal(rootPubKey1, stakePubKey1) {
		t.Error("Root and stake keys should be different")
	}

	// Test DRep key derivation: m/1852'/1815'/0'/3/0
	drepKey1 := accountKey1.Derive(3).Derive(0)
	drepPubKey1 := drepKey1.PublicKey()
	if len(drepPubKey1) != 32 {
		t.Errorf(
			"Expected DRep public key length 32, got %d",
			len(drepPubKey1),
		)
	}

	// Test Committee Cold key: m/1852'/1815'/0'/4/0
	committeeColdKey1 := accountKey1.Derive(4).Derive(0)
	committeeColdPubKey1 := committeeColdKey1.PublicKey()
	if len(committeeColdPubKey1) != 32 {
		t.Errorf(
			"Expected committee cold public key length 32, got %d",
			len(committeeColdPubKey1),
		)
	}

	// Test Committee Hot key: m/1852'/1815'/0'/5/0
	committeeHotKey1 := accountKey1.Derive(5).Derive(0)
	committeeHotPubKey1 := committeeHotKey1.PublicKey()
	if len(committeeHotPubKey1) != 32 {
		t.Errorf(
			"Expected committee hot public key length 32, got %d",
			len(committeeHotPubKey1),
		)
	}

	// Test vector 2: Different entropy
	entropy2 := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	}
	password2 := []byte("test")

	rootKey2 := FromBip39Entropy(entropy2, password2)
	rootPubKey2 := rootKey2.PublicKey()

	// Derive account key: m/1852'/1815'/0'
	accountKey2 := rootKey2.
		Derive(HardenedIndex(1852)).
		Derive(HardenedIndex(1815)).
		Derive(HardenedIndex(0))

	// Derive payment key: m/1852'/1815'/0'/0/0
	paymentKey2 := accountKey2.Derive(0).Derive(0)
	paymentPubKey2 := paymentKey2.PublicKey()

	// Derive stake key: m/1852'/1815'/0'/2/0
	stakeKey2 := accountKey2.Derive(2).Derive(0)
	stakePubKey2 := stakeKey2.PublicKey()

	// Verify that keys from different entropy are different
	if bytes.Equal(rootPubKey1, rootPubKey2) {
		t.Error("Root keys from different entropy should be different")
	}
	if bytes.Equal(paymentPubKey1, paymentPubKey2) {
		t.Error("Payment keys from different entropy should be different")
	}
	if bytes.Equal(stakePubKey1, stakePubKey2) {
		t.Error("Stake keys from different entropy should be different")
	}

	// Test multiple accounts
	accountKey1_1 := rootKey1.
		Derive(HardenedIndex(1852)).
		Derive(HardenedIndex(1815)).
		Derive(HardenedIndex(1)) // Account 1

	paymentKey1_1 := accountKey1_1.Derive(0).Derive(0)
	paymentPubKey1_1 := paymentKey1_1.PublicKey()

	// Verify different accounts produce different keys
	if bytes.Equal(paymentPubKey1, paymentPubKey1_1) {
		t.Error("Keys from different accounts should be different")
	}
}

// TestHardenedIndex tests the HardenedIndex helper function.
func TestHardenedIndex(t *testing.T) {
	tests := []struct {
		input    uint32
		expected uint32
	}{
		{0, 0x80000000},
		{1, 0x80000001},
		{44, 0x8000002C},
		{1852, 0x8000073C},
	}

	for _, test := range tests {
		result := HardenedIndex(test.input)
		if result != test.expected {
			t.Errorf(
				"HardenedIndex(%d) = %x, want %x",
				test.input,
				result,
				test.expected,
			)
		}
	}
}

// TestStringMethods tests the String methods for XPrv, XPub, and PublicKey.
func TestStringMethods(t *testing.T) {
	// Test with zero entropy
	entropy := make([]byte, 32)
	password := []byte{}
	xprv := FromBip39Entropy(entropy, password)

	// Test XPrv String
	xprvStr := xprv.String()
	if xprvStr == "" {
		t.Error("XPrv String should not be empty")
	}
	if !strings.HasPrefix(xprvStr, "root_xsk") {
		t.Errorf("XPrv String should start with 'root_xsk', got %s", xprvStr)
	}

	// Test XPub String
	xpub := xprv.Public()
	xpubStr := xpub.String()
	if xpubStr == "" {
		t.Error("XPub String should not be empty")
	}
	if !strings.HasPrefix(xpubStr, "root_xvk") {
		t.Errorf("XPub String should start with 'root_xvk', got %s", xpubStr)
	}

	// Test PublicKey String
	pubKey := xpub.PublicKey()
	pubKeyStr := pubKey.String()
	if pubKeyStr == "" {
		t.Error("PublicKey String should not be empty")
	}
	if !strings.HasPrefix(pubKeyStr, "addr_vk") {
		t.Errorf(
			"PublicKey String should start with 'addr_vk', got %s",
			pubKeyStr,
		)
	}
}

// TestCIP0005Bech32Encoding validates CIP-0005 Bech32 encoding prefixes and formats
func TestCIP0005Bech32Encoding(t *testing.T) {
	// Test with known entropy for reproducible results
	entropy := make([]byte, 32)
	entropy[0] = 0x12
	entropy[1] = 0x34

	rootKey := FromBip39Entropy(entropy, []byte{})

	// Test root extended private key encoding (root_xsk)
	rootXskStr := rootKey.String()
	if !strings.HasPrefix(rootXskStr, "root_xsk") {
		t.Errorf(
			"Root extended private key should start with 'root_xsk', got %s",
			rootXskStr,
		)
	}

	// Test root extended public key encoding (root_xvk)
	rootXpub := rootKey.Public()
	rootXvkStr := rootXpub.String()
	if !strings.HasPrefix(rootXvkStr, "root_xvk") {
		t.Errorf(
			"Root extended public key should start with 'root_xvk', got %s",
			rootXvkStr,
		)
	}

	// Test payment verification key encoding (addr_vk)
	paymentKey := rootKey.Derive(0).Derive(0)
	paymentPubKey := PublicKey(paymentKey.PublicKey())
	paymentVkStr := paymentPubKey.String()
	if !strings.HasPrefix(paymentVkStr, "addr_vk") {
		t.Errorf(
			"Payment verification key should start with 'addr_vk', got %s",
			paymentVkStr,
		)
	}

	// Test stake verification key encoding (addr_vk)
	stakeKey := rootKey.Derive(2).Derive(0)
	stakePubKey := PublicKey(stakeKey.PublicKey())
	stakeVkStr := stakePubKey.String()
	if !strings.HasPrefix(stakeVkStr, "addr_vk") {
		t.Errorf(
			"Stake verification key should start with 'addr_vk', got %s",
			stakeVkStr,
		)
	}

	// Verify that all encoded strings are valid Bech32 (basic validation)
	testStrings := []string{rootXskStr, rootXvkStr, paymentVkStr, stakeVkStr}
	for _, s := range testStrings {
		if s == "" {
			t.Error("Bech32 encoded string should not be empty")
			continue
		}

		// Check that there's a separator '1'
		sepIndex := strings.Index(s, "1")
		if sepIndex == -1 || sepIndex == 0 || sepIndex == len(s)-1 {
			t.Errorf(
				"Invalid Bech32 format (missing or misplaced separator): %s",
				s,
			)
		}
	}

	// Test that different keys produce different encodings
	entropy2 := make([]byte, 32)
	entropy2[0] = 0x56
	entropy2[1] = 0x78
	rootKey2 := FromBip39Entropy(entropy2, []byte{})

	if rootKey.String() == rootKey2.String() {
		t.Error("Different entropy should produce different Bech32 encodings")
	}
}

func TestEd25519EncodeDecodeRoundTrip(t *testing.T) {
	// Generate a deterministic key pair for test (not cryptographically random)
	seed := make([]byte, 32)
	for i := range 32 {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	// Encode private seed and public
	skEnc, err := EncodeEd25519Private(seed)
	if err != nil {
		t.Fatalf("EncodeEd25519Private failed: %v", err)
	}
	pkEnc, err := EncodeEd25519Public(pub)
	if err != nil {
		t.Fatalf("EncodeEd25519Public failed: %v", err)
	}

	// Parse back
	skParsed, err := ParseEd25519Private(skEnc)
	if err != nil {
		t.Fatalf("ParseEd25519Private failed: %v", err)
	}
	pkParsed, err := ParseEd25519Public(pkEnc)
	if err != nil {
		t.Fatalf("ParseEd25519Public failed: %v", err)
	}

	if !bytes.Equal(skParsed, seed) {
		t.Fatalf("private key round-trip mismatch")
	}
	if !bytes.Equal(pkParsed, pub) {
		t.Fatalf("public key round-trip mismatch")
	}
}

func TestSign(t *testing.T) {
	entropy := make([]byte, 32)
	xprv := FromBip39Entropy(entropy, []byte{})
	pub := ed25519.PublicKey(xprv.PublicKey())

	// Sign a message and verify with standard ed25519.Verify
	msg := []byte("hello cardano")
	sig := xprv.Sign(msg)

	if len(sig) != 64 {
		t.Fatalf("Expected signature length 64, got %d", len(sig))
	}

	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("Signature verification failed")
	}

	// Signing different message should produce different signature
	sig2 := xprv.Sign([]byte("different message"))
	if bytes.Equal(sig, sig2) {
		t.Error("Different messages should produce different signatures")
	}

	// Different key should produce different signature for same message
	entropy2 := make([]byte, 32)
	entropy2[0] = 0x01
	xprv2 := FromBip39Entropy(entropy2, []byte{})
	sig3 := xprv2.Sign(msg)
	if bytes.Equal(sig, sig3) {
		t.Error("Different keys should produce different signatures")
	}

	// Verify deterministic: signing same message twice gives same signature
	sig4 := xprv.Sign(msg)
	if !bytes.Equal(sig, sig4) {
		t.Error("Signing should be deterministic")
	}

	// Verify with wrong key should fail
	pub2 := ed25519.PublicKey(xprv2.PublicKey())
	if ed25519.Verify(pub2, msg, sig) {
		t.Error("Verification with wrong key should fail")
	}

	// Verify with derived key
	child := xprv.Derive(HardenedIndex(1852)).Derive(HardenedIndex(1815)).Derive(HardenedIndex(0))
	childPub := ed25519.PublicKey(child.PublicKey())
	childSig := child.Sign(msg)
	if !ed25519.Verify(childPub, msg, childSig) {
		t.Fatal("Derived key signature verification failed")
	}

	// Empty message
	emptySig := xprv.Sign([]byte{})
	if !ed25519.Verify(pub, []byte{}, emptySig) {
		t.Fatal("Empty message signature verification failed")
	}
}

func TestLenientBech32Decode(t *testing.T) {
	// Generate a valid Bech32 string using the existing code
	entropy := make([]byte, 32)
	password := []byte{}
	xprv := FromBip39Entropy(entropy, password)
	pubKey := xprv.Public().PublicKey()
	validBech32 := pubKey.String()

	hrp, data, err := LenientBech32Decode(validBech32)
	if err != nil {
		t.Fatalf("LenientBech32Decode failed on valid string: %v", err)
	}
	if hrp != "addr_vk" {
		t.Errorf("Expected HRP 'addr_vk', got '%s'", hrp)
	}
	if len(data) == 0 {
		t.Error("Expected non-empty data")
	}

	// Test invalid Bech32 string with wrong checksum (modify a data character)
	// Change a character in the data part to make checksum invalid
	invalidChecksum := validBech32[:20] + "z" + validBech32[21:] // change char at position 20
	_, _, err = LenientBech32Decode(invalidChecksum)
	if err == nil {
		t.Error("LenientBech32Decode should fail on invalid checksum")
	}

	// Test invalid Bech32 string with invalid character
	invalidChar := strings.Replace(
		validBech32,
		"q",
		"!",
		1,
	) // replace first 'q' with '!'
	_, _, err = LenientBech32Decode(invalidChar)
	if err == nil {
		t.Error("LenientBech32Decode should fail on invalid character")
	}

	// Test invalid Bech32 string with no separator
	noSeparator := strings.Replace(validBech32, "1", "", 1)
	_, _, err = LenientBech32Decode(noSeparator)
	if err == nil {
		t.Error("LenientBech32Decode should fail on missing separator")
	}

	// Test long Bech32 string (should work with lenient decoder)
	// Create a long data payload that will result in a string >90 characters
	longData := make([]byte, 100) // 100 bytes should result in a long string
	for i := range longData {
		longData[i] = byte(i % 32) // Use valid 5-bit values
	}
	longEncoded, err := bech32.Encode("addr_vk", longData)
	if err != nil {
		t.Fatalf("Failed to encode long test string: %v", err)
	}
	if len(longEncoded) <= 90 {
		t.Fatalf("Test string should be >90 chars, got %d", len(longEncoded))
	}

	hrp2, data2, err := LenientBech32Decode(longEncoded)
	if err != nil {
		t.Fatalf("LenientBech32Decode failed on long string: %v", err)
	}
	if hrp2 != "addr_vk" {
		t.Errorf("Expected HRP 'addr_vk' for long string, got '%s'", hrp2)
	}
	if len(data2) == 0 {
		t.Error("Expected non-empty data for long string")
	}
	if !bytes.Equal(data2, longData) {
		t.Error("Decoded data should match original data")
	}

	// Test uppercase Bech32 string (should work with case-insensitive decoding)
	upperBech32 := strings.ToUpper(validBech32)
	hrp3, data3, err := LenientBech32Decode(upperBech32)
	if err != nil {
		t.Fatalf("LenientBech32Decode failed on uppercase string: %v", err)
	}
	if hrp3 != "addr_vk" {
		t.Errorf("Expected HRP 'addr_vk' for uppercase string, got '%s'", hrp3)
	}
	if !bytes.Equal(data, data3) {
		t.Error("Uppercase and lowercase should decode to same data")
	}
}
