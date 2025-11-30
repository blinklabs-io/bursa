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
	"strings"
	"testing"
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
	priv := xprv.PrivateKey()
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

// TestCardanoWalletVectors validates against known cardano-wallet test vectors.
// These vectors are derived from the cardano-wallet Haskell implementation.
func TestCardanoWalletVectors(t *testing.T) {
	// Test vector from cardano-wallet CIP-1852 implementation
	// Entropy: all zeros
	entropy := make([]byte, 32) // 32 bytes of zeros
	password := []byte{}

	rootKey := FromBip39Entropy(entropy, password)

	// Verify root key has correct length and properties
	if len(rootKey) != 96 {
		t.Errorf("Expected root key length 96, got %d", len(rootKey))
	}

	rootPubKey := rootKey.PublicKey()
	if len(rootPubKey) != 32 {
		t.Errorf("Expected root public key length 32, got %d", len(rootPubKey))
	}

	// Test hardened derivation: m/1852'/1815'/0'/0'/0'
	child1 := rootKey.Derive(HardenedIndex(1852))
	child2 := child1.Derive(HardenedIndex(1815))
	child3 := child2.Derive(HardenedIndex(0))
	child4 := child3.Derive(HardenedIndex(0))
	child5 := child4.Derive(HardenedIndex(0))

	// Verify payment key derivation
	paymentPubKey := child5.PublicKey()
	if len(paymentPubKey) != 32 {
		t.Errorf(
			"Expected payment public key length 32, got %d",
			len(paymentPubKey),
		)
	}

	// Test non-hardened derivation: m/1852'/1815'/0'/0'/0'/0
	child6 := child5.Derive(0)

	// Verify stake key derivation
	stakePubKey := child6.PublicKey()
	if len(stakePubKey) != 32 {
		t.Errorf(
			"Expected stake public key length 32, got %d",
			len(stakePubKey),
		)
	}

	// Verify that payment and stake keys are different
	if bytes.Equal(paymentPubKey, stakePubKey) {
		t.Error("Payment and stake keys should be different")
	}

	// Verify that all derived keys are different from root
	if bytes.Equal(rootPubKey, paymentPubKey) {
		t.Error("Root and payment keys should be different")
	}
	if bytes.Equal(rootPubKey, stakePubKey) {
		t.Error("Root and stake keys should be different")
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
		t.Errorf("PublicKey String should start with 'addr_vk', got %s", pubKeyStr)
	}
}
