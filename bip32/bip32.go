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

// Package bip32 implements BIP32-Ed25519 hierarchical deterministic key derivation
// following CIP-1852 specifications for Cardano HD wallets.
//
// Key types:
//   - XPrv: 96-byte extended private key (32 bytes k_L + 32 bytes k_R + 32 bytes chain code)
//   - XPub: 64-byte extended public key (32 bytes public key + 32 bytes chain code)
//   - PublicKey: 32-byte Ed25519 public key
//
// Usage:
//
//	rootKey := bip32.FromBip39Entropy(entropy, password)
//	childKey := rootKey.Derive(bip32.HardenedIndex(0))
//	publicKey := childKey.Public()
package bip32

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"

	"filippo.io/edwards25519"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/blake2b"
)

// XPrv represents an extended private key (32 bytes k_L + 32 bytes k_R + 32 bytes chain code).
type XPrv []byte

// XPub represents an extended public key (32 bytes public + 32 bytes chain code).
type XPub []byte

// PublicKey represents a 32-byte Ed25519 public key.
type PublicKey []byte

// PrivateKey returns the 64-byte private key portion (k_L + k_R) of the extended private key.
func (x XPrv) PrivateKey() []byte {
	if len(x) != 96 {
		panic("XPrv must be 96 bytes")
	}
	return x[:64]
}

// PublicKey returns the 32-byte public key portion of the extended private key.
func (x XPrv) PublicKey() []byte {
	if len(x) != 96 {
		panic("XPrv must be 96 bytes")
	}
	return makePublicKey(x[:32])
}

// ChainCode returns the 32-byte chain code portion of the extended private key.
func (x XPrv) ChainCode() []byte {
	if len(x) != 96 {
		panic("XPrv must be 96 bytes")
	}
	return x[64:]
}

// Public returns the extended public key derived from this extended private key.
func (x XPrv) Public() XPub {
	if len(x) != 96 {
		panic("XPrv must be 96 bytes")
	}
	pub := makePublicKey(x[:32])
	return XPub(append(pub, x.ChainCode()...))
}

// PublicKey returns the 32-byte public key portion of the extended public key.
func (x XPub) PublicKey() PublicKey {
	if len(x) != 64 {
		panic("XPub must be 64 bytes")
	}
	return PublicKey(x[:32])
}

// ChainCode returns the 32-byte chain code portion of the extended public key.
func (x XPub) ChainCode() []byte {
	if len(x) != 64 {
		panic("XPub must be 64 bytes")
	}
	return x[32:]
}

// Hash returns the Blake2b-224 hash of the public key (28 bytes).
func (x XPub) Hash() []byte {
	if len(x) != 64 {
		panic("XPub must be 64 bytes")
	}
	h, err := blake2b.New(28, nil)
	if err != nil {
		panic(err)
	}
	h.Write(x[:32])
	return h.Sum(nil)
}

// Hash returns the Blake2b-224 hash of the public key (28 bytes).
func (p PublicKey) Hash() []byte {
	if len(p) != 32 {
		panic("PublicKey must be 32 bytes")
	}
	h, err := blake2b.New(28, nil)
	if err != nil {
		panic(err)
	}
	h.Write(p)
	return h.Sum(nil)
}

// FromBip39Entropy derives the root extended private key from BIP39 entropy and password.
// Follows CIP-1852: generates BIP39 seed, derives master key via HMAC-SHA512,
// computes separate chain code via HMAC-SHA256, and applies Ed25519 clamping.
func FromBip39Entropy(entropy []byte, password []byte) XPrv {
	// Generate BIP39 mnemonic from entropy
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		panic(err) // Should not happen with valid entropy
	}

	// Generate BIP39 seed (64 bytes)
	seed := bip39.NewSeed(mnemonic, string(password))

	// Derive master key as per SLIP-0010
	h := hmac.New(sha512.New, []byte("ed25519 seed"))
	h.Write(seed)
	master := h.Sum(nil)

	priv := make([]byte, 32)
	copy(priv, master[:32])
	kr := make([]byte, 32)
	copy(kr, master[32:])

	// Compute chain code as HMAC-SHA256("ed25519 seed", 0x01 || seed)
	ccMac := hmac.New(sha256.New, []byte("ed25519 seed"))
	ccMac.Write([]byte{0x01})
	ccMac.Write(seed)
	chainCode := ccMac.Sum(nil)

	// Clamp the private key
	priv[0] &= 0b1111_1000
	priv[31] &= 0b0001_1111
	priv[31] |= 0b0100_0000

	xprv := make([]byte, 96)
	copy(xprv[:32], priv)
	copy(xprv[32:64], kr)
	copy(xprv[64:], chainCode)
	return xprv
}

func makePublicKey(priv []byte) []byte {
	// Use SetUniformBytes with zero-padding to avoid re-clamping derived keys.
	// Zero-padding creates a 512-bit value that reduces mod L correctly for both
	// manually-clamped root keys and derived child keys computed via add28mul8/add256bits.
	padded := make([]byte, 64)
	copy(padded[:32], priv)
	s, err := edwards25519.NewScalar().SetUniformBytes(padded)
	if err != nil {
		panic(err)
	}
	p := edwards25519.NewIdentityPoint().ScalarBaseMult(s)
	return p.Bytes()
}

func add256bits(x, y []byte) []byte {
	var carry uint16

	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		r := uint16(x[i]) + uint16(y[i]) + carry
		out[i] = byte(r & 0xff)
		carry = r >> 8
	}
	return out
}

func add28mul8(x, y []byte) []byte {
	var carry uint16

	out := make([]byte, 32)
	for i := 0; i < 28; i++ {
		r := uint16(x[i]) + (uint16(y[i]) << 3) + carry
		out[i] = byte(r & 0xff)
		carry = r >> 8
	}
	for i := 28; i < 32; i++ {
		r := uint16(x[i]) + carry
		out[i] = byte(r & 0xff)
		carry = r >> 8
	}
	return out
}

// Derive derives a child extended private key from the parent using the given index.
// Follows CIP-1852: hardened derivation uses private key, non-hardened uses public key.
// Index >= 0x80000000 indicates hardened derivation.
func (key XPrv) Derive(index uint32) XPrv {
	if len(key) != 96 {
		panic("XPrv must be 96 bytes")
	}
	keyHmac := hmac.New(sha512.New, key.ChainCode())
	chainHmac := hmac.New(sha512.New, key.ChainCode())

	serializedIndex := make([]byte, 4)
	binary.LittleEndian.PutUint32(serializedIndex, index)

	if hardened(index) {
		keyHmac.Write([]byte{0x00})
		keyHmac.Write(key[:32]) // left 32 bytes of private key (k_L)
		keyHmac.Write(serializedIndex)
		chainHmac.Write([]byte{0x01})
		chainHmac.Write(key[:32]) // left 32 bytes of private key (k_L)
		chainHmac.Write(serializedIndex)
	} else {
		pk := makePublicKey(key[:32]) // pub from k_L (left 32 bytes of private key)
		keyHmac.Write([]byte{0x02})
		keyHmac.Write(pk)
		keyHmac.Write(serializedIndex)
		chainHmac.Write([]byte{0x03})
		chainHmac.Write(pk)
		chainHmac.Write(serializedIndex)
	}

	zout := keyHmac.Sum(nil)
	iout := chainHmac.Sum(nil)

	zl := zout[:32]
	zr := zout[32:]

	parentKl := key[:32]
	parentKr := key[32:64]

	childKl := add28mul8(parentKl, zl)
	childKr := add256bits(parentKr, zr)
	childChain := iout[32:]

	child := make([]byte, 96)
	copy(child[:32], childKl)
	copy(child[32:64], childKr)
	copy(child[64:], childChain)

	return child
}

func hardened(index uint32) bool {
	return index >= 0x80000000
}

// HardenedIndex returns a hardened derivation index.
func HardenedIndex(index uint32) uint32 {
	return index | 0x80000000
}
