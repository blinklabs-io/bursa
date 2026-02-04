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
	"errors"
	"strings"

	"filippo.io/edwards25519"
	"github.com/blinklabs-io/go-bip39"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"golang.org/x/crypto/blake2b"
)

// XPrv represents an extended private key (32 bytes k_L + 32 bytes k_R + 32 bytes chain code).
type XPrv []byte

// XPub represents an extended public key (32 bytes public + 32 bytes chain code).
type XPub []byte

// PublicKey represents a 32-byte Ed25519 public key.
type PublicKey []byte

// String returns the Bech32-encoded representation of the extended private key as root_xsk
func (x XPrv) String() string {
	if len(x) != 96 {
		return ""
	}
	converted, err := bech32.ConvertBits(x, 8, 5, true)
	if err != nil {
		return ""
	}
	encoded, err := bech32.Encode("root_xsk", converted)
	if err != nil {
		return ""
	}
	return encoded
}

// String returns the Bech32-encoded representation of the extended public key as root_xvk
func (x XPub) String() string {
	if len(x) != 64 {
		return ""
	}
	converted, err := bech32.ConvertBits(x, 8, 5, true)
	if err != nil {
		return ""
	}
	encoded, err := bech32.Encode("root_xvk", converted)
	if err != nil {
		return ""
	}
	return encoded
}

// String returns the Bech32-encoded representation of the public key as addr_vk
func (p PublicKey) String() string {
	if len(p) != 32 {
		return ""
	}
	converted, err := bech32.ConvertBits(p, 8, 5, true)
	if err != nil {
		return ""
	}
	encoded, err := bech32.Encode("addr_vk", converted)
	if err != nil {
		return ""
	}
	return encoded
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

// PrivateKey returns the 64-byte private key (k_L || k_R) portion of the extended private key.
func (x XPrv) PrivateKey() []byte {
	if len(x) != 96 {
		panic("XPrv must be 96 bytes")
	}
	out := make([]byte, 64)
	copy(out, x[:64])
	return out
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

// EncodeEd25519Private encodes a raw 32-byte Ed25519 private key seed as Bech32 (hrp: ed25519_sk)
func EncodeEd25519Private(sk []byte) (string, error) {
	if len(sk) != 32 {
		return "", errors.New("ed25519 private key seed must be 32 bytes")
	}
	converted, err := bech32.ConvertBits(sk, 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.Encode("ed25519_sk", converted)
}

// EncodeEd25519Public encodes a raw 32-byte Ed25519 public key as Bech32 (hrp: ed25519_pk)
func EncodeEd25519Public(pk []byte) (string, error) {
	if len(pk) != 32 {
		return "", errors.New("ed25519 public key must be 32 bytes")
	}
	converted, err := bech32.ConvertBits(pk, 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.Encode("ed25519_pk", converted)
}

// ParseEd25519Private decodes a Bech32-encoded Ed25519 private key seed with hrp ed25519_sk
func ParseEd25519Private(s string) ([]byte, error) {
	hrp, decoded, err := bech32.Decode(s)
	if err != nil {
		hrp, decoded, err = LenientBech32Decode(s)
		if err != nil {
			return nil, err
		}
	}
	if hrp != "ed25519_sk" {
		return nil, errors.New(
			"invalid HRP for ed25519 private key, expected ed25519_sk",
		)
	}
	converted, err := bech32.ConvertBits(decoded, 5, 8, false)
	if err != nil {
		return nil, err
	}
	if len(converted) != 32 {
		return nil, errors.New(
			"invalid length for ed25519 private key, expected 32 bytes",
		)
	}
	return converted, nil
}

// ParseEd25519Public decodes a Bech32-encoded Ed25519 public key with hrp ed25519_pk
func ParseEd25519Public(s string) ([]byte, error) {
	hrp, decoded, err := bech32.Decode(s)
	if err != nil {
		hrp, decoded, err = LenientBech32Decode(s)
		if err != nil {
			return nil, err
		}
	}
	if hrp != "ed25519_pk" {
		return nil, errors.New(
			"invalid HRP for ed25519 public key, expected ed25519_pk",
		)
	}
	converted, err := bech32.ConvertBits(decoded, 5, 8, false)
	if err != nil {
		return nil, err
	}
	if len(converted) != 32 {
		return nil, errors.New(
			"invalid length for ed25519 public key, expected 32 bytes",
		)
	}
	return converted, nil
}

// LenientBech32Decode decodes bech32 without enforcing the 90-char limit from the dependency.
// Returns hrp and the 5-bit data bytes as expected by ConvertBits.
// Validates the Bech32 checksum using btcsuite when possible, or custom implementation for long strings.
func LenientBech32Decode(s string) (string, []byte, error) {
	// First try btcsuite's decoder (which includes checksum validation)
	hrp, data, err := bech32.Decode(s)
	if err == nil {
		// btcsuite successfully decoded and validated the string
		return hrp, data, nil
	}

	// If btcsuite failed, check if it's due to length limit
	if strings.Contains(err.Error(), "invalid bech32 string length") {
		// Length limit exceeded, fall back to custom lenient decoding
		return lenientBech32DecodeNoValidation(s)
	}

	// btcsuite failed for other reasons (invalid format, bad checksum, etc.)
	return "", nil, err
}

// lenientBech32DecodeNoValidation decodes bech32 without length limit but with checksum validation.
// Used as fallback for long strings where btcsuite fails.
func lenientBech32DecodeNoValidation(s string) (string, []byte, error) {
	// Convert to lowercase as Bech32 is case-insensitive
	s = strings.ToLower(s)

	idx := strings.LastIndex(s, "1")
	if idx < 1 || idx+1 >= len(s) {
		return "", nil, errors.New("invalid bech32 string")
	}
	hrp := s[:idx]
	dataPart := s[idx+1:]

	// Convert data part to 5-bit values
	charset := "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	decoded := make([]byte, len(dataPart))
	for i, ch := range dataPart {
		pos := strings.IndexRune(charset, ch)
		if pos < 0 {
			return "", nil, errors.New("invalid bech32 character")
		}
		decoded[i] = byte(pos)
	}

	// Validate checksum
	if !validateBech32Checksum(hrp, decoded) {
		return "", nil, errors.New("invalid bech32 checksum")
	}

	// Return HRP and data without the 6 checksum characters
	return hrp, decoded[:len(decoded)-6], nil
}

// validateBech32Checksum validates the Bech32 checksum using the polymod algorithm.
func validateBech32Checksum(hrp string, data []byte) bool {
	expanded := expandHrp(hrp)
	combined := append(expanded, data...)
	return polymod(combined) == 1
}

// expandHrp expands the HRP for checksum calculation.
func expandHrp(hrp string) []byte {
	expanded := make([]byte, len(hrp)*2+1)
	for i, r := range hrp {
		expanded[i] = byte(r >> 5)
		expanded[i+len(hrp)+1] = byte(r & 31)
	}
	return expanded
}

// polymod calculates the Bech32 checksum using the BCH code.
func polymod(values []byte) uint32 {
	generator := []uint32{
		0x3b6a57b2,
		0x26508e6d,
		0x1ea119fa,
		0x3d4233dd,
		0x2a1462b3,
	}
	var chk uint32 = 1
	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := range uint(5) {
			if (b>>i)&1 == 1 {
				chk ^= generator[i]
			}
		}
	}
	return chk
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
	for i := range 32 {
		r := uint16(x[i]) + uint16(y[i]) + carry
		out[i] = byte(r & 0xff)
		carry = r >> 8
	}
	return out
}

func add28mul8(x, y []byte) []byte {
	var carry uint16

	out := make([]byte, 32)
	for i := range 28 {
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

// ParseXPrv parses a Bech32-encoded extended private key (root_xsk) and returns the XPrv.
func ParseXPrv(s string) (XPrv, error) {
	hrp, decoded, err := bech32.Decode(s)
	if err != nil {
		hrp, decoded, err = LenientBech32Decode(s)
		if err != nil {
			return nil, err
		}
	}
	if hrp != "root_xsk" {
		return nil, errors.New(
			"invalid HRP for extended private key, expected root_xsk",
		)
	}
	converted, err := bech32.ConvertBits(decoded, 5, 8, false)
	if err != nil {
		return nil, err
	}
	if len(converted) != 96 {
		return nil, errors.New(
			"invalid length for extended private key, expected 96 bytes",
		)
	}
	return XPrv(converted), nil
}

// ParseXPub parses a Bech32-encoded extended public key (root_xvk) and returns the XPub.
func ParseXPub(s string) (XPub, error) {
	hrp, decoded, err := bech32.Decode(s)
	if err != nil {
		hrp, decoded, err = LenientBech32Decode(s)
		if err != nil {
			return nil, err
		}
	}
	if hrp != "root_xvk" {
		return nil, errors.New(
			"invalid HRP for extended public key, expected root_xvk",
		)
	}
	converted, err := bech32.ConvertBits(decoded, 5, 8, false)
	if err != nil {
		return nil, err
	}
	if len(converted) != 64 {
		return nil, errors.New(
			"invalid length for extended public key, expected 64 bytes",
		)
	}
	return XPub(converted), nil
}

// ParsePublicKey parses a Bech32-encoded public key (addr_vk) and returns the PublicKey.
func ParsePublicKey(s string) (PublicKey, error) {
	hrp, decoded, err := bech32.Decode(s)
	if err != nil {
		return nil, err
	}
	if hrp != "addr_vk" {
		return nil, errors.New("invalid HRP for public key, expected addr_vk")
	}
	converted, err := bech32.ConvertBits(decoded, 5, 8, false)
	if err != nil {
		return nil, err
	}
	if len(converted) != 32 {
		return nil, errors.New(
			"invalid length for public key, expected 32 bytes",
		)
	}
	return PublicKey(converted), nil
}
