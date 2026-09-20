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
	"crypto/sha256"

	"github.com/blinklabs-io/bursa/bip32"
	bip39 "github.com/blinklabs-io/go-bip39"
	"golang.org/x/text/unicode/norm"
)

// GetRootKeyFromMnemonicBytes derives the CIP-1852 root key from a mnemonic held
// in a zeroable byte slice, without ever materializing it as an immutable Go
// string. This is the entry point signing paths should use so the decrypted
// mnemonic never lingers on the heap in a string that cannot be zeroed; callers
// remain responsible for zeroing the byte slice they pass in.
//
// go-bip39 (v0.2.0) exposes no byte-oriented decode: every public entry point
// (IsMnemonicValid, EntropyFromMnemonic) takes a string and would force an
// immutable copy of the mnemonic. To avoid that, the BIP39 mnemonic->entropy
// decode (word lookup + checksum verification) is reimplemented here over the
// byte slice, using only go-bip39's word list. For a mnemonic already in NFKD
// form it produces entropy identical to bip39.EntropyFromMnemonic; unlike that
// function it also accepts the other Unicode forms BIP39 requires.
func GetRootKeyFromMnemonicBytes(
	mnemonic []byte,
	password string,
) (bip32.XPrv, error) {
	entropy, err := entropyFromMnemonicBytes(mnemonic)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(entropy)
	var pwBytes []byte
	if password != "" {
		pwBytes = []byte(password)
	}
	defer zeroBytes(pwBytes)
	return GetRootKey(entropy, pwBytes), nil
}

// entropyFromMnemonicBytes decodes BIP39 entropy from a mnemonic byte slice,
// verifying the checksum, without allocating an immutable mnemonic string.
func entropyFromMnemonicBytes(mnemonic []byte) ([]byte, error) {
	// BIP39 defines the mnemonic in NFKD, and the word lists are NFKD, so a
	// byte comparison against them rejects every other Unicode form of the same
	// phrase. Normalize before splitting, not after: NFKD folds the ideographic
	// space U+3000 that Japanese mnemonics use as a separator into U+0020.
	// norm.NFKD.Bytes may alias its argument, so only the copy it allocates for
	// a non-NFKD mnemonic is zeroed here; the caller still owns mnemonic.
	normalized := mnemonic
	if !norm.NFKD.IsNormal(mnemonic) {
		normalized = norm.NFKD.Bytes(mnemonic)
		defer zeroBytes(normalized)
	}

	words := bytes.Fields(normalized)
	if len(words)%3 != 0 || len(words) < 12 || len(words) > 24 {
		return nil, ErrInvalidMnemonic
	}

	wordList := bip39.GetWordList()
	if len(wordList) != 2048 {
		return nil, ErrInvalidMnemonic
	}

	entropyLen := len(words) / 3 * 4
	checksumBits := len(words) / 3
	data := make([]byte, entropyLen+1)
	defer zeroBytes(data)
	for i, word := range words {
		index, ok := mnemonicWordIndex(word, wordList)
		if !ok {
			return nil, ErrInvalidMnemonic
		}
		writeMnemonicIndexBits(data, i, index)
	}

	hash := sha256.Sum256(data[:entropyLen])
	checksumShift := 8 - uint(checksumBits)
	gotChecksum := data[entropyLen] >> checksumShift
	wantChecksum := hash[0] >> checksumShift
	if gotChecksum != wantChecksum {
		return nil, ErrInvalidMnemonic
	}
	entropy := make([]byte, entropyLen)
	copy(entropy, data[:entropyLen])
	return entropy, nil
}

// writeMnemonicIndexBits writes the 11-bit word index for the word at wordOffset
// into the packed bit buffer out (big-endian, matching BIP39 encoding).
func writeMnemonicIndexBits(out []byte, wordOffset, index int) {
	for bit := 0; bit < 11; bit++ {
		if index&(1<<uint(10-bit)) == 0 {
			continue
		}
		bitOffset := wordOffset*11 + bit
		out[bitOffset/8] |= 1 << uint(7-bitOffset%8)
	}
}

// mnemonicWordIndex returns the BIP39 word list index for word, comparing over
// bytes so the mnemonic is never converted to a string.
func mnemonicWordIndex(word []byte, wordList []string) (int, bool) {
	for i, candidate := range wordList {
		if len(word) != len(candidate) {
			continue
		}
		match := true
		for j := 0; j < len(candidate); j++ {
			if word[j] != candidate[j] {
				match = false
				break
			}
		}
		if match {
			return i, true
		}
	}
	return 0, false
}

// isMnemonicValid reports whether mnemonic decodes to valid BIP39 entropy under
// the active word list. It stands in for bip39.IsMnemonicValid, which matches
// the mnemonic in whatever Unicode form it arrives in and so rejects the NFC
// phrases input methods commonly produce for non-ASCII word lists.
func isMnemonicValid(mnemonic string) bool {
	b := []byte(mnemonic)
	defer zeroBytes(b)
	entropy, err := entropyFromMnemonicBytes(b)
	if err != nil {
		return false
	}
	zeroBytes(entropy)
	return true
}

// zeroBytes overwrites b with zeros.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
