// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wallet

import (
	"bytes"
	"crypto/sha256"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/bip32"
	bip39 "github.com/blinklabs-io/go-bip39"
	"golang.org/x/text/unicode/norm"
)

// RootKeyFromMnemonicBytes derives a CIP-1852 root key from a zeroable mnemonic
// byte slice. It mirrors bursa.GetRootKeyFromMnemonic without materializing the
// full mnemonic as an immutable Go string, so signing paths that hold the
// decrypted mnemonic in a zeroable buffer can derive without leaving an
// un-zeroable copy on the heap. The caller keeps ownership of, and must zero,
// the mnemonic slice it passes in.
//
// The ui module pins the bursa root module to a published commit (there is no
// local replace directive), so this lives here rather than calling a root-module
// helper: it lets the wallet's own packages derive from bytes without depending
// on an unreleased bursa version.
func RootKeyFromMnemonicBytes(mnemonic []byte) (bip32.XPrv, error) {
	entropy, err := entropyFromMnemonicBytes(mnemonic)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(entropy)
	return bursa.GetRootKey(entropy, nil), nil
}

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
		return nil, bursa.ErrInvalidMnemonic
	}

	wordList := bip39.GetWordList()
	if len(wordList) != 2048 {
		return nil, bursa.ErrInvalidMnemonic
	}

	entropyLen := len(words) / 3 * 4
	checksumBits := len(words) / 3
	data := make([]byte, entropyLen+1)
	defer zeroBytes(data)
	for i, word := range words {
		index, ok := mnemonicWordIndex(word, wordList)
		if !ok {
			return nil, bursa.ErrInvalidMnemonic
		}
		writeMnemonicIndexBits(data, i, index)
	}

	hash := sha256.Sum256(data[:entropyLen])
	checksumShift := 8 - uint(checksumBits)
	gotChecksum := data[entropyLen] >> checksumShift
	wantChecksum := hash[0] >> checksumShift
	if gotChecksum != wantChecksum {
		return nil, bursa.ErrInvalidMnemonic
	}
	entropy := make([]byte, entropyLen)
	copy(entropy, data[:entropyLen])
	return entropy, nil
}

func writeMnemonicIndexBits(out []byte, wordOffset, index int) {
	for bit := 0; bit < 11; bit++ {
		if index&(1<<uint(10-bit)) == 0 {
			continue
		}
		bitOffset := wordOffset*11 + bit
		out[bitOffset/8] |= 1 << uint(7-bitOffset%8)
	}
}

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

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
