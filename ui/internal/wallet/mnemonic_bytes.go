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
)

// rootKeyFromMnemonicBytes derives a root key from a zeroable mnemonic byte
// slice. It mirrors bursa.GetRootKeyFromMnemonic without materializing the full
// mnemonic as an immutable Go string.
func rootKeyFromMnemonicBytes(mnemonic []byte) (bip32.XPrv, error) {
	entropy, err := entropyFromMnemonicBytes(mnemonic)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(entropy)
	return bursa.GetRootKey(entropy, nil), nil
}

func entropyFromMnemonicBytes(mnemonic []byte) ([]byte, error) {
	words := bytes.Fields(mnemonic)
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
		zeroBytes(data)
		return nil, bursa.ErrInvalidMnemonic
	}
	entropy := make([]byte, entropyLen)
	copy(entropy, data[:entropyLen])
	zeroBytes(data)
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
