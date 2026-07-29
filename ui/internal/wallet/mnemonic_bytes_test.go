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
	"errors"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa"
	bip39 "github.com/blinklabs-io/go-bip39"
)

// TestRootKeyFromMnemonicBytesMatchesUpstream validates the local byte decoder
// against go-bip39's EntropyFromMnemonic (the upstream decoder) rather than
// against bursa.GetRootKeyFromMnemonic. That string path is a genuine
// cross-check only while ui pins a pre-zeroization bursa; once ui bumps past
// the PR that makes GetRootKeyFromMnemonic delegate to the byte decoder, it
// would become circular. Asserting against the upstream decoder keeps this a
// real guard after a bump. All five BIP39 word counts are covered so every
// checksumShift value (12/15/18/21/24 words -> shift 4/3/2/1/0) is exercised.
func TestRootKeyFromMnemonicBytesMatchesUpstream(t *testing.T) {
	for _, words := range []int{12, 15, 18, 21, 24} {
		entropy := make([]byte, words/3*4)
		for i := range entropy {
			entropy[i] = byte(i*7 + 3) // deterministic, non-uniform
		}

		mnemonic, err := bip39.NewMnemonic(entropy)
		if err != nil {
			t.Fatalf("%d words: NewMnemonic: %v", words, err)
		}
		if got := len(strings.Fields(mnemonic)); got != words {
			t.Fatalf("%d words: got %d words", words, got)
		}

		wantEntropy, err := bip39.EntropyFromMnemonic(mnemonic)
		if err != nil {
			t.Fatalf("%d words: EntropyFromMnemonic: %v", words, err)
		}
		gotEntropy, err := entropyFromMnemonicBytes([]byte(mnemonic))
		if err != nil {
			t.Fatalf("%d words: entropyFromMnemonicBytes: %v", words, err)
		}
		if !bytes.Equal(wantEntropy, gotEntropy) {
			t.Fatalf("%d words: byte decoder disagrees with upstream", words)
		}

		want := bursa.GetRootKey(wantEntropy, nil)
		got, err := RootKeyFromMnemonicBytes([]byte(mnemonic))
		if err != nil {
			t.Fatalf("%d words: RootKeyFromMnemonicBytes: %v", words, err)
		}
		if !bytes.Equal([]byte(want), []byte(got)) {
			t.Fatalf("%d words: root key mismatch vs upstream-derived key", words)
		}
	}
}

func TestRootKeyFromMnemonicBytesRejectsInvalid(t *testing.T) {
	// A 12-word mnemonic whose last token is not in the BIP39 word list:
	// legal length, so it reaches word lookup and fails there.
	unknownWord := "abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon zzzzzz"
	// All-"abandon": every token is a valid word and the length is legal, so
	// it reaches checksum verification and fails there (the valid all-zero-
	// entropy mnemonic ends in "about", not "abandon"). Confirmed checksum-
	// invalid via bip39.EntropyFromMnemonic (returns an error).
	invalidChecksum := "abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon abandon"
	if _, err := bip39.EntropyFromMnemonic(invalidChecksum); err == nil {
		t.Fatal("sanity: all-abandon must be checksum-invalid")
	}
	for _, m := range []string{"", "invalid mnemonic", unknownWord, invalidChecksum} {
		if _, err := RootKeyFromMnemonicBytes([]byte(m)); !errors.Is(err, bursa.ErrInvalidMnemonic) {
			t.Errorf("mnemonic %q: got err %v, want ErrInvalidMnemonic", m, err)
		}
	}
}
