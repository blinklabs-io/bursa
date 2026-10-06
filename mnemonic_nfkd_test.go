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
	"errors"
	"strings"
	"testing"

	bip39 "github.com/blinklabs-io/go-bip39"
	"github.com/blinklabs-io/go-bip39/wordlists"
	"golang.org/x/text/unicode/norm"
)

// useJapaneseWordList swaps the process-wide go-bip39 word list for the
// duration of the test. go-bip39 holds a single word list per process, so no
// test in this file may call t.Parallel.
func useJapaneseWordList(t *testing.T) {
	t.Helper()
	previous := bip39.GetWordList()
	bip39.SetWordList(wordlists.Japanese)
	t.Cleanup(func() { bip39.SetWordList(previous) })
}

// nfkdTestEntropy is a fixed, non-uniform entropy so every derived vector is
// reproducible.
func nfkdTestEntropy(size int) []byte {
	entropy := make([]byte, size)
	for i := range entropy {
		entropy[i] = byte(i*7 + 3)
	}
	return entropy
}

// toFullWidthLatin maps ASCII letters to their U+FF21..U+FF5A full-width
// compatibility forms, which NFKD folds back to ASCII. Input methods emit these
// for Latin text typed in a CJK layout.
func toFullWidthLatin(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(0xFF41 + (r - 'a'))
		case r >= 'A' && r <= 'Z':
			b.WriteRune(0xFF21 + (r - 'A'))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// TestEntropyFromMnemonicBytesAcceptsNFC covers a Japanese mnemonic in NFC, the
// form an IME produces: identical phrase, different bytes from the NFKD word
// list. Without normalization the byte comparison in mnemonicWordIndex rejects
// every word.
func TestEntropyFromMnemonicBytesAcceptsNFC(t *testing.T) {
	useJapaneseWordList(t)
	want := nfkdTestEntropy(16)
	nfkdMnemonic, err := bip39.NewMnemonic(want)
	if err != nil {
		t.Fatalf("NewMnemonic: %v", err)
	}
	if !norm.NFKD.IsNormalString(nfkdMnemonic) {
		t.Fatalf("word list mnemonic is not NFKD, vector is invalid")
	}
	nfcMnemonic := norm.NFC.String(nfkdMnemonic)
	if nfcMnemonic == nfkdMnemonic {
		t.Fatalf("NFC and NFKD forms are identical, vector proves nothing")
	}

	for name, mnemonic := range map[string]string{
		"nfc":                   nfcMnemonic,
		"nfc-ideographic-space": strings.ReplaceAll(nfcMnemonic, " ", "　"),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := entropyFromMnemonicBytes([]byte(mnemonic))
			if err != nil {
				t.Fatalf("entropyFromMnemonicBytes: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("entropy = %x, want %x", got, want)
			}
		})
	}
}

// TestEntropyFromMnemonicBytesNFKDUnchanged is the idempotence case: a mnemonic
// already in NFKD decodes to the entropy it was built from and agrees with
// go-bip39, so normalization cannot alter an input the decoder accepted before.
func TestEntropyFromMnemonicBytesNFKDUnchanged(t *testing.T) {
	useJapaneseWordList(t)
	want := nfkdTestEntropy(32)
	mnemonic, err := bip39.NewMnemonic(want)
	if err != nil {
		t.Fatalf("NewMnemonic: %v", err)
	}
	if norm.NFKD.String(mnemonic) != mnemonic {
		t.Fatalf("mnemonic is not NFKD, vector is invalid")
	}
	upstream, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		t.Fatalf("EntropyFromMnemonic: %v", err)
	}
	got, err := entropyFromMnemonicBytes([]byte(mnemonic))
	if err != nil {
		t.Fatalf("entropyFromMnemonicBytes: %v", err)
	}
	if !bytes.Equal(got, want) || !bytes.Equal(got, upstream) {
		t.Fatalf("entropy = %x, want %x (upstream %x)", got, want, upstream)
	}
}

// TestEntropyFromMnemonicBytesASCIIInvariant checks that NFKD is the identity on
// English mnemonics at every BIP39 word count, and that a caller's buffer is
// never mutated by the decode.
func TestEntropyFromMnemonicBytesASCIIInvariant(t *testing.T) {
	for _, words := range []int{12, 15, 18, 21, 24} {
		want := nfkdTestEntropy(words / 3 * 4)
		mnemonic, err := bip39.NewMnemonic(want)
		if err != nil {
			t.Fatalf("%d words: NewMnemonic: %v", words, err)
		}
		if norm.NFKD.String(mnemonic) != mnemonic {
			t.Fatalf("%d words: English mnemonic changed under NFKD", words)
		}
		buf := []byte(mnemonic)
		got, err := entropyFromMnemonicBytes(buf)
		if err != nil {
			t.Fatalf("%d words: entropyFromMnemonicBytes: %v", words, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%d words: entropy = %x, want %x", words, got, want)
		}
		if string(buf) != mnemonic {
			t.Fatalf("%d words: caller buffer was modified", words)
		}
	}
}

// TestEntropyFromMnemonicBytesAcceptsFullWidthLatin covers the default English
// word list reached through a CJK input method: full-width letters and an
// ideographic space, both folded to ASCII by NFKD.
func TestEntropyFromMnemonicBytesAcceptsFullWidthLatin(t *testing.T) {
	want := nfkdTestEntropy(16)
	mnemonic, err := bip39.NewMnemonic(want)
	if err != nil {
		t.Fatalf("NewMnemonic: %v", err)
	}
	wide := toFullWidthLatin(strings.ReplaceAll(mnemonic, " ", "　"))
	if wide == mnemonic {
		t.Fatalf("full-width form is identical, vector proves nothing")
	}
	buf := []byte(wide)
	got, err := entropyFromMnemonicBytes(buf)
	if err != nil {
		t.Fatalf("entropyFromMnemonicBytes: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("entropy = %x, want %x", got, want)
	}
	if string(buf) != wide {
		t.Fatalf("caller buffer was modified")
	}
}

// TestNewWalletAcceptsNFC covers the restore gate: NewWallet must derive the
// same wallet from either Unicode form of one phrase.
func TestNewWalletAcceptsNFC(t *testing.T) {
	useJapaneseWordList(t)
	nfkdMnemonic, err := bip39.NewMnemonic(nfkdTestEntropy(16))
	if err != nil {
		t.Fatalf("NewMnemonic: %v", err)
	}
	nfcMnemonic := norm.NFC.String(nfkdMnemonic)
	if nfcMnemonic == nfkdMnemonic {
		t.Fatalf("NFC and NFKD forms are identical, vector proves nothing")
	}

	wantWallet, err := NewWallet(nfkdMnemonic, WithNetwork("preview"))
	if err != nil {
		t.Fatalf("NewWallet(NFKD): %v", err)
	}
	gotWallet, err := NewWallet(nfcMnemonic, WithNetwork("preview"))
	if err != nil {
		t.Fatalf("NewWallet(NFC): %v", err)
	}
	if gotWallet.PaymentAddress != wantWallet.PaymentAddress {
		t.Fatalf(
			"payment address = %q, want %q",
			gotWallet.PaymentAddress,
			wantWallet.PaymentAddress,
		)
	}
}

// TestMnemonicNormalizationRejectsInvalid confirms normalization widens the
// accepted set only to other forms of a valid phrase.
func TestMnemonicNormalizationRejectsInvalid(t *testing.T) {
	mnemonic, err := bip39.NewMnemonic(nfkdTestEntropy(16))
	if err != nil {
		t.Fatalf("NewMnemonic: %v", err)
	}
	words := strings.Fields(mnemonic)
	words[0], words[1] = words[1], words[0]
	broken := strings.Join(words, " ")
	if broken == mnemonic {
		t.Fatalf("swapped mnemonic is unchanged, vector proves nothing")
	}
	if _, err := entropyFromMnemonicBytes([]byte(broken)); !errors.Is(err, ErrInvalidMnemonic) {
		t.Fatalf("err = %v, want ErrInvalidMnemonic", err)
	}
	if _, err := NewWallet(broken); !errors.Is(err, ErrInvalidMnemonic) {
		t.Fatalf("NewWallet err = %v, want ErrInvalidMnemonic", err)
	}
	if _, err := entropyFromMnemonicBytes([]byte("\xff\xfe not utf8 at all")); !errors.Is(err, ErrInvalidMnemonic) {
		t.Fatalf("invalid UTF-8 err = %v, want ErrInvalidMnemonic", err)
	}
}
