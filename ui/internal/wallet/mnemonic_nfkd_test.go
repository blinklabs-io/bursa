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
	"reflect"
	"testing"

	bip39 "github.com/blinklabs-io/go-bip39"
	"github.com/blinklabs-io/go-bip39/wordlists"
	"golang.org/x/text/unicode/norm"
)

// TestDeriveFromMnemonicBytesFormInvariant checks that the zeroable-byte
// derivation accepts every Unicode form of one phrase and yields one account.
// Not t.Parallel: go-bip39 holds a single process-wide word list.
func TestDeriveFromMnemonicBytesFormInvariant(t *testing.T) {
	previous := bip39.GetWordList()
	bip39.SetWordList(wordlists.Japanese)
	t.Cleanup(func() { bip39.SetWordList(previous) })

	entropy := make([]byte, 16)
	for i := range entropy {
		entropy[i] = byte(i*7 + 3)
	}
	nfkd, err := bip39.NewMnemonic(entropy)
	if err != nil {
		t.Fatalf("NewMnemonic: %v", err)
	}
	nfc := norm.NFC.String(nfkd)
	if nfc == nfkd {
		t.Fatal("NFC and NFKD forms are identical, vector proves nothing")
	}
	want, err := DeriveFromMnemonicBytes([]byte(nfkd), "preprod", 2)
	if err != nil {
		t.Fatalf("DeriveFromMnemonicBytes(NFKD): %v", err)
	}
	got, err := DeriveFromMnemonicBytes([]byte(nfc), "preprod", 2)
	if err != nil {
		t.Fatalf("DeriveFromMnemonicBytes(NFC): %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("account differs between NFC and NFKD input:\n got %+v\nwant %+v", got, want)
	}
}
