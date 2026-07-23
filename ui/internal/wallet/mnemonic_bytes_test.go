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
	"testing"

	"github.com/blinklabs-io/bursa"
)

// TestRootKeyFromMnemonicBytesMatchesString verifies the zeroable byte entry
// point used by the signing paths derives the identical root key to the string
// version, so no behavior changes when a decrypted mnemonic is kept in a
// zeroable buffer instead of an immutable string.
func TestRootKeyFromMnemonicBytesMatchesString(t *testing.T) {
	want, err := bursa.GetRootKeyFromMnemonic(testMnemonic, "")
	if err != nil {
		t.Fatalf("GetRootKeyFromMnemonic: %v", err)
	}
	got, err := RootKeyFromMnemonicBytes([]byte(testMnemonic))
	if err != nil {
		t.Fatalf("RootKeyFromMnemonicBytes: %v", err)
	}
	if !bytes.Equal([]byte(want), []byte(got)) {
		t.Fatalf("root key mismatch between byte and string derivation")
	}
}

func TestRootKeyFromMnemonicBytesRejectsInvalid(t *testing.T) {
	for _, m := range []string{"", "invalid mnemonic"} {
		if _, err := RootKeyFromMnemonicBytes([]byte(m)); err == nil {
			t.Errorf("expected error for invalid mnemonic %q", m)
		}
	}
}
