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

package spend

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/keystore"
)

// TestSetWalletReattachAcceptsEquivalentUnicodeForm re-attaches to a keystore
// created from one Unicode form of a phrase using a different form that
// decodes to the same entropy. Full-width Latin folds to ASCII under NFKD.
func TestSetWalletReattachAcceptsEquivalentUnicodeForm(t *testing.T) {
	t.Parallel()
	fullWidth := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' {
			return 0xFF41 + (r - 'a')
		}
		return r
	}, testMnemonic)
	if fullWidth == testMnemonic {
		t.Fatal("full-width form is identical, vector proves nothing")
	}

	ks := keystore.New(filepath.Join(t.TempDir(), "keystore.json"))
	s := NewService(newFakeChain(0, ""), ks, nil)
	want, err := s.SetWallet(testMnemonic, "preview", "spend-password-1")
	if err != nil {
		t.Fatalf("SetWallet create: %v", err)
	}
	got, err := s.SetWallet(fullWidth, "preview", "spend-password-1")
	if err != nil {
		t.Fatalf("SetWallet re-attach with equivalent form: %v", err)
	}
	if got.StakeAddress != want.StakeAddress {
		t.Fatalf("stake address %q, want %q", got.StakeAddress, want.StakeAddress)
	}
	if _, err := s.SetWallet(differentMnemonic, "preview", "spend-password-1"); err == nil {
		t.Fatal("re-attach with a different mnemonic must still fail")
	}
}
