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

import "testing"

func TestEnumerateAddresses(t *testing.T) {
	mnemonic, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("mnemonic: %v", err)
	}
	addrs, err := EnumerateAddresses(mnemonic, "", "preview", 0, 0, 5)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if len(addrs) != 5 {
		t.Fatalf("expected 5 addresses, got %d", len(addrs))
	}
	seen := map[string]bool{}
	for _, a := range addrs {
		if a.Address == "" {
			t.Fatalf("empty address at index %d", a.Index)
		}
		if seen[a.Address] {
			t.Fatalf("duplicate address %s", a.Address)
		}
		seen[a.Address] = true
	}
	if addrs[0].Index != 0 || addrs[4].Index != 4 {
		t.Fatalf("unexpected index sequence")
	}
}

func TestEnumerateAddresses_CountValidation(t *testing.T) {
	m, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("mnemonic: %v", err)
	}
	if _, err := EnumerateAddresses(m, "", "preview", 0, 0, 0); err == nil {
		t.Fatalf("expected error for count=0")
	}
	if _, err := EnumerateAddresses(m, "", "preview", 0, 0, 1001); err == nil {
		t.Fatalf("expected error for count>1000")
	}
	if _, err := EnumerateAddresses(m, "", "preview", 0, maxAddressDerivationIndex, 2); err == nil {
		t.Fatalf("expected error for range past maximum address derivation index")
	}
	if _, err := EnumerateAddresses(m, "", "preview", 0, maxAddressDerivationIndex+1, 1); err == nil {
		t.Fatalf("expected error for start past maximum address derivation index")
	}
}
