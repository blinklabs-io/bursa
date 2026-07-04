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
package handle

import (
	"context"
	"errors"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/chain"
)

func TestNormalizeStripsLeadingDollar(t *testing.T) {
	got, err := Normalize("$chris")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if got != "chris" {
		t.Fatalf("Normalize($chris) = %q, want %q", got, "chris")
	}
}

func TestNormalizeWithoutDollar(t *testing.T) {
	got, err := Normalize("chris")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if got != "chris" {
		t.Fatalf("Normalize(chris) = %q, want %q", got, "chris")
	}
}

func TestNormalizeTrimsWhitespace(t *testing.T) {
	got, err := Normalize("  $chris  ")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if got != "chris" {
		t.Fatalf("Normalize = %q, want %q", got, "chris")
	}
}

func TestNormalizeRejectsEmpty(t *testing.T) {
	for _, in := range []string{"", "$", "   ", "  $  "} {
		if _, err := Normalize(in); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("Normalize(%q) err = %v, want ErrInvalidName", in, err)
		}
	}
}

func TestAssetNameHex(t *testing.T) {
	cases := map[string]string{
		"chris": "6368726973",
		"ape":   "617065",
		"a":     "61",
	}
	for name, want := range cases {
		if got := AssetNameHex(name); got != want {
			t.Errorf("AssetNameHex(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestPolicyForNetworkMainnetOnly(t *testing.T) {
	policy, ok := PolicyForNetwork("mainnet")
	if !ok {
		t.Fatal("PolicyForNetwork(mainnet) ok = false, want true")
	}
	if policy != MainnetPolicyID {
		t.Fatalf("PolicyForNetwork(mainnet) = %q, want %q", policy, MainnetPolicyID)
	}
	for _, net := range []string{"preview", "preprod", "testnet", "", "MAINNET"} {
		if _, ok := PolicyForNetwork(net); ok {
			t.Errorf("PolicyForNetwork(%q) ok = true, want false", net)
		}
	}
}

func TestAssetUnit(t *testing.T) {
	unit, ok := AssetUnit("mainnet", "chris")
	if !ok {
		t.Fatal("AssetUnit(mainnet, chris) ok = false, want true")
	}
	want := MainnetPolicyID + "6368726973"
	if unit != want {
		t.Fatalf("AssetUnit(mainnet, chris) = %q, want %q", unit, want)
	}
	if _, ok := AssetUnit("preview", "chris"); ok {
		t.Fatal("AssetUnit(preview, chris) ok = true, want false")
	}
}

// fakeAssetLookup is a test double for AssetLookup; it records whether it was
// called (so tests can assert Resolve short-circuits on unsupported networks
// without touching the node) and which asset unit it was called with (so
// tests can assert Resolve queries the case-folded unit).
type fakeAssetLookup struct {
	called   bool
	gotAsset string
	addrs    []chain.AssetAddress
	err      error
}

func (f *fakeAssetLookup) AssetAddresses(_ context.Context, asset string) ([]chain.AssetAddress, error) {
	f.called = true
	f.gotAsset = asset
	return f.addrs, f.err
}

func TestResolveFound(t *testing.T) {
	lk := &fakeAssetLookup{addrs: []chain.AssetAddress{{Address: "addr1abc", Quantity: "1"}}}
	name, addr, err := Resolve(context.Background(), lk, "mainnet", "$chris")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if name != "chris" {
		t.Fatalf("Resolve name = %q, want chris", name)
	}
	if addr != "addr1abc" {
		t.Fatalf("Resolve address = %q, want addr1abc", addr)
	}
	if !lk.called {
		t.Fatal("Resolve did not query the node")
	}
}

func TestResolveNotFoundOnUnsupportedNetworkSkipsNodeQuery(t *testing.T) {
	lk := &fakeAssetLookup{addrs: []chain.AssetAddress{{Address: "addr1abc"}}}
	_, _, err := Resolve(context.Background(), lk, "preview", "$chris")
	if !errors.Is(err, chain.ErrNotFound) {
		t.Fatalf("Resolve err = %v, want chain.ErrNotFound", err)
	}
	if lk.called {
		t.Fatal("Resolve queried the node for a network with no Handle policy")
	}
}

func TestResolveNotFoundWhenNodeHasNotSeenAsset(t *testing.T) {
	lk := &fakeAssetLookup{err: chain.ErrNotFound}
	_, _, err := Resolve(context.Background(), lk, "mainnet", "chris")
	if !errors.Is(err, chain.ErrNotFound) {
		t.Fatalf("Resolve err = %v, want chain.ErrNotFound", err)
	}
}

func TestResolveNotFoundWhenNoHolders(t *testing.T) {
	lk := &fakeAssetLookup{addrs: nil}
	_, _, err := Resolve(context.Background(), lk, "mainnet", "chris")
	if !errors.Is(err, chain.ErrNotFound) {
		t.Fatalf("Resolve err = %v, want chain.ErrNotFound", err)
	}
}

func TestResolveInvalidNameNotFound(t *testing.T) {
	lk := &fakeAssetLookup{}
	_, _, err := Resolve(context.Background(), lk, "mainnet", "$")
	if !errors.Is(err, chain.ErrNotFound) {
		t.Fatalf("Resolve err = %v, want chain.ErrNotFound", err)
	}
	if lk.called {
		t.Fatal("Resolve queried the node for an invalid handle name")
	}
}

func TestResolvePropagatesHardErrors(t *testing.T) {
	wantErr := errors.New("boom")
	lk := &fakeAssetLookup{err: wantErr}
	_, _, err := Resolve(context.Background(), lk, "mainnet", "chris")
	if !errors.Is(err, wantErr) {
		t.Fatalf("Resolve err = %v, want %v", err, wantErr)
	}
}

func TestNormalizeCaseFolds(t *testing.T) {
	for _, in := range []string{"chris", "Chris", "CHRIS", "$chris", "$Chris", "$CHRIS"} {
		got, err := Normalize(in)
		if err != nil {
			t.Fatalf("Normalize(%q): %v", in, err)
		}
		if got != "chris" {
			t.Fatalf("Normalize(%q) = %q, want %q", in, got, "chris")
		}
	}
}

func TestAssetNameHexCaseInsensitive(t *testing.T) {
	want := AssetNameHex("chris")
	for _, in := range []string{"Chris", "CHRIS", "$Chris", "$CHRIS"} {
		norm, err := Normalize(in)
		if err != nil {
			t.Fatalf("Normalize(%q): %v", in, err)
		}
		if got := AssetNameHex(norm); got != want {
			t.Errorf("AssetNameHex(Normalize(%q)) = %q, want %q", in, got, want)
		}
	}
}

func TestAssetUnitCaseInsensitive(t *testing.T) {
	want, ok := AssetUnit("mainnet", "chris")
	if !ok {
		t.Fatal("AssetUnit(mainnet, chris) ok = false, want true")
	}
	for _, in := range []string{"Chris", "CHRIS", "$Chris", "$CHRIS"} {
		norm, err := Normalize(in)
		if err != nil {
			t.Fatalf("Normalize(%q): %v", in, err)
		}
		got, ok := AssetUnit("mainnet", norm)
		if !ok || got != want {
			t.Errorf("AssetUnit(mainnet, Normalize(%q)) = (%q, %v), want (%q, true)", in, got, ok, want)
		}
	}
}

// TestResolveCaseInsensitive asserts that mixed-case handle input resolves
// identically to lowercase input: same normalized name, same node query (the
// lowercased asset unit), same resolved address.
func TestResolveCaseInsensitive(t *testing.T) {
	wantUnit, ok := AssetUnit("mainnet", "chris")
	if !ok {
		t.Fatal("AssetUnit(mainnet, chris) ok = false, want true")
	}
	for _, in := range []string{"chris", "Chris", "CHRIS", "$Chris", "$CHRIS"} {
		lk := &fakeAssetLookup{addrs: []chain.AssetAddress{{Address: "addr1abc", Quantity: "1"}}}
		name, addr, err := Resolve(context.Background(), lk, "mainnet", in)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", in, err)
		}
		if name != "chris" {
			t.Errorf("Resolve(%q) name = %q, want chris", in, name)
		}
		if addr != "addr1abc" {
			t.Errorf("Resolve(%q) address = %q, want addr1abc", in, addr)
		}
		if lk.gotAsset != wantUnit {
			t.Errorf("Resolve(%q) queried asset %q, want %q", in, lk.gotAsset, wantUnit)
		}
	}
}
