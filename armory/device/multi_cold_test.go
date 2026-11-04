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

package device

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"testing"
)

// The cold key objects of each scope of a multi image are fixed.
func TestColdKeyRange(t *testing.T) {
	t.Parallel()

	for _, c := range []struct {
		scope       Scope
		first, last uint32
	}{
		{ScopeTestnet, 0x20e50010, 0x20e50017},
		{Scope{Network: 1, Chain: "cardano-mainnet"}, 0x20e50018, 0x20e5001b},
		{Scope{Network: 1, Chain: "prime-mainnet"}, 0x20e5001c, 0x20e5001f},
	} {
		first, last, ok := ColdKeyRange(c.scope)
		if !ok || first != c.first || last != c.last {
			t.Errorf("ColdKeyRange(%s) = %#08x-%#08x %v, want %#08x-%#08x", c.scope.Name(), first, last, ok, c.first, c.last)
		}
	}

	if _, _, ok := ColdKeyRange(Scope{Network: 1, Chain: "other-mainnet"}); ok {
		t.Error("a scope no multi image serves has a cold key range")
	}

	// a scope without a range takes no cold key object at all
	if err := coldInRange(Scope{Network: 1, Chain: "other-mainnet"}, 0x20e50010); !errors.Is(err, errColdRange) {
		t.Errorf("coldInRange for a scope without a range = %v", err)
	}
}

// multiFirstKeys is a multi provisioning image on a fresh chip with the
// first host key of each scope.
func multiFirstKeys(t *testing.T) (*fakeChip, http.Handler) {
	t.Helper()

	chip := newFakeChip()
	h := multiImage(t, chip, true).Handler()

	for _, p := range multiProfiles {
		code, body := firstKey(t, h, p.key, p.scope)
		mustOK(t, "first key "+p.scope, code, body)
	}

	return chip, h
}

// A cold key is imported only into the range of the importing key's scope:
// both boundaries are accepted, the neighbouring slots refused.
func TestMultiColdImportInScopeRange(t *testing.T) {
	t.Parallel()

	_, h := multiFirstKeys(t)
	seed := byte(0x80)

	for _, c := range []struct {
		key    ed25519.PrivateKey
		scope  string
		accept []uint32
		refuse []uint32
	}{
		{multiKeyTestnet, scopeTestnetName, []uint32{0x20e50011, 0x20e50017}, []uint32{0x20e50018, 0x20e5001c}},
		{multiKeyCardano, scopeCardanoName, []uint32{0x20e50018, 0x20e5001b}, []uint32{0x20e50016, 0x20e5001c}},
		{multiKeyPrime, scopePrimeName, []uint32{0x20e5001c, 0x20e5001f}, []uint32{0x20e5001b, 0x20e50011}},
	} {
		for _, id := range c.refuse {
			seed++
			code, body := postAs(t, h, RouteProvisionCold, coldReq(id, seed), c.key)
			refused(t, fmt.Sprintf("%s import into %#08x", c.scope, id), code, body, errColdRange)
		}

		for _, id := range c.accept {
			seed++
			code, body := postAs(t, h, RouteProvisionCold, coldReq(id, seed), c.key)
			mustOK(t, fmt.Sprintf("%s import into %#08x", c.scope, id), code, body)
		}
	}
}

// A new profile takes only a cold key object of its own scope's range, even
// an unused key already on the chip outside it.
func TestMultiProfileColdInScopeRange(t *testing.T) {
	t.Parallel()

	chip, h := multiFirstKeys(t)
	counter := uint64(1)

	// unused keys left by an older image: one in the cardano range, one in
	// the testnet range
	chip.keys[0x20e50018] = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x90}, 32))
	chip.keys[0x20e50017] = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x91}, 32))

	for _, c := range []struct {
		name string
		net  uint8
		key  ed25519.PrivateKey
		cold uint32
	}{
		{"t@preview", 0, multiKeyTestnet, 0x20e50018},
		{"p@prime-mainnet", 1, multiKeyPrime, 0x20e50018},
		{"c@cardano-mainnet", 1, multiKeyCardano, 0x20e50017},
		{"p@prime-mainnet", 1, multiKeyPrime, 0x20e50017},
	} {
		code, body := postAs(t, h, RouteProvisionProfile, ProvisionRequest{
			Name: c.name, NetworkID: c.net, Slot: 5, ColdKeyID: c.cold, ChainCounter: &counter,
		}, c.key)
		refused(t, fmt.Sprintf("%s on %#08x", c.name, c.cold), code, body, errColdRange)
	}

	code, body := postAs(t, h, RouteProvisionProfile, ProvisionRequest{
		Name: "t@preview", Slot: 5, ColdKeyID: 0x20e50017, ChainCounter: &counter,
	}, multiKeyTestnet)
	mustOK(t, "testnet profile in its range", code, body)

	code, body = postAs(t, h, RouteProvisionProfile, ProvisionRequest{
		Name: "c@cardano-mainnet", NetworkID: 1, Slot: 6, ColdKeyID: 0x20e50018, ChainCounter: &counter,
	}, multiKeyCardano)
	mustOK(t, "cardano profile in its range", code, body)
}

// A profile stored by a single-scope image on a cold key outside its scope's
// range keeps working on the multi image; only new provisioning is refused.
func TestMultiKeepsOutOfRangeProfile(t *testing.T) {
	t.Parallel()

	chip := newFakeChip()
	old := imageOn(t, chip, 0, "")
	counter := uint64(3)

	code, body := rawPost(old.Handler(), RouteProvisionCold, jsonOf(t, coldReq(0x20e5001d, 0x92)))
	mustOK(t, "cold key on the testnet image", code, body)

	code, body = rawPost(old.Handler(), RouteProvisionProfile, jsonOf(t, ProvisionRequest{
		Name: "old@preview", Slot: 0, ColdKeyID: 0x20e5001d, ChainCounter: &counter,
	}))
	mustOK(t, "profile on the testnet image", code, body)

	if _, err := old.addHostKey(HostKeyRequest{PublicKey: hostPub(multiKeyTestnet)}); err != nil {
		t.Fatal(err)
	}

	signing := multiImage(t, chip, false)
	p := multiProfile{name: "old@preview", cold: 0x20e5001d}

	if resp := opcertFor(t, signing, chip, p, multiKeyTestnet, 1); resp.Error != "" {
		t.Fatalf("the out-of-range testnet profile no longer signs: %q", resp.Error)
	}

	code, body = postAs(t, signing.Handler(), RouteProvisionFloor, FloorRequest{Profile: "old@preview", ChainCounter: 4}, multiKeyTestnet)
	mustOK(t, "floor of the out-of-range profile", code, body)
}
