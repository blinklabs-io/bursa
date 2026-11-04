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
	"net/http"
	"testing"
)

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

// A profile stored by a single-scope image keeps working on the multi image,
// whichever cold key object it names.
func TestMultiKeepsLegacyProfile(t *testing.T) {
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

// A key read that fails while checking another scope's keys refuses the
// request instead of skipping the comparison.
func TestMultiScopeConflictFailsClosed(t *testing.T) {
	t.Parallel()

	t.Run("cold import", func(t *testing.T) {
		chip, s := seedMulti(t)
		cardano := multiProfiles[1]
		chip.failPublic = map[uint32]bool{cardano.cold: true}

		code, body := postAs(t, s.Handler(), RouteProvisionCold, coldReq(0x20e50014, cardano.seed), multiKeyTestnet)
		refused(t, "testnet import of the cardano key, cardano key unreadable", code, body, errDevice)
	})

	t.Run("profile on an unreadable cold key", func(t *testing.T) {
		chip, s := seedMulti(t)
		counter := uint64(1)
		chip.keys[0x20e50014] = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{multiProfiles[1].seed}, 32))
		chip.failPublic = map[uint32]bool{0x20e50014: true}

		code, body := postAs(t, s.Handler(), RouteProvisionProfile, ProvisionRequest{
			Name: "dup@preview", Slot: 5, ColdKeyID: 0x20e50014, ChainCounter: &counter,
		}, multiKeyTestnet)
		refused(t, "testnet profile on an unreadable cold key", code, body, errDevice)
	})
}
