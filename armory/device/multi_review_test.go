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
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

// A multi image has no unsigned cold key import even before any host key is
// registered, and says so instead of claiming a key is registered.
func TestMultiUnsignedImportRefusalNamesFirstKey(t *testing.T) {
	t.Parallel()

	s := multiImage(t, newFakeChip(), true)
	if err := s.UnsignedProvisioningLocked(); !errors.Is(
		err,
		errUnsignedImportMulti,
	) {
		t.Fatalf(
			"UnsignedProvisioningLocked = %v, want %v",
			err,
			errUnsignedImportMulti,
		)
	}
}

// otherChainKey is registered by an image of a chain the multi image does not
// serve, then for scope by its own single-scope image.
func otherChainKey(
	t *testing.T,
	chip *fakeChip,
	k ed25519.PrivateKey,
	network uint8,
	chain string,
) {
	t.Helper()

	if _, err := imageOn(t, chip, 1, "other-mainnet").addHostKey(HostKeyRequest{PublicKey: hostPub(k)}); err != nil {
		t.Fatal(err)
	}

	if chain == "" && network == 0 {
		return
	}

	if _, err := imageOn(t, chip, network, chain).addHostKey(HostKeyRequest{PublicKey: hostPub(k)}); err != nil {
		t.Fatal(err)
	}
}

// A key stored for a scope the image does not serve is not a key of any of
// its scopes: adding it for testnet is refused rather than answered as done.
func TestMultiAddRefusesKeyOfUnservedScope(t *testing.T) {
	t.Parallel()

	chip := newFakeChip()
	k := scopeKey(0xd1)
	otherChainKey(t, chip, k, 0, "")

	// the device holds a key, so the testnet key is stored directly
	if _, err := imageOn(t, chip, 0, "").addHostKey(HostKeyRequest{PublicKey: hostPub(multiKeyTestnet)}); err != nil {
		t.Fatal(err)
	}

	h := multiImage(t, chip, true).Handler()
	code, body := firstKey(t, h, scopeKey(0xd2), scopeTestnetName)
	refused(
		t,
		"unsigned key on a device holding keys",
		code,
		body,
		errFirstKeyHeld,
	)

	stored := bytes.Clone(chip.bins[hostKeysID])

	code, body = postAs(
		t,
		h,
		RouteProvisionHostKey,
		HostKeyRequest{PublicKey: hostPub(k), Scope: scopeTestnetName},
		multiKeyTestnet,
	)
	refused(
		t,
		"testnet add of a key stored for an unserved chain",
		code,
		body,
		errKeyOtherScope,
	)

	if !bytes.Equal(chip.bins[hostKeysID], stored) {
		t.Fatal("the refused add changed the stored list")
	}
}

// A key stored first for an unserved chain and then for prime-mainnet acts
// as a prime-mainnet key only, never as a testnet one.
func TestMultiKeyScopeSkipsUnservedEntry(t *testing.T) {
	t.Parallel()

	chip := newFakeChip()
	counter := uint64(3)

	code, body := rawPost(
		imageOn(t, chip, 0, "").Handler(),
		RouteProvisionProfile,
		jsonOf(t, ProvisionRequest{
			Name: "otg@preview", Slot: 0, ColdKeyID: testColdID, ChainCounter: &counter,
		}),
	)
	mustOK(t, "profile on the testnet image", code, body)

	k := scopeKey(0xd2)
	otherChainKey(t, chip, k, 1, scopePrimeName)

	h := multiImage(t, chip, false).Handler()
	code, body = postAs(
		t,
		h,
		RouteProvisionFloor,
		FloorRequest{Profile: "otg@preview", ChainCounter: 4},
		k,
	)
	refused(t, "prime key on the testnet profile", code, body, errScopeMismatch)
}

// postWith sends req to h signed by key over challenge ch.
func postWith(
	t *testing.T,
	h http.Handler,
	path string,
	req any,
	key ed25519.PrivateKey,
	ch []byte,
) (int, []byte) {
	t.Helper()

	body, err := SignAdminRequest(path, jsonOf(t, req), key, ch)
	if err != nil {
		t.Fatal(err)
	}

	return rawPost(h, path, body)
}

func challengeOf(t *testing.T, h http.Handler) []byte {
	t.Helper()

	code, b := rawPost(h, "/v1/challenge", []byte("{}"))
	if code != http.StatusOK {
		t.Fatalf("challenge: %d %s", code, b)
	}

	var ch ChallengeResponse
	if err := json.Unmarshal(b, &ch); err != nil {
		t.Fatal(err)
	}

	return ch.Challenge
}

// A request refused for the scope of its key leaves its challenge to the key
// of the right scope: only an authorized request burns one.
func TestMultiScopeRefusalKeepsChallenge(t *testing.T) {
	t.Parallel()

	chip, s := seedMulti(t)
	installLog(t, s)
	h := s.Handler()
	testnet := multiProfiles[0]

	t.Run("admin", func(t *testing.T) {
		ch := challengeOf(t, h)
		req := FloorRequest{Profile: testnet.name, ChainCounter: 4}

		code, body := postWith(
			t,
			h,
			RouteProvisionFloor,
			req,
			multiKeyPrime,
			ch,
		)
		refused(t, "prime key", code, body, errScopeMismatch)

		code, body = postWith(
			t,
			h,
			RouteProvisionFloor,
			req,
			multiKeyTestnet,
			ch,
		)
		mustOK(t, "testnet key on the same challenge", code, body)
	})

	t.Run("device-wide", func(t *testing.T) {
		ch := challengeOf(t, h)

		code, body := postWith(
			t,
			h,
			RouteProvisionIdentity,
			IdentityRequest{},
			multiKeyTestnet,
			ch,
		)
		refused(t, "testnet key", code, body, errDeviceWide)

		code, body = postWith(
			t,
			h,
			RouteProvisionIdentity,
			IdentityRequest{},
			multiKeyCardano,
			ch,
		)
		mustOK(t, "cardano key on the same challenge", code, body)
	})

	// the admin subtest raised the floor to 4
	t.Run("sign", func(t *testing.T) {
		ch := challenge(t, s)
		cold, _ := chip.PublicKeyEd25519(testnet.cold)
		req := SignRequest{
			Version: Protocol, Purpose: "opcert-next", KeyHash: hashHex(cold), Role: "pool",
			Nonce: nonce(
				0x61,
			), Payload: opCertPayload(bytes.Repeat([]byte{0x4b}, 32), 4, 1100), Profile: testnet.name,
		}

		if resp := postSign(t, s, authenticate(req, multiKeyPrime, ch)); resp.Error != errScopeMismatch.Error() {
			t.Fatalf("prime key: %q", resp.Error)
		}

		if resp := postSign(t, s, authenticate(req, multiKeyTestnet, ch)); resp.Error != "" {
			t.Fatalf("testnet key on the same challenge: %q", resp.Error)
		}
	})

	t.Run("inventory", func(t *testing.T) {
		ch := challenge(t, s)
		as := func(k ed25519.PrivateKey) (int, []byte) {
			req := InventoryRequest{
				Nonce:     nonce(0x62),
				Profile:   testnet.name,
				Challenge: ch,
				HostKey:   hostPub(k),
			}
			req.HostSignature = ed25519.Sign(k, InventoryRequestBinding(req))

			return post(t, s, "/v1/inventory", req)
		}

		code, body := as(multiKeyPrime)
		refused(t, "prime key", code, body, errScopeMismatch)

		code, body = as(multiKeyTestnet)
		mustOK(t, "testnet key on the same challenge", code, body)
	})

	t.Run("signlog", func(t *testing.T) {
		ch := challenge(t, s)
		as := func(k ed25519.PrivateKey) (int, []byte) {
			req := SignLogRequest{
				Nonce:     nonce(0x63),
				Challenge: ch,
				HostKey:   hostPub(k),
			}
			req.HostSignature = ed25519.Sign(k, SignLogBinding(req))

			return post(t, s, "/v1/signlog", req)
		}

		code, body := as(multiKeyTestnet)
		refused(t, "testnet key", code, body, errDeviceWide)

		code, body = as(multiKeyCardano)
		mustOK(t, "cardano key on the same challenge", code, body)
	})
}

// One cold key imported by two scopes into two empty slots before either has
// a profile ends with one profile: the second scope's profile is refused.
func TestMultiSameColdKeyTwoScopesOneProfile(t *testing.T) {
	t.Parallel()

	chip, _ := seedMulti(t)
	h := multiImage(t, chip, true).Handler()
	counter := uint64(1)

	code, body := postAs(
		t,
		h,
		RouteProvisionCold,
		coldReq(0x20e50014, 0x77),
		multiKeyTestnet,
	)
	mustOK(t, "testnet import", code, body)

	code, body = postAs(
		t,
		h,
		RouteProvisionCold,
		coldReq(0x20e5001d, 0x77),
		multiKeyPrime,
	)
	mustOK(t, "prime import of the same key into another slot", code, body)

	code, body = postAs(t, h, RouteProvisionProfile, ProvisionRequest{
		Name: "first@preview", Slot: 8, ColdKeyID: 0x20e50014, ChainCounter: &counter,
	}, multiKeyTestnet)
	mustOK(t, "testnet profile", code, body)

	code, body = postAs(t, h, RouteProvisionProfile, ProvisionRequest{
		Name: "second@prime-mainnet", NetworkID: 1, Slot: 9, ColdKeyID: 0x20e5001d, ChainCounter: &counter,
	}, multiKeyPrime)
	refused(t, "prime profile on the same key", code, body, errCrossScope)
}
