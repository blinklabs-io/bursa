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
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/blinklabs-io/bursa/armory/profile"
)

func rawPost(h http.Handler, path string, body []byte) (int, []byte) {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, jsonRequest(path, bytes.NewReader(body)))

	return w.Code, w.Body.Bytes()
}

// postAs sends req to h signed by key, with a challenge h issued.
func postAs(t *testing.T, h http.Handler, path string, req any, key ed25519.PrivateKey) (int, []byte) {
	t.Helper()

	code, b := rawPost(h, "/v1/challenge", []byte("{}"))
	if code != http.StatusOK {
		t.Fatalf("challenge: %d %s", code, b)
	}

	var ch ChallengeResponse
	if err := json.Unmarshal(b, &ch); err != nil {
		t.Fatal(err)
	}

	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	if body, err = SignAdminRequest(path, body, key, ch.Challenge); err != nil {
		t.Fatal(err)
	}

	return rawPost(h, path, body)
}

func jsonOf(t *testing.T, v any) []byte {
	t.Helper()

	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}

	return b
}

// requestFor is a valid request body for each authenticated route against the
// newHostAuthService fixture, for a request whose only fault is missing or
// wrong authentication.
func requestFor(t *testing.T, s *Service, route string) any {
	t.Helper()

	h := s.ProvisioningHandler()

	code, b := postAs(t, h, RouteProvisionIdentity, IdentityRequest{}, testHostKey)
	if code != http.StatusOK {
		t.Fatalf("identity: %d %s", code, b)
	}

	var ident IdentityResponse
	if err := json.Unmarshal(b, &ident); err != nil {
		t.Fatal(err)
	}

	id := hex.EncodeToString(ident.PublicKey)
	chain := uint64(1)
	cold := ColdRequest{ColdKeyID: testColdID + 1, SigningKey: "5820" + strings.Repeat("11", 32)}

	switch route {
	case RouteProvisionProfile:
		if code, b := postAs(t, h, RouteProvisionCold, cold, testHostKey); code != http.StatusOK {
			t.Fatalf("cold key: %d %s", code, b)
		}

		return ProvisionRequest{Name: "other@preview", Slot: 1, ColdKeyID: testColdID + 1, ChainCounter: &chain}
	case RouteProvisionFloor:
		return FloorRequest{Profile: "otg@preview", ChainCounter: 0}
	case RouteProvisionReward:
		return RewardRequest{Profile: "otg@preview", RewardAccount: strings.Repeat("e0", 29)}
	case RouteProvisionCold:
		return cold
	case RouteProvisionIdentity:
		return IdentityRequest{}
	case RouteProvisionHostKey:
		return HostKeyRequest{PublicKey: hostPub(scopeKey(0x70))}
	case RouteProvisionHostRevoke:
		// a registered key, so an unsigned request is refused for its
		// missing signature and not for an unknown key
		return HostKeyRequest{PublicKey: hostPub(testHostKey)}
	case RouteWipeProfile:
		return WipeProfileRequest{IdentityPublicKey: id, Profile: "otg@preview"}
	case RouteWipeSignLog:
		return WipeSignLogRequest{IdentityPublicKey: id}
	}

	t.Fatalf("no request for %s", route)

	return nil
}

// chipState is a copy of every object on c and its contents, to tell a
// replaced or rewritten object from an untouched one.
func chipState(c *fakeChip) map[uint32]string {
	state := map[uint32]string{}
	for id, k := range c.keys {
		state[id] = "key:" + hex.EncodeToString(k)
	}

	for id, b := range c.bins {
		state[id] = "bin:" + hex.EncodeToString(b)
	}

	return state
}

func handlerFor(s *Service, route string) http.Handler {
	if strings.HasPrefix(route, "/wipe/") {
		return s.WipeHandler()
	}

	return s.ProvisioningHandler()
}

// Once a host key is registered every provisioning and wipe route refuses an
// unsigned request and leaves the chip as it was.
func TestAdminRoutesRefuseUnsignedWithHostKey(t *testing.T) {
	t.Parallel()

	for route := range adminRequests {
		t.Run(route, func(t *testing.T) {
			t.Parallel()

			s, chip := newHostAuthService(t)
			req := requestFor(t, s, route)
			before := chipState(chip)

			code, body := rawPost(handlerFor(s, route), route, jsonOf(t, req))
			if code == http.StatusOK {
				t.Fatalf("unsigned request accepted: %s", body)
			}

			if !strings.Contains(string(body), errHostKeyUnknown.Error()) {
				t.Fatalf("refused for another reason: %s", body)
			}

			if got := chipState(chip); !reflect.DeepEqual(got, before) {
				t.Fatal("chip changed")
			}
		})
	}
}

// A signature from a registered key of the image's scope is accepted by every
// route, and the challenge is burned.
func TestAdminRoutesAcceptSigned(t *testing.T) {
	t.Parallel()

	for route := range adminRequests {
		t.Run(route, func(t *testing.T) {
			t.Parallel()

			s, _ := newHostAuthService(t)
			req := requestFor(t, s, route)
			h := handlerFor(s, route)

			code, body := postAs(t, h, route, req, testHostKey)
			if code != http.StatusOK {
				t.Fatalf("signed request refused: %d %s", code, body)
			}
		})
	}
}

// A signature covers the route and the request: it cannot be moved to another
// route, another body or a used challenge.
func TestAdminSignatureBinding(t *testing.T) {
	t.Parallel()

	s, _ := newHostAuthService(t)
	h := s.ProvisioningHandler()

	chain := uint64(5)
	signed := func(route string, req any) ([]byte, []byte) {
		code, b := rawPost(h, "/v1/challenge", []byte("{}"))
		if code != http.StatusOK {
			t.Fatalf("challenge: %d", code)
		}

		var ch ChallengeResponse
		if err := json.Unmarshal(b, &ch); err != nil {
			t.Fatal(err)
		}

		body, err := SignAdminRequest(route, jsonOf(t, req), testHostKey, ch.Challenge)
		if err != nil {
			t.Fatal(err)
		}

		return body, ch.Challenge
	}

	floor := FloorRequest{Profile: "otg@preview", ChainCounter: 9}

	// another route: a floor request signed for /provision/reward, in a body
	// the floor decoder takes, so the route is the only difference
	code, b := rawPost(h, "/v1/challenge", []byte("{}"))
	if code != http.StatusOK {
		t.Fatalf("challenge: %d", code)
	}

	var ch ChallengeResponse
	if err := json.Unmarshal(b, &ch); err != nil {
		t.Fatal(err)
	}

	canonical, err := canonicalRequest(&FloorRequest{Profile: "otg@preview"})
	if err != nil {
		t.Fatal(err)
	}

	cross := FloorRequest{Profile: "otg@preview", HostAuth: HostAuth{
		Challenge:     ch.Challenge,
		HostKey:       testHostKey.Public().(ed25519.PublicKey),
		HostSignature: ed25519.Sign(testHostKey, AdminBinding(RouteProvisionReward, canonical, ch.Challenge)),
	}}

	if code, b := rawPost(h, RouteProvisionFloor, jsonOf(t, cross)); !strings.Contains(string(b), "host signature does not verify") {
		t.Errorf("signature for /provision/reward on /provision/floor: %d %s", code, b)
	}

	// another body
	body, _ := signed(RouteProvisionFloor, floor)

	var tampered FloorRequest
	if err := json.Unmarshal(body, &tampered); err != nil {
		t.Fatal(err)
	}

	tampered.ChainCounter = chain

	if code, _ := rawPost(h, RouteProvisionFloor, jsonOf(t, tampered)); code == http.StatusOK {
		t.Error("signature accepted for a changed request")
	}

	// a used challenge
	body, _ = signed(RouteProvisionFloor, floor)
	if code, b := rawPost(h, RouteProvisionFloor, body); code != http.StatusOK {
		t.Fatalf("signed request refused: %d %s", code, b)
	}

	if code, _ := rawPost(h, RouteProvisionFloor, body); code == http.StatusOK {
		t.Error("replayed request accepted")
	}

	// a key that is not registered
	if code, _ := postAs(t, h, RouteProvisionFloor, floor, scopeKey(0x71)); code == http.StatusOK {
		t.Error("unregistered key accepted")
	}
}

// The first host key is added unsigned, and the device then refuses unsigned
// requests, including a second key.
func TestFirstHostKeyUnsigned(t *testing.T) {
	t.Parallel()

	s, chip := newTestService(t)
	h := s.ProvisioningHandler()
	provisionTestProfile(t, s)

	// provisioning stays usable unsigned while no host key exists
	chain := uint64(2)
	if code, body := rawPost(h, RouteProvisionFloor, jsonOf(t, FloorRequest{Profile: "otg@preview", ChainCounter: chain})); code != http.StatusOK {
		t.Fatalf("floor with no host key: %d %s", code, body)
	}

	if code, body := rawPost(h, RouteProvisionHostKey, jsonOf(t, HostKeyRequest{PublicKey: hostPub(testHostKey)})); code != http.StatusOK {
		t.Fatalf("first host key: %d %s", code, body)
	}

	if _, ok := chip.bins[hostKeysID]; !ok {
		t.Fatal("first host key not stored")
	}

	if code, _ := rawPost(h, RouteProvisionHostKey, jsonOf(t, HostKeyRequest{PublicKey: hostPub(scopeKey(0x72))})); code == http.StatusOK {
		t.Fatal("second host key added unsigned")
	}

	if code, body := postAs(t, h, RouteProvisionHostKey, HostKeyRequest{PublicKey: hostPub(scopeKey(0x72))}, testHostKey); code != http.StatusOK {
		t.Fatalf("second host key signed by the first: %d %s", code, body)
	}
}

// A request signed while no host key exists is not checked, so its challenge
// is not burned; registering the first host key must still void that
// challenge, or the request replays once its key is registered.
func TestFirstHostKeyVoidsBootstrapChallenges(t *testing.T) {
	t.Parallel()

	s, _ := newTestService(t)
	h := s.ProvisioningHandler()
	provisionTestProfile(t, s)

	code, b := rawPost(h, "/v1/challenge", []byte("{}"))
	if code != http.StatusOK {
		t.Fatalf("challenge: %d %s", code, b)
	}

	var ch ChallengeResponse
	if err := json.Unmarshal(b, &ch); err != nil {
		t.Fatal(err)
	}

	signed, err := SignAdminRequest(RouteProvisionFloor, jsonOf(t, FloorRequest{Profile: "otg@preview"}), testHostKey, ch.Challenge)
	if err != nil {
		t.Fatal(err)
	}

	if code, body := rawPost(h, RouteProvisionFloor, signed); code != http.StatusOK {
		t.Fatalf("signed floor with no host key: %d %s", code, body)
	}

	if code, body := rawPost(h, RouteProvisionHostKey, jsonOf(t, HostKeyRequest{PublicKey: hostPub(testHostKey)})); code != http.StatusOK {
		t.Fatalf("first host key: %d %s", code, body)
	}

	code, body := rawPost(h, RouteProvisionFloor, signed)
	if code == http.StatusOK || !strings.Contains(string(body), "unknown or used challenge") {
		t.Fatalf("bootstrap request replayed after the first host key: %d %s", code, body)
	}

	if code, body := postAs(t, h, RouteProvisionFloor, FloorRequest{Profile: "otg@preview"}, testHostKey); code != http.StatusOK {
		t.Fatalf("fresh signed floor: %d %s", code, body)
	}
}

// A key registered for another network is not a key of this image's scope:
// it neither authenticates a request nor lets the image's first key in
// unsigned.
func TestAdminRefusesOtherScopeHostKey(t *testing.T) {
	t.Parallel()

	chip := newFakeChip()
	other := scopeKey(0x73)

	mainnet := imageOn(t, chip, 1, "")
	if _, err := mainnet.addHostKey(HostKeyRequest{PublicKey: hostPub(other)}); err != nil {
		t.Fatal(err)
	}

	testnet := imageOn(t, chip, 0, "")
	h := testnet.ProvisioningHandler()
	add := HostKeyRequest{PublicKey: hostPub(scopeKey(0x74))}

	if code, _ := rawPost(h, RouteProvisionHostKey, jsonOf(t, add)); code == http.StatusOK {
		t.Fatal("testnet image added a key unsigned beside a mainnet key")
	}

	if code, body := postAs(t, h, RouteProvisionHostKey, add, other); code == http.StatusOK {
		t.Fatalf("testnet image accepted a mainnet host key: %s", body)
	}

	if len(testnet.hostKeys) != 0 {
		t.Fatal("key registered")
	}
}

// The wipe image serves the challenge endpoint and the provisioning image
// does too.
func TestImagesServeChallenge(t *testing.T) {
	t.Parallel()

	s, _ := newTestService(t)

	for name, h := range map[string]http.Handler{"provisioning": s.ProvisioningHandler(), "wipe": s.WipeHandler()} {
		code, body := rawPost(h, "/v1/challenge", []byte("{}"))
		if code != http.StatusOK {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}
}

// /wipe/device is confirmed by the identity key alone, even with a host key
// registered: it is the way out when every host key is lost. /wipe/profile
// and /wipe/signlog are not.
func TestWipeDeviceUnsignedWithHostKey(t *testing.T) {
	t.Parallel()

	s, chip := newHostAuthService(t)
	h := s.WipeHandler()

	code, b := postAs(t, s.ProvisioningHandler(), RouteProvisionIdentity, IdentityRequest{}, testHostKey)
	if code != http.StatusOK {
		t.Fatalf("identity: %d %s", code, b)
	}

	var ident IdentityResponse
	if err := json.Unmarshal(b, &ident); err != nil {
		t.Fatal(err)
	}

	id := hex.EncodeToString(ident.PublicKey)

	for _, route := range []string{RouteWipeProfile, RouteWipeSignLog} {
		var req any = WipeProfileRequest{IdentityPublicKey: id, Profile: "otg@preview"}
		if route == RouteWipeSignLog {
			req = WipeSignLogRequest{IdentityPublicKey: id}
		}

		if code, body := rawPost(h, route, jsonOf(t, req)); code != http.StatusOK && !strings.Contains(string(body), errHostKeyUnknown.Error()) {
			t.Errorf("%s refused for another reason: %s", route, body)
		} else if code == http.StatusOK {
			t.Errorf("%s accepted unsigned", route)
		}
	}

	if _, ok := chip.bins[profile.SignLogHeadID]; ok {
		t.Fatal("test set up a log head")
	}

	if code, body := rawPost(h, "/wipe/device", jsonOf(t, WipeDeviceRequest{IdentityPublicKey: id})); code != http.StatusOK {
		t.Fatalf("unsigned device wipe: %d %s", code, body)
	}

	if len(objectIDs(chip)) != 0 {
		t.Fatalf("objects left: %v", objectIDs(chip))
	}

	// the device is in the bootstrap state again
	if code, body := rawPost(s.ProvisioningHandler(), RouteProvisionHostKey, jsonOf(t, HostKeyRequest{PublicKey: hostPub(testHostKey)})); code != http.StatusOK {
		t.Fatalf("host key after device wipe: %d %s", code, body)
	}

}

// An unreadable host key list refuses every authenticated route, even though
// it holds no key to check a signature against, and leaves the chip as it was.
func TestAdminRefusesUnreadableHostKeys(t *testing.T) {
	t.Parallel()

	for route := range adminRequests {
		t.Run(route, func(t *testing.T) {
			t.Parallel()

			s, chip := newHostAuthService(t)
			req := requestFor(t, s, route)
			chip.bins[hostKeysID] = []byte("torn")
			before := chipState(chip)

			s2 := New(&sync.Mutex{}, t.Logf)
			if err := s2.SetChip(chip); err != nil {
				t.Fatal(err)
			}

			code, body := postAs(t, handlerFor(s2, route), route, req, testHostKey)
			if code == http.StatusOK {
				t.Fatalf("accepted over an unreadable host key list: %s", body)
			}

			if !strings.Contains(string(body), errHostKeysBad.Error()) {
				t.Fatalf("refused for another reason: %s", body)
			}

			if got := chipState(chip); !reflect.DeepEqual(got, before) {
				t.Fatal("chip changed")
			}
		})
	}
}

// The unsigned cold key import the firmware serves is open only while the
// device is in the bootstrap state, and the refusal names the state.
func TestUnsignedProvisioningLocked(t *testing.T) {
	t.Parallel()

	open := func(s *Service) error {
		s.mu.Lock()
		defer s.mu.Unlock()

		return s.UnsignedProvisioningLocked()
	}

	if err := open(New(&sync.Mutex{}, t.Logf)); !errors.Is(err, errNoChip) {
		t.Fatalf("no chip: %v", err)
	}

	s, chip := newTestService(t)
	if err := open(s); err != nil {
		t.Fatalf("closed with no host key: %v", err)
	}

	registerHostKey(t, s, hostPub(testHostKey))

	if err := open(s); !errors.Is(err, errProvisioningClosed) {
		t.Fatalf("with a host key registered: %v", err)
	}

	// a key of another scope closes it too
	if err := open(imageOn(t, chip, 1, "")); !errors.Is(err, errProvisioningClosed) {
		t.Fatalf("beside a key of another scope: %v", err)
	}

	chip.bins[hostKeysID] = []byte("torn")

	if err := open(imageOn(t, chip, 0, "")); !errors.Is(err, errHostKeysBad) {
		t.Fatalf("over an unreadable host key list: %v", err)
	}
}

// The binding a host key signs is fixed across releases: armory-pool and the
// device image ship separately, so the canonical request JSON and the digest
// over it must not change shape.
func TestAdminBindingVector(t *testing.T) {
	t.Parallel()

	chain := uint64(7)
	req := &ProvisionRequest{
		HostAuth: HostAuth{Challenge: []byte{9}, HostKey: []byte{9}, HostSignature: []byte{9}},
		Name:     "otg@preview", Slot: 1, ColdKeyID: 538247424, ChainCounter: &chain, RewardAccount: "e0",
	}

	canonical, err := canonicalRequest(req)
	if err != nil {
		t.Fatal(err)
	}

	const want = `{"name":"otg@preview","network_id":0,"slot":1,"cold_key_id":538247424,"chain_counter":7,"reward_account":"e0"}`
	if string(canonical) != want {
		t.Fatalf("canonical request = %s", canonical)
	}

	if len(req.HostSignature) != 1 {
		t.Fatal("canonicalRequest did not restore the authentication fields")
	}

	got := hex.EncodeToString(AdminBinding(RouteProvisionProfile, canonical, bytes.Repeat([]byte{3}, 32)))
	if got != adminBindingVector {
		t.Fatalf("AdminBinding = %s", got)
	}
}

// adminBindingVector was computed independently of AdminBinding.
const adminBindingVector = "c73665362e27aa398646a9469c18a09656072edacc0df51b7e2e7f86490dae35"
