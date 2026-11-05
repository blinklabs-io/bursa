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
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/blinklabs-io/bursa/armory/profile"
	"github.com/blinklabs-io/bursa/armory/signlog"
)

const (
	scopeTestnetName = "testnet"
	scopeCardanoName = "cardano-mainnet"
	scopePrimeName   = "prime-mainnet"
)

var (
	multiKeyTestnet = scopeKey(0x91)
	multiKeyCardano = scopeKey(0x92)
	multiKeyPrime   = scopeKey(0x93)
)

// multiImage returns a multi image on chip: a provisioning image when
// provisioning is set, else a signing image.
func multiImage(t *testing.T, chip *fakeChip, provisioning bool) *Service {
	t.Helper()

	s := New(&sync.Mutex{}, t.Logf)
	s.SetScopes(MultiScopes())

	if provisioning {
		s.AllowFirstHostKey()
	}

	if err := s.SetChip(chip); err != nil {
		t.Fatal(err)
	}

	return s
}

func refused(t *testing.T, what string, code int, body []byte, want error) {
	t.Helper()

	if code == http.StatusOK || !strings.Contains(string(body), want.Error()) {
		t.Fatalf("%s: got %d %q, want a refusal %q", what, code, body, want)
	}
}

func firstKey(t *testing.T, h http.Handler, key ed25519.PrivateKey, scope string) (int, []byte) {
	t.Helper()

	return rawPost(h, RouteProvisionHostKey, jsonOf(t, HostKeyRequest{PublicKey: hostPub(key), Scope: scope}))
}

// seedHostKeys gives a device with no host key the key of each scope: the
// cardano-mainnet key unsigned, then the others added by it.
func seedHostKeys(t *testing.T, h http.Handler) {
	t.Helper()

	code, body := firstKey(t, h, multiKeyCardano, scopeCardanoName)
	mustOK(t, "first key "+scopeCardanoName, code, body)

	for _, c := range []struct {
		scope string
		key   ed25519.PrivateKey
	}{{scopeTestnetName, multiKeyTestnet}, {scopePrimeName, multiKeyPrime}} {
		code, body = postAs(t, h, RouteProvisionHostKey, HostKeyRequest{PublicKey: hostPub(c.key), Scope: c.scope}, multiKeyCardano)
		mustOK(t, "first key "+c.scope, code, body)
	}
}

// A provisioning image takes one unsigned host key, on a device that holds
// none; a key of a mainnet scope then adds the first key of every other
// scope, and a scope with a key takes no other scope's add.
func TestMultiFirstHostKeyPerScope(t *testing.T) {
	t.Parallel()

	chip := newFakeChip()
	h := multiImage(t, chip, true).Handler()

	code, body := firstKey(t, h, multiKeyCardano, scopeCardanoName)
	mustOK(t, "first cardano key", code, body)

	// the answer lists the keys of the scope only
	var resp HostKeyResponse
	if err := json.Unmarshal(body, &resp); err != nil || len(resp.HostKeys) != 1 || !bytes.Equal(resp.HostKeys[0], hostPub(multiKeyCardano)) {
		t.Fatalf("first cardano key answer %s (%v)", body, err)
	}

	// the device holds a key: no other scope's first key goes in unsigned
	for _, sc := range []string{scopeCardanoName, scopePrimeName, scopeTestnetName} {
		code, body = firstKey(t, h, scopeKey(0xa0), sc)
		refused(t, "unsigned "+sc+" key on a device with a key", code, body, errFirstKeyHeld)
	}

	for _, c := range []struct {
		scope string
		key   ed25519.PrivateKey
	}{
		{scopePrimeName, multiKeyPrime},
		{scopeTestnetName, multiKeyTestnet},
	} {
		code, body = postAs(t, h, RouteProvisionHostKey, HostKeyRequest{PublicKey: hostPub(c.key), Scope: c.scope}, multiKeyCardano)
		mustOK(t, "cardano key adds the first "+c.scope+" key", code, body)

		// the answer lists the keys the mainnet key sees, the new one included
		if err := json.Unmarshal(body, &resp); err != nil || !slices.ContainsFunc(resp.HostKeys, func(k []byte) bool { return bytes.Equal(k, hostPub(c.key)) }) {
			t.Fatalf("first %s key answer %s (%v)", c.scope, body, err)
		}
	}

	// every scope has a key now
	code, body = postAs(t, h, RouteProvisionHostKey, HostKeyRequest{PublicKey: hostPub(scopeKey(0xa1)), Scope: scopePrimeName}, multiKeyCardano)
	refused(t, "cardano key adds a second prime key", code, body, errAddScopeMismatch)
}

// A testnet key does not act device-wide on an image that serves mainnet
// scopes, so it adds no mainnet scope's first key.
func TestMultiTestnetKeyAddsNoFirstMainnetKey(t *testing.T) {
	t.Parallel()

	chip := newFakeChip()
	h := multiImage(t, chip, true).Handler()

	code, body := firstKey(t, h, multiKeyTestnet, scopeTestnetName)
	mustOK(t, "first testnet key", code, body)

	code, body = postAs(t, h, RouteProvisionHostKey, HostKeyRequest{PublicKey: hostPub(multiKeyPrime), Scope: scopePrimeName}, multiKeyTestnet)
	refused(t, "testnet key adds the first prime key", code, body, errAddScopeMismatch)

	code, body = firstKey(t, h, multiKeyPrime, scopePrimeName)
	refused(t, "unsigned prime key beside a testnet key", code, body, errFirstKeyHeld)

	// revoking its own last key empties the device, which takes an unsigned key again
	code, body = postAs(t, h, RouteProvisionHostRevoke, HostKeyRequest{PublicKey: hostPub(multiKeyTestnet)}, multiKeyTestnet)
	mustOK(t, "testnet key revokes itself", code, body)

	code, body = firstKey(t, h, multiKeyPrime, scopePrimeName)
	mustOK(t, "unsigned prime key on an emptied device", code, body)
}

func TestMultiFirstHostKeyRefusals(t *testing.T) {
	t.Parallel()

	for name, c := range map[string]struct {
		provisioning bool
		scope        string
		want         error
	}{
		"signing image":     {false, scopePrimeName, errHostAuthMissing},
		"unnamed scope":     {true, "", errScopeNeeded},
		"scope not in set":  {true, "other-mainnet", errFirstKey},
		"bare mainnet":      {true, "mainnet", errFirstKey},
		"cardano not prime": {true, "cardano", errFirstKey},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			chip := newFakeChip()
			h := multiImage(t, chip, c.provisioning).Handler()

			code, body := firstKey(t, h, multiKeyPrime, c.scope)
			refused(t, name, code, body, c.want)

			if _, ok := chip.bins[hostKeysID]; ok {
				t.Fatal("a refused request stored a host key")
			}
		})
	}
}

// A single-scope image is not a multi image: its unsigned first key and the
// absent scope field work as before, and a scope it does not serve is refused.
func TestSingleImageHostKeyScopeField(t *testing.T) {
	t.Parallel()

	chip := newFakeChip()
	s := imageOn(t, chip, 1, "prime-mainnet")
	h := s.Handler()

	code, body := firstKey(t, h, multiKeyPrime, scopeCardanoName)
	if code == http.StatusOK {
		t.Fatalf("prime image took a cardano-mainnet key: %s", body)
	}

	if code, body = firstKey(t, h, multiKeyPrime, scopePrimeName); code != http.StatusOK {
		t.Fatalf("prime image refused its own scope: %d %s", code, body)
	}
}

type multiProfile struct {
	name  string
	scope string
	net   uint8
	slot  uint8
	cold  uint32
	seed  byte
	key   ed25519.PrivateKey
}

var multiProfiles = []multiProfile{
	{"otg@preview", scopeTestnetName, 0, 0, testColdID + 1, 0x01, multiKeyTestnet},
	{"pool@cardano-mainnet", scopeCardanoName, 1, 1, 0x20e50018, 0x02, multiKeyCardano},
	{"pool@prime-mainnet", scopePrimeName, 1, 2, 0x20e5001c, 0x03, multiKeyPrime},
}

func coldReq(slot uint32, seed byte) ColdRequest {
	return ColdRequest{ColdKeyID: slot, SigningKey: secretHex(append([]byte{0x58, 0x20}, bytes.Repeat([]byte{seed}, 32)...))}
}

func mustOK(t *testing.T, what string, code int, body []byte) {
	t.Helper()

	if code != http.StatusOK {
		t.Fatalf("%s: %d %s", what, code, body)
	}
}

// seedMulti provisions a chip through a multi provisioning image: a first
// host key per scope, the device identity and one profile per scope, each
// with its own cold key. It returns the chip and a signing image on it.
func seedMulti(t *testing.T) (*fakeChip, *Service) {
	t.Helper()

	chip := newFakeChip()
	h := multiImage(t, chip, true).Handler()

	seedHostKeys(t, h)

	code, body := postAs(t, h, RouteProvisionIdentity, IdentityRequest{}, multiKeyCardano)
	mustOK(t, "identity", code, body)

	counter := uint64(3)

	for _, p := range multiProfiles {
		code, body = postAs(t, h, RouteProvisionCold, coldReq(p.cold, p.seed), p.key)
		mustOK(t, "cold "+p.name, code, body)

		code, body = postAs(t, h, RouteProvisionProfile, ProvisionRequest{
			Name: p.name, NetworkID: p.net, Slot: p.slot, ColdKeyID: p.cold, ChainCounter: &counter,
		}, p.key)
		mustOK(t, "profile "+p.name, code, body)
	}

	return chip, multiImage(t, chip, false)
}

// opcertFor is an opcert-next request for p, authenticated by key.
func opcertFor(t *testing.T, s *Service, chip *fakeChip, p multiProfile, key ed25519.PrivateKey, n byte) SignResponse {
	t.Helper()

	cold, _ := chip.PublicKeyEd25519(p.cold)
	req := SignRequest{
		Version: Protocol, Purpose: "opcert-next", KeyHash: hashHex(cold), Role: "pool",
		Nonce: nonce(n), Payload: opCertPayload(bytes.Repeat([]byte{0x4b}, 32), 3, 1100), Profile: p.name,
	}

	return postSign(t, s, authenticate(req, key, challenge(t, s)))
}

// Signing needs a host key whose scope equals the profile's scope: no other
// pairing of the three keys and three profiles signs.
func TestMultiSigningNeedsKeyOfProfileScope(t *testing.T) {
	t.Parallel()

	chip, s := seedMulti(t)
	n := byte(0)

	for _, p := range multiProfiles {
		for _, k := range multiProfiles {
			n++

			resp := opcertFor(t, s, chip, p, k.key, n)

			if p.scope == k.scope {
				if resp.Error != "" || len(resp.Signature) == 0 {
					t.Errorf("%s key refused for %s: %q", k.scope, p.name, resp.Error)
				}

				continue
			}

			if resp.Error != errScopeMismatch.Error() || len(resp.Signature) != 0 {
				t.Errorf("%s key signing for %s: error %q, signature %x", k.scope, p.name, resp.Error, resp.Signature)
			}
		}
	}
}

// A scope-mismatched signing request is refused before the nonce is used or
// the signing log is touched, so the right key can still use the nonce.
func TestMultiSigningScopeRefusalKeepsNonce(t *testing.T) {
	t.Parallel()

	chip, s := seedMulti(t)
	prime := multiProfiles[2]

	if resp := opcertFor(t, s, chip, prime, multiKeyTestnet, 7); resp.Error != errScopeMismatch.Error() {
		t.Fatalf("testnet key for prime: %q", resp.Error)
	}

	if resp := opcertFor(t, s, chip, prime, multiKeyPrime, 7); resp.Error != "" {
		t.Fatalf("nonce burned by a refused request: %q", resp.Error)
	}
}

// A profile that is unknown or outside the set is refused as before, and a
// key of any scope signs nothing for it.
func TestMultiSigningUnknownProfile(t *testing.T) {
	t.Parallel()

	chip, s := seedMulti(t)
	ghost := multiProfile{name: "pool@other-mainnet", cold: testColdID}

	resp := opcertFor(t, s, chip, ghost, multiKeyCardano, 9)
	if resp.Error == "" || len(resp.Signature) != 0 {
		t.Fatalf("unknown profile signed: %+v", resp)
	}
}

func profileRequest(t *testing.T, route string, p multiProfile) any {
	t.Helper()

	switch route {
	case RouteProvisionFloor:
		return FloorRequest{Profile: p.name, ChainCounter: 3}
	case RouteProvisionReward:
		return RewardRequest{Profile: p.name, RewardAccount: "e" + string(rune('0'+p.net)) + strings.Repeat("ee", 28)}
	case RouteProvisionPins:
		r := setPinsReq()
		r.Profile = p.name

		return r
	case RouteWipeProfile:
		return WipeProfileRequest{Profile: p.name}
	}

	t.Fatalf("no profile request for %s", route)

	return nil
}

// Every route that targets a profile refuses a key of another scope, and
// accepts the key of the profile's scope.
func TestMultiProfileRoutesNeedKeyOfProfileScope(t *testing.T) {
	t.Parallel()

	for _, route := range []string{RouteProvisionFloor, RouteProvisionReward, RouteProvisionPins} {
		for _, p := range multiProfiles {
			for _, k := range multiProfiles {
				t.Run(route+"/"+p.scope+"/by-"+k.scope, func(t *testing.T) {
					t.Parallel()

					_, s := seedMulti(t)
					code, body := postAs(t, s.Handler(), route, profileRequest(t, route, p), k.key)

					if p.scope == k.scope {
						mustOK(t, "same scope", code, body)
						return
					}

					refused(t, "other scope", code, body, errScopeMismatch)
				})
			}
		}
	}
}

// Removing a profile needs a key of the profile's scope, or a mainnet key for
// a testnet profile.
func TestMultiWipeProfileNeedsKeyOfProfileScope(t *testing.T) {
	t.Parallel()

	for _, p := range multiProfiles {
		for _, k := range multiProfiles {
			t.Run(p.scope+"/by-"+k.scope, func(t *testing.T) {
				t.Parallel()

				_, s := seedMulti(t)
				h := s.WipeHandler()

				// the wipe confirms the device identity
				var id IdentityResponse

				code, body := postAs(t, s.Handler(), RouteProvisionIdentity, IdentityRequest{}, multiKeyCardano)
				mustOK(t, "identity", code, body)

				if err := json.Unmarshal(body, &id); err != nil {
					t.Fatal(err)
				}

				req := WipeProfileRequest{Profile: p.name, IdentityPublicKey: hexOf(id.PublicKey)}
				code, body = postAs(t, h, RouteWipeProfile, req, k.key)

				// a mainnet key also removes a testnet profile
				if p.scope == k.scope || (p.net == 0 && k.net == 1) {
					mustOK(t, "same scope, or testnet by mainnet", code, body)
					return
				}

				refused(t, "other scope", code, body, errScopeMismatch)
			})
		}
	}
}

// Provisioning a profile needs a key of the profile's scope.
func TestMultiProvisionProfileNeedsKeyOfProfileScope(t *testing.T) {
	t.Parallel()

	_, s := seedMulti(t)
	h := s.Handler()

	counter := uint64(1)

	for _, c := range []struct {
		name string
		net  uint8
		key  ed25519.PrivateKey
	}{
		{"new@prime-mainnet", 1, multiKeyTestnet},
		{"new@prime-mainnet", 1, multiKeyCardano},
		{"new@cardano-mainnet", 1, multiKeyPrime},
		{"new@preview", 0, multiKeyPrime},
		{"new@preview", 0, multiKeyCardano},
	} {
		// the cold key is imported by the key that also provisions, in the
		// scope of that key, so the scope check is the one that refuses
		req := ProvisionRequest{Name: c.name, NetworkID: c.net, Slot: 9, ColdKeyID: testColdID + 9, ChainCounter: &counter}
		code, body := postAs(t, h, RouteProvisionProfile, req, c.key)
		refused(t, c.name, code, body, errScopeMismatch)
	}
}

// A testnet profile may not take the name of a mainnet scope's profile: the
// name would be refused to that scope, and a host picking its key by the name
// would pick the mainnet one.
func TestMultiTestnetProfileRefusesMainnetName(t *testing.T) {
	t.Parallel()

	_, s := seedMulti(t)
	h := s.Handler()
	counter := uint64(1)

	code, body := postAs(t, h, RouteProvisionCold, coldReq(0x20e50014, 0x46), multiKeyTestnet)
	mustOK(t, "testnet cold key", code, body)

	for _, name := range []string{"squat@cardano-mainnet", "squat@prime-mainnet"} {
		code, body = postAs(t, h, RouteProvisionProfile, ProvisionRequest{
			Name: name, Slot: 9, ColdKeyID: 0x20e50014, ChainCounter: &counter,
		}, multiKeyTestnet)
		refused(t, name, code, body, errMainnetName)
	}

	code, body = postAs(t, h, RouteProvisionProfile, ProvisionRequest{
		Name: "fine@preview", Slot: 9, ColdKeyID: 0x20e50014, ChainCounter: &counter,
	}, multiKeyTestnet)
	mustOK(t, "testnet profile with a testnet name", code, body)
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

// Device-wide requests need a key of a mainnet scope while the image serves
// one: a testnet key is refused, either mainnet key is accepted.
func TestMultiDeviceWideNeedsMainnetKey(t *testing.T) {
	t.Parallel()

	for _, c := range []struct {
		name string
		do   func(t *testing.T, s *Service, id string, key ed25519.PrivateKey) (int, []byte)
	}{
		{"identity", func(t *testing.T, s *Service, _ string, k ed25519.PrivateKey) (int, []byte) {
			return postAs(t, s.Handler(), RouteProvisionIdentity, IdentityRequest{}, k)
		}},
		{"wipe signlog", func(t *testing.T, s *Service, id string, k ed25519.PrivateKey) (int, []byte) {
			return postAs(t, s.WipeHandler(), RouteWipeSignLog, WipeSignLogRequest{IdentityPublicKey: id}, k)
		}},
		{"revoke another scope's key", func(t *testing.T, s *Service, _ string, k ed25519.PrivateKey) (int, []byte) {
			// cardano keeps a key, so only the scope rule applies
			code, body := postAs(t, s.Handler(), RouteProvisionHostKey, HostKeyRequest{PublicKey: hostPub(scopeKey(0xb5)), Scope: scopeCardanoName}, multiKeyCardano)
			mustOK(t, "add a second cardano key", code, body)

			return postAs(t, s.Handler(), RouteProvisionHostRevoke, HostKeyRequest{PublicKey: hostPub(multiKeyCardano), Scope: scopeCardanoName}, k)
		}},
	} {
		for _, k := range multiProfiles {
			t.Run(c.name+"/by-"+k.scope, func(t *testing.T) {
				t.Parallel()

				chip, s := seedMulti(t)
				pub, _ := chip.PublicKeyEd25519(profile.IdentityKeyID)
				code, body := c.do(t, s, hexOf(pub), k.key)

				if k.scope != scopeTestnetName {
					mustOK(t, "mainnet key", code, body)
					return
				}

				refused(t, "testnet key", code, body, errDeviceWide)
			})
		}
	}
}

// Listing: a testnet key sees only the testnet keys, a mainnet key all.
func TestMultiHostKeyListing(t *testing.T) {
	t.Parallel()

	_, s := seedMulti(t)

	for _, c := range []struct {
		key   ed25519.PrivateKey
		scope string
		want  int
	}{
		{multiKeyTestnet, scopeTestnetName, 1},
		{multiKeyCardano, scopeCardanoName, 3},
		{multiKeyPrime, scopePrimeName, 3},
	} {
		// re-adding the key is a no-op that answers with the list
		code, body := postAs(t, s.Handler(), RouteProvisionHostKey, HostKeyRequest{PublicKey: hostPub(c.key), Scope: c.scope}, c.key)
		mustOK(t, c.scope, code, body)

		var resp HostKeyResponse
		if err := json.Unmarshal(body, &resp); err != nil || len(resp.HostKeys) != c.want {
			t.Errorf("%s key lists %d keys, want %d (%v)", c.scope, len(resp.HostKeys), c.want, err)
		}
	}
}

// A signed add names the scope, and the signing key is of that scope.
func TestMultiSignedHostKeyAddNamesSigningScope(t *testing.T) {
	t.Parallel()

	_, s := seedMulti(t)
	h := s.Handler()
	extra := scopeKey(0xb1)

	for name, c := range map[string]struct {
		req  HostKeyRequest
		key  ed25519.PrivateKey
		want error
	}{
		"testnet key adds prime key": {HostKeyRequest{PublicKey: hostPub(extra), Scope: scopePrimeName}, multiKeyTestnet, errAddScopeMismatch},
		"prime key adds cardano key": {HostKeyRequest{PublicKey: hostPub(extra), Scope: scopeCardanoName}, multiKeyPrime, errAddScopeMismatch},
		"unnamed scope":              {HostKeyRequest{PublicKey: hostPub(extra)}, multiKeyPrime, errScopeNeeded},
		"existing key, other scope":  {HostKeyRequest{PublicKey: hostPub(multiKeyCardano), Scope: scopePrimeName}, multiKeyPrime, errKeyOtherScope},
	} {
		code, body := postAs(t, h, RouteProvisionHostKey, c.req, c.key)
		refused(t, name, code, body, c.want)
	}

	code, body := postAs(t, h, RouteProvisionHostKey, HostKeyRequest{PublicKey: hostPub(extra), Scope: scopePrimeName}, multiKeyPrime)
	mustOK(t, "prime key adds a second prime key", code, body)
}

// The scope is part of what the host key signs: a signed add for one scope
// is not valid for another.
func TestMultiHostKeyScopeIsSigned(t *testing.T) {
	t.Parallel()

	_, s := seedMulti(t)
	h := s.Handler()

	body := jsonOf(t, HostKeyRequest{PublicKey: hostPub(scopeKey(0xb2)), Scope: scopePrimeName})
	other := jsonOf(t, HostKeyRequest{PublicKey: hostPub(scopeKey(0xb2)), Scope: scopeCardanoName})

	a, err := canonicalRequest(&HostKeyRequest{PublicKey: hostPub(scopeKey(0xb2)), Scope: scopePrimeName})
	if err != nil {
		t.Fatal(err)
	}

	b, _ := canonicalRequest(&HostKeyRequest{PublicKey: hostPub(scopeKey(0xb2)), Scope: scopeCardanoName})
	if bytes.Equal(a, b) {
		t.Fatal("the canonical request does not cover the scope")
	}

	_, ch := rawPost(h, "/v1/challenge", []byte("{}"))

	var c ChallengeResponse
	if err := json.Unmarshal(ch, &c); err != nil {
		t.Fatal(err)
	}

	signed, err := SignAdminRequest(RouteProvisionHostKey, body, multiKeyPrime, c.Challenge)
	if err != nil {
		t.Fatal(err)
	}

	// the signature, challenge and key of the prime request, carrying the
	// cardano scope: a cardano key could never have signed this
	var env map[string]json.RawMessage
	if err = json.Unmarshal(signed, &env); err != nil {
		t.Fatal(err)
	}

	var swapped map[string]json.RawMessage
	_ = json.Unmarshal(other, &swapped)
	env["scope"] = swapped["scope"]

	forged, _ := json.Marshal(env)
	code, resp := rawPost(h, RouteProvisionHostKey, forged)

	if code == http.StatusOK || !strings.Contains(string(resp), "host signature does not verify") {
		t.Fatalf("scope swapped under a valid signature: %d %s", code, resp)
	}
}

// A key revokes keys of its own scope; a testnet key revokes none of another
// scope's, a mainnet key revokes any that is not the scope's last.
func TestMultiRevoke(t *testing.T) {
	t.Parallel()

	_, s := seedMulti(t)
	h := s.Handler()

	// a second prime key, revoked by the first
	second := scopeKey(0xb3)
	code, body := postAs(t, h, RouteProvisionHostKey, HostKeyRequest{PublicKey: hostPub(second), Scope: scopePrimeName}, multiKeyPrime)
	mustOK(t, "add", code, body)

	code, body = postAs(t, h, RouteProvisionHostRevoke, HostKeyRequest{PublicKey: hostPub(multiKeyPrime), Scope: scopePrimeName}, multiKeyTestnet)
	refused(t, "testnet key revokes prime key", code, body, errDeviceWide)

	code, body = postAs(t, h, RouteProvisionHostRevoke, HostKeyRequest{PublicKey: hostPub(second), Scope: scopePrimeName}, multiKeyPrime)
	mustOK(t, "prime key revokes a prime key", code, body)

	code, body = postAs(t, h, RouteProvisionHostKey, HostKeyRequest{PublicKey: hostPub(scopeKey(0xb6)), Scope: scopeTestnetName}, multiKeyTestnet)
	mustOK(t, "add a second testnet key", code, body)

	code, body = postAs(t, h, RouteProvisionHostRevoke, HostKeyRequest{PublicKey: hostPub(multiKeyTestnet), Scope: scopeTestnetName}, multiKeyCardano)
	mustOK(t, "mainnet key revokes a testnet key", code, body)
}

// A cold or owner key that already belongs to a profile of another scope is
// refused; the same key under a second slot of one scope stays allowed, as
// the live preview and musashi profiles share one testnet cold key.
func TestMultiColdKeyNotSharedAcrossScopes(t *testing.T) {
	t.Parallel()

	_, s := seedMulti(t)
	h := s.Handler()

	testnet, cardano, prime := multiProfiles[0], multiProfiles[1], multiProfiles[2]

	// the testnet profile's cold key, imported again for a mainnet scope
	for name, c := range map[string]struct {
		slot uint32
		seed byte
		key  ed25519.PrivateKey
	}{
		"prime key, new slot":            {0x20e5001d, testnet.seed, multiKeyPrime},
		"cardano key, new slot":          {0x20e50019, testnet.seed, multiKeyCardano},
		"testnet key, cardano's key":     {0x20e50014, cardano.seed, multiKeyTestnet},
		"cardano key, prime profile key": {0x20e50019, prime.seed, multiKeyCardano},
	} {
		code, body := postAs(t, h, RouteProvisionCold, coldReq(c.slot, c.seed), c.key)
		refused(t, name, code, body, errCrossScope)
	}

	// the testnet profile's own slot belongs to the testnet scope
	code, body := postAs(t, h, RouteProvisionCold, coldReq(testnet.cold, testnet.seed), multiKeyPrime)
	refused(t, "prime key, slot of testnet", code, body, errColdOwner)

	// the same testnet key twice, under two slots, is one scope
	code, body = postAs(t, h, RouteProvisionCold, coldReq(0x20e50014, testnet.seed), multiKeyTestnet)
	mustOK(t, "same-scope duplicate cold key", code, body)

	counter := uint64(1)

	// a profile on that second slot is a same-scope duplicate as well
	code, body = postAs(t, h, RouteProvisionProfile, ProvisionRequest{
		Name: "musashi@preview", Slot: 8, ColdKeyID: 0x20e50014, ChainCounter: &counter,
	}, multiKeyTestnet)
	mustOK(t, "same-scope profile on a duplicate cold key", code, body)
}

func TestMultiProvisionRefusesCrossScopeKeys(t *testing.T) {
	t.Parallel()

	_, s := seedMulti(t)
	h := s.Handler()
	counter := uint64(1)
	testnet, cardano := multiProfiles[0], multiProfiles[1]

	// a prime profile on the testnet profile's cold slot
	code, body := postAs(t, h, RouteProvisionProfile, ProvisionRequest{
		Name: "x@prime-mainnet", NetworkID: 1, Slot: 8, ColdKeyID: testnet.cold, ChainCounter: &counter,
	}, multiKeyPrime)
	refused(t, "cold slot of another scope's profile", code, body, errColdOwner)

	// a prime cold key whose slot holds a key the testnet profile owns too:
	// the key shared by two slots, one of each scope, is refused at the
	// second profile
	code, body = postAs(t, h, RouteProvisionCold, coldReq(0x20e5001d, 0x44), multiKeyPrime)
	mustOK(t, "prime cold key", code, body)

	// an imported owner key equal to another scope's cold key
	own := ProvisionRequest{
		Name: "x@prime-mainnet", NetworkID: 1, Slot: 8, ColdKeyID: 0x20e5001d, ChainCounter: &counter,
		OwnerSigningKey: coldReq(0, cardano.seed).SigningKey,
	}
	code, body = postAs(t, h, RouteProvisionProfile, own, multiKeyPrime)
	refused(t, "owner key equal to a cardano cold key", code, body, errCrossScope)

	// within one scope it is allowed
	same := ProvisionRequest{
		Name: "y@preview", Slot: 9, ColdKeyID: 0x20e50015, ChainCounter: &counter,
		OwnerSigningKey: coldReq(0, testnet.seed).SigningKey,
	}
	code, body = postAs(t, h, RouteProvisionCold, coldReq(0x20e50015, 0x45), multiKeyTestnet)
	mustOK(t, "testnet cold key", code, body)

	code, body = postAs(t, h, RouteProvisionProfile, same, multiKeyTestnet)
	mustOK(t, "owner key equal to a testnet cold key, same scope", code, body)
}

// Flashing the multi image onto a device that ran a testnet image keeps its
// profile and its testnet host key working with nothing rewritten, whether
// the key list is the scoped one or the legacy unscoped one. The mainnet
// scopes then get their first keys from the provisioning image.
func TestMultiKeepsExistingTestnetDevice(t *testing.T) {
	t.Parallel()

	for name, legacy := range map[string]bool{"scoped list": false, "legacy list": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			chip := newFakeChip()
			old := imageOn(t, chip, 0, "")
			counter := uint64(3)

			code, body := rawPost(old.Handler(), RouteProvisionProfile, jsonOf(t, ProvisionRequest{
				Name: "otg@preview", Slot: 0, ColdKeyID: testColdID, ChainCounter: &counter,
			}))
			mustOK(t, "profile on the testnet image", code, body)

			if legacy {
				list := make([]byte, hostKeysLen)
				copy(list, hostPub(multiKeyTestnet))
				chip.bins[hostKeysID] = list
			} else if _, err := old.addHostKey(HostKeyRequest{PublicKey: hostPub(multiKeyTestnet)}); err != nil {
				t.Fatal(err)
			}

			stored := bytes.Clone(chip.bins[hostKeysID])
			preview := multiProfile{name: "otg@preview", cold: testColdID}

			signing := multiImage(t, chip, false)
			if resp := opcertFor(t, signing, chip, preview, multiKeyTestnet, 1); resp.Error != "" {
				t.Fatalf("the testnet key no longer signs otg@preview: %q", resp.Error)
			}

			if !bytes.Equal(chip.bins[hostKeysID], stored) {
				t.Fatal("flashing the multi image rewrote the host key list")
			}

			// the device holds a key, so none goes in unsigned
			prov := multiImage(t, chip, true)
			code, body = firstKey(t, prov.Handler(), scopeKey(0xc0), scopeTestnetName)
			refused(t, "second unsigned testnet key", code, body, errFirstKeyHeld)

			code, body = firstKey(t, prov.Handler(), multiKeyCardano, scopeCardanoName)
			refused(t, "unsigned cardano key beside the testnet key", code, body, errFirstKeyHeld)

			// a testnet add keeps the legacy entry legacy in the rewritten list
			extra := scopeKey(0xc1)
			code, body = postAs(t, prov.Handler(), RouteProvisionHostKey, HostKeyRequest{PublicKey: hostPub(extra), Scope: scopeTestnetName}, multiKeyTestnet)
			mustOK(t, "testnet key adds a testnet key", code, body)

			if legacy && chip.bins[hostKeysID][ed25519.PublicKeySize] != scopeLegacy {
				t.Fatal("the legacy host key was rewritten as scoped")
			}

			// the testnet keys revoke themselves; the emptied device takes the
			// mainnet key unsigned, which adds the other scopes' keys
			for _, k := range []ed25519.PrivateKey{extra, multiKeyTestnet} {
				code, body = postAs(t, prov.Handler(), RouteProvisionHostRevoke, HostKeyRequest{PublicKey: hostPub(k)}, multiKeyTestnet)
				mustOK(t, "testnet key revokes a testnet key", code, body)
			}

			seedHostKeys(t, prov.Handler())

			// each key signs for its own scope only
			signing = multiImage(t, chip, false)
			if resp := opcertFor(t, signing, chip, preview, multiKeyTestnet, 2); resp.Error != "" {
				t.Fatalf("the testnet key stopped signing otg@preview: %q", resp.Error)
			}

			for _, k := range []ed25519.PrivateKey{multiKeyCardano, multiKeyPrime} {
				if resp := opcertFor(t, signing, chip, preview, k, 3); resp.Error != errScopeMismatch.Error() {
					t.Fatalf("a mainnet key signed for otg@preview: %q", resp.Error)
				}
			}

			// and a prime profile is provisioned and signed by the prime key
			code, body = postAs(t, signing.Handler(), RouteProvisionCold, coldReq(0x20e5001d, 0x55), multiKeyPrime)
			mustOK(t, "prime cold key", code, body)

			code, body = postAs(t, signing.Handler(), RouteProvisionProfile, ProvisionRequest{
				Name: "pool@prime-mainnet", NetworkID: 1, Slot: 1, ColdKeyID: 0x20e5001d, ChainCounter: &counter,
			}, multiKeyPrime)
			mustOK(t, "prime profile", code, body)

			signing = multiImage(t, chip, false)
			prime := multiProfile{name: "pool@prime-mainnet", cold: 0x20e5001d}

			if resp := opcertFor(t, signing, chip, prime, multiKeyPrime, 4); resp.Error != "" {
				t.Fatalf("prime key refused for its profile: %q", resp.Error)
			}

			if resp := opcertFor(t, signing, chip, prime, multiKeyTestnet, 5); resp.Error != errScopeMismatch.Error() {
				t.Fatalf("the testnet key signed for the prime profile: %q", resp.Error)
			}
		})
	}
}

// A multi image has no unsigned cold key import, and its signing log read is
// device-wide.
func TestMultiClosesUnsignedImport(t *testing.T) {
	t.Parallel()

	s := multiImage(t, newFakeChip(), true)
	if err := s.UnsignedProvisioningLocked(); err == nil {
		t.Fatal("a multi image takes an unsigned cold key import with no host key registered")
	}
}

func TestMultiSignLogReadIsDeviceWide(t *testing.T) {
	t.Parallel()

	_, s := seedMulti(t)
	installLog(t, s)

	for _, c := range []struct {
		key  ed25519.PrivateKey
		wide bool
	}{{multiKeyTestnet, false}, {multiKeyCardano, true}, {multiKeyPrime, true}} {
		req := SignLogRequest{Nonce: nonce(1), Count: 0}
		req.Challenge = challenge(t, s)
		req.HostKey = hostPub(c.key)
		req.HostSignature = ed25519.Sign(c.key, SignLogBinding(req))

		code, body := post(t, s, "/v1/signlog", req)

		if c.wide {
			mustOK(t, "mainnet key reads the log", code, body)
			continue
		}

		refused(t, "testnet key reads the log", code, body, errDeviceWide)
	}
}

// installLog gives s an empty signing log.
func installLog(t *testing.T, s *Service) {
	t.Helper()

	_, priv, _ := ed25519.GenerateKey(nil)
	m := signlog.NewMemMedium(1 + 4*signlog.RecordBlocks)

	w, err := signlog.Open(m, signlog.NewMemHeadStore(signlog.Head{}), signlog.NewKeySigner(priv))
	if err != nil {
		t.Fatal(err)
	}

	s.SetSigningLog(w, m)
}

func inventoryAs(t *testing.T, s *Service, p multiProfile, key ed25519.PrivateKey) (int, []byte) {
	t.Helper()

	req := InventoryRequest{Nonce: nonce(0x31), Profile: p.name}

	if key != nil {
		req.Challenge = challenge(t, s)
		req.HostKey = hostPub(key)
		req.HostSignature = ed25519.Sign(key, InventoryRequestBinding(req))
	}

	return post(t, s, "/v1/inventory", req)
}

// A multi image answers an inventory request only for a host key of the
// profile's scope.
func TestMultiInventoryNeedsKeyOfProfileScope(t *testing.T) {
	t.Parallel()

	_, s := seedMulti(t)

	for _, p := range multiProfiles {
		code, body := inventoryAs(t, s, p, nil)
		refused(t, p.name+" unsigned", code, body, errHostKeyUnknown)

		for _, k := range multiProfiles {
			code, body = inventoryAs(t, s, p, k.key)

			if p.scope == k.scope {
				mustOK(t, p.name+" by "+k.scope, code, body)
				continue
			}

			refused(t, p.name+" by "+k.scope, code, body, errScopeMismatch)
		}
	}
}

// The binding is fixed: a host built against another version must agree.
func TestInventoryRequestBindingVector(t *testing.T) {
	t.Parallel()

	got := hex.EncodeToString(InventoryRequestBinding(InventoryRequest{
		Nonce: bytes.Repeat([]byte{1}, 32), Profile: "otg@preview", Challenge: bytes.Repeat([]byte{2}, 32),
	}))

	const want = "25a68ec406d4ac5178c76c4362792d33c7bf8330af3efe1028db60d03a11860e"
	if got != want {
		t.Fatalf("binding %s", got)
	}
}

// A mainnet key revokes another scope's keys only while that scope keeps
// one. A scope may still revoke its own last key; a mainnet key then adds
// its first key again, and no unsigned key is taken.
func TestMultiRevokeKeepsOtherScopesLastKey(t *testing.T) {
	t.Parallel()

	chip, _ := seedMulti(t)
	h := multiImage(t, chip, true).Handler()

	code, body := postAs(t, h, RouteProvisionHostRevoke, HostKeyRequest{PublicKey: hostPub(multiKeyPrime), Scope: scopePrimeName}, multiKeyCardano)
	refused(t, "cardano key revokes prime's last key", code, body, errLastKeyOtherScope)

	code, body = firstKey(t, h, scopeKey(0xb4), scopePrimeName)
	refused(t, "unsigned prime key after the refused revoke", code, body, errFirstKeyHeld)

	second := scopeKey(0xb3)
	code, body = postAs(t, h, RouteProvisionHostKey, HostKeyRequest{PublicKey: hostPub(second), Scope: scopePrimeName}, multiKeyPrime)
	mustOK(t, "add a second prime key", code, body)

	code, body = postAs(t, h, RouteProvisionHostRevoke, HostKeyRequest{PublicKey: hostPub(multiKeyPrime), Scope: scopePrimeName}, multiKeyCardano)
	mustOK(t, "cardano key revokes a prime key while prime keeps one", code, body)

	code, body = postAs(t, h, RouteProvisionHostRevoke, HostKeyRequest{PublicKey: hostPub(second), Scope: scopePrimeName}, multiKeyCardano)
	refused(t, "cardano key revokes prime's remaining key", code, body, errLastKeyOtherScope)

	code, body = postAs(t, h, RouteProvisionHostRevoke, HostKeyRequest{PublicKey: hostPub(second), Scope: scopePrimeName}, second)
	mustOK(t, "prime key revokes its own last key", code, body)

	code, body = firstKey(t, h, scopeKey(0xb4), scopePrimeName)
	refused(t, "unsigned prime key after prime revoked its own", code, body, errFirstKeyHeld)

	code, body = postAs(t, h, RouteProvisionHostKey, HostKeyRequest{PublicKey: hostPub(scopeKey(0xb4)), Scope: scopePrimeName}, multiKeyCardano)
	mustOK(t, "cardano key adds prime's first key again", code, body)
}
