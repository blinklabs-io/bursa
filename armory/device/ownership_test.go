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
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/blinklabs-io/bursa/armory/profile"
)

type ownerScope struct {
	name string
	net  uint8
	key  ed25519.PrivateKey
	// profile is a profile name of the scope
	profile string
	sc      Scope
}

var ownerScopes = []ownerScope{
	{scopeTestnetName, 0, multiKeyTestnet, "t@preview", ScopeTestnet},
	{scopeCardanoName, 1, multiKeyCardano, "c@cardano-mainnet", Scope{Network: 1, Chain: "cardano-mainnet"}},
	{scopePrimeName, 1, multiKeyPrime, "p@prime-mainnet", Scope{Network: 1, Chain: "prime-mainnet"}},
}

// ownersRecord builds an ownership record claiming the given objects.
func ownersRecord(t *testing.T, claims map[uint32]Scope) []byte {
	t.Helper()

	b := make([]byte, ownersSize)
	b[0] = ownersVersion

	for id, sc := range claims {
		i, ok := coldKeyIndex(id)
		if !ok {
			t.Fatalf("%#08x is not a cold key object", id)
		}

		e := b[1+i*ownerEntry:]
		tag := tagOf(sc)
		e[0], e[1] = 1, tag.network
		copy(e[2:], tag.chain[:])
	}

	return b
}

// claimOf reads the claim on id from the record on chip.
func claimOf(t *testing.T, chip *fakeChip, id uint32) (Scope, bool) {
	t.Helper()

	b, ok := chip.bins[ownersID]
	if !ok {
		return Scope{}, false
	}

	if len(b) != ownersSize || b[0] != ownersVersion {
		t.Fatalf("ownership record is %d bytes, version %d", len(b), b[0])
	}

	i, ok := coldKeyIndex(id)
	if !ok {
		t.Fatalf("%#08x is not a cold key object", id)
	}

	e := b[1+i*ownerEntry:]
	if e[0] == 0 {
		return Scope{}, false
	}

	for _, o := range ownerScopes {
		tag := tagOf(o.sc)
		if tag.network == e[1] && bytes.Equal(tag.chain[:], e[2:ownerEntry]) {
			return o.sc, true
		}
	}

	t.Fatalf("claim on %#08x names no known scope: % x", id, e[:ownerEntry])

	return Scope{}, false
}

func ownerHandler(t *testing.T, chip *fakeChip) http.Handler {
	t.Helper()

	h := multiImage(t, chip, true).Handler()

	seedHostKeys(t, h)

	return h
}

func provisionOn(t *testing.T, h http.Handler, o ownerScope, slot uint8, cold uint32) (int, []byte) {
	t.Helper()

	counter := uint64(1)

	return postAs(t, h, RouteProvisionProfile, ProvisionRequest{
		Name: o.profile, NetworkID: o.net, Slot: slot, ColdKeyID: cold, ChainCounter: &counter,
	}, o.key)
}

func TestColdKeyObjects(t *testing.T) {
	t.Parallel()

	ids := coldKeyIDs()
	if len(ids) != 32 {
		t.Fatalf("%d cold key objects, want 32", len(ids))
	}

	seen := map[uint32]bool{}

	for i, id := range ids {
		if seen[id] || !isColdKeyID(id) {
			t.Errorf("cold key object %#08x duplicated or not recognised", id)
		}

		seen[id] = true

		if got, ok := coldKeyIndex(id); !ok || got != i {
			t.Errorf("coldKeyIndex(%#08x) = %d %v, want %d", id, got, ok, i)
		}
	}

	for _, id := range []uint32{0x20e5000f, 0x20e50020, 0x20e50023, 0x20e505ff, 0x20e50610} {
		if isColdKeyID(id) {
			t.Errorf("%#08x taken for a cold key object", id)
		}
	}

	if ownersID != 0x20e50023 || ownersSize != 1+32*10 {
		t.Errorf("record %#08x of %d bytes", ownersID, ownersSize)
	}
}

// Any scope imports into any free cold key object, in either block, and the
// import is recorded as that scope's.
func TestColdOwnershipAnyScopeAnyFreeObject(t *testing.T) {
	t.Parallel()

	chip := newFakeChip()
	// the fake chip starts with a key in the first cold key object
	delete(chip.keys, testColdID)

	h := ownerHandler(t, chip)

	for i, id := range coldKeyIDs() {
		o := ownerScopes[i%len(ownerScopes)]
		code, body := postAs(t, h, RouteProvisionCold, coldReq(id, byte(0x80+i)), o.key)
		mustOK(t, fmt.Sprintf("%s import into %#08x", o.name, id), code, body)

		if got, ok := claimOf(t, chip, id); !ok || got != o.sc {
			t.Errorf("claim on %#08x = %v %v, want %s", id, got, ok, o.name)
		}
	}
}

// An object another scope owns refuses import and profile provisioning, for
// every pair of scopes, in both blocks; the owner may import the same key
// again, and not another.
func TestColdOwnershipRefusesOtherScope(t *testing.T) {
	t.Parallel()

	for _, id := range []uint32{0x20e50013, 0x20e50600, 0x20e5060f} {
		for _, owner := range ownerScopes {
			t.Run(fmt.Sprintf("%#08x/%s", id, owner.name), func(t *testing.T) {
				t.Parallel()

				chip := newFakeChip()
				h := ownerHandler(t, chip)

				code, body := postAs(t, h, RouteProvisionCold, coldReq(id, 0x61), owner.key)
				mustOK(t, "owner import", code, body)

				for _, other := range ownerScopes {
					if other.name == owner.name {
						continue
					}

					code, body = postAs(t, h, RouteProvisionCold, coldReq(id, 0x61), other.key)
					refused(t, other.name+" imports the same key", code, body, errColdOwner)

					code, body = postAs(t, h, RouteProvisionCold, coldReq(id, 0x62), other.key)
					refused(t, other.name+" imports another key", code, body, errColdOwner)

					code, body = provisionOn(t, h, other, 3, id)
					refused(t, other.name+" provisions a profile", code, body, errColdOwner)
				}

				code, body = postAs(t, h, RouteProvisionCold, coldReq(id, 0x61), owner.key)
				mustOK(t, "owner re-imports the same key", code, body)

				code, body = postAs(t, h, RouteProvisionCold, coldReq(id, 0x62), owner.key)
				refused(t, "owner imports another key", code, body, errKeyExists)

				code, body = provisionOn(t, h, owner, 3, id)
				mustOK(t, "owner provisions a profile", code, body)
			})
		}
	}
}

// A claim never locks an empty object: another scope's stale claim on an
// object with no key is replaced by the next import.
func TestColdOwnershipStaleClaimOnEmptyObjectIsFree(t *testing.T) {
	t.Parallel()

	chip := newFakeChip()
	chip.bins[ownersID] = ownersRecord(t, map[uint32]Scope{
		0x20e50600: ScopeTestnet,
		0x20e50012: ownerScopes[2].sc,
	})
	h := ownerHandler(t, chip)

	code, body := postAs(t, h, RouteProvisionCold, coldReq(0x20e50600, 0x63), multiKeyCardano)
	mustOK(t, "cardano into an object with a stale testnet claim", code, body)

	if got, ok := claimOf(t, chip, 0x20e50600); !ok || got != ownerScopes[1].sc {
		t.Errorf("claim = %v %v, want cardano", got, ok)
	}

	// the other claim is untouched
	if got, ok := claimOf(t, chip, 0x20e50012); !ok || got != ownerScopes[2].sc {
		t.Errorf("unrelated claim = %v %v, want prime", got, ok)
	}
}

// The claim is written before the key, so a failed import leaves the object
// empty, and an empty object is free to any scope.
func TestColdOwnershipClaimBeforeImport(t *testing.T) {
	t.Parallel()

	chip := newFakeChip()
	h := ownerHandler(t, chip)

	chip.failImport = true

	code, body := postAs(t, h, RouteProvisionCold, coldReq(0x20e50601, 0x64), multiKeyCardano)
	if code == http.StatusOK {
		t.Fatalf("import succeeded on a failing chip: %s", body)
	}

	if got, ok := claimOf(t, chip, 0x20e50601); !ok || got != ownerScopes[1].sc {
		t.Fatalf("claim after the failed import = %v %v, want cardano's, written first", got, ok)
	}

	if _, ok := chip.keys[0x20e50601]; ok {
		t.Fatal("the failed import left a key")
	}

	chip.failImport = false

	code, body = postAs(t, h, RouteProvisionCold, coldReq(0x20e50601, 0x65), multiKeyPrime)
	mustOK(t, "prime into the object a failed cardano import left", code, body)

	if got, _ := claimOf(t, chip, 0x20e50601); got != ownerScopes[2].sc {
		t.Errorf("claim = %v, want prime", got)
	}
}

// A key an older image stored without a claim belongs to the scope of the
// profile on it; with no profile it belongs to nobody and every scope is
// refused.
func TestColdOwnershipLegacyKeys(t *testing.T) {
	t.Parallel()

	for _, owner := range ownerScopes {
		t.Run("profile "+owner.name, func(t *testing.T) {
			t.Parallel()

			chip := newFakeChip()
			chip.keys[0x20e50014] = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x66}, 32))
			storeRecord(t, chip, profile.Profile{
				Name: owner.profile, NetworkID: owner.net, Slot: 7, ColdKeyID: 0x20e50014,
			})
			h := ownerHandler(t, chip)

			for _, other := range ownerScopes {
				code, body := postAs(t, h, RouteProvisionCold, coldReq(0x20e50014, 0x66), other.key)

				if other.name == owner.name {
					mustOK(t, "owner re-imports the legacy key", code, body)
					continue
				}

				refused(t, other.name+" imports", code, body, errColdOwner)

				code, body = provisionOn(t, h, other, 3, 0x20e50014)
				refused(t, other.name+" provisions", code, body, errColdOwner)
			}

			// the owner passes the ownership check; the one profile per cold
			// key rule still applies
			second := owner
			second.profile = "second-" + owner.profile
			code, body := provisionOn(t, h, second, 3, 0x20e50014)
			refused(t, "owner provisions a second profile", code, body, errors.New("cold key already belongs to a profile"))
		})
	}

	t.Run("no profile", func(t *testing.T) {
		t.Parallel()

		chip := newFakeChip()
		chip.keys[0x20e50014] = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x66}, 32))
		chip.keys[0x20e50602] = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x67}, 32))
		h := ownerHandler(t, chip)

		for _, id := range []uint32{0x20e50014, 0x20e50602} {
			for _, o := range ownerScopes {
				code, body := postAs(t, h, RouteProvisionCold, coldReq(id, 0x66), o.key)
				refused(t, fmt.Sprintf("%s imports into the unowned %#08x", o.name, id), code, body, errColdOwner)

				code, body = provisionOn(t, h, o, 3, id)
				refused(t, fmt.Sprintf("%s provisions on the unowned %#08x", o.name, id), code, body, errColdOwner)
			}
		}
	})
}

// A single-network image records its own scope as the owner, and a multi
// image later honors it, and the other way round.
func TestColdOwnershipSingleImageClaims(t *testing.T) {
	t.Parallel()

	chip := newFakeChip()
	testnet := imageOn(t, chip, 0, "")

	code, body := post(t, testnet, "/provision/cold", coldReq(0x20e50600, 0x68))
	mustOK(t, "single testnet import", code, body)

	if got, ok := claimOf(t, chip, 0x20e50600); !ok || got != ScopeTestnet {
		t.Fatalf("single image claim = %v %v, want testnet", got, ok)
	}

	h := ownerHandler(t, chip)

	for _, o := range ownerScopes[1:] {
		code, body = postAs(t, h, RouteProvisionCold, coldReq(0x20e50600, 0x68), o.key)
		refused(t, o.name+" imports into the testnet image's key", code, body, errColdOwner)

		code, body = provisionOn(t, h, o, 3, 0x20e50600)
		refused(t, o.name+" provisions on it", code, body, errColdOwner)
	}

	code, body = provisionOn(t, h, ownerScopes[0], 3, 0x20e50600)
	mustOK(t, "testnet provisions on its key", code, body)

	// a single image refuses a key the record gives to a mainnet scope
	chip = newFakeChip()
	plant(chip, 0x20e50601)
	chip.bins[ownersID] = ownersRecord(t, map[uint32]Scope{0x20e50601: ownerScopes[1].sc})

	testnet = imageOn(t, chip, 0, "")
	code, body = post(t, testnet, "/provision/cold", coldReq(0x20e50601, 0x69))
	refused(t, "testnet image imports cardano's key", code, body, errColdOwner)

	// and refuses a profile on it
	chain := uint64(0)
	code, body = post(t, testnet, "/provision/profile", ProvisionRequest{
		Name: "x@preview", Slot: 1, ColdKeyID: 0x20e50601, ChainCounter: &chain, RewardAccount: testReward,
	})
	refused(t, "testnet image provisions on cardano's key", code, body, errColdOwner)
}

// A device wipe clears the record, and the wipe image lists both cold key
// blocks and the record.
func TestColdOwnershipWipe(t *testing.T) {
	t.Parallel()

	s, chip := newTestService(t)
	id := identityHex(t, s)

	plant(chip, 0x20e50600, 0x20e5060f, 0x20e50010)
	chip.bins[ownersID] = ownersRecord(t, map[uint32]Scope{0x20e50600: ScopeTestnet})

	code, body := wipePost(t, s, "/wipe/objects", struct{}{})
	if code != http.StatusOK {
		t.Fatalf("objects: %d %s", code, body)
	}

	var listed WipeResponse
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatal(err)
	}

	for _, want := range []uint32{0x20e50600, 0x20e5060f, 0x20e50010, ownersID} {
		if !slices.Contains(listed.Objects, fmt.Sprintf("%#08x", want)) {
			t.Errorf("wipe objects %v lacks %#08x", listed.Objects, want)
		}
	}

	code, body = wipePost(t, s, "/wipe/device", WipeDeviceRequest{IdentityPublicKey: id})
	if code != http.StatusOK {
		t.Fatalf("wipe: %d %s", code, body)
	}

	if _, ok := chip.bins[ownersID]; ok {
		t.Error("device wipe left the ownership record")
	}

	for _, left := range []uint32{0x20e50600, 0x20e5060f, 0x20e50010} {
		if _, ok := chip.keys[left]; ok {
			t.Errorf("device wipe left cold key %#08x", left)
		}
	}
}

// Wiping a profile deletes its cold key and drops the claim on it.
func TestColdOwnershipWipeProfileClearsClaim(t *testing.T) {
	t.Parallel()

	s, chip := newTestService(t)
	id := identityHex(t, s)

	code, body := post(t, s, "/provision/cold", coldReq(0x20e50602, 0x6a))
	mustOK(t, "import", code, body)

	chain := uint64(0)
	code, body = post(t, s, "/provision/profile", ProvisionRequest{
		Name: "w@preview", Slot: 2, ColdKeyID: 0x20e50602, ChainCounter: &chain, RewardAccount: testReward,
	})
	mustOK(t, "profile", code, body)

	if _, ok := claimOf(t, chip, 0x20e50602); !ok {
		t.Fatal("import left no claim")
	}

	code, body = wipePost(t, s, "/wipe/profile", WipeProfileRequest{IdentityPublicKey: id, Profile: "w@preview"})
	mustOK(t, "wipe profile", code, body)

	if _, ok := chip.keys[0x20e50602]; ok {
		t.Fatal("cold key survived the profile wipe")
	}

	if got, ok := claimOf(t, chip, 0x20e50602); ok {
		t.Errorf("claim %v survived the profile wipe", got)
	}
}

// A record that is short, of another version or malformed is refused with a
// clear error rather than read as no claims.
func TestColdOwnershipCorruptRecordFailsClosed(t *testing.T) {
	t.Parallel()

	good := ownersRecord(t, nil)
	badFlag := bytes.Clone(good)
	badFlag[1] = 7
	badVersion := bytes.Clone(good)
	badVersion[0] = 9

	for name, rec := range map[string][]byte{
		"short":   good[:ownersSize-1],
		"long":    append(bytes.Clone(good), 0),
		"empty":   {},
		"version": badVersion,
		"flag":    badFlag,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			chip := newFakeChip()
			chip.keys[0x20e50015] = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x6b}, 32))
			chip.bins[ownersID] = rec
			h := ownerHandler(t, chip)

			code, body := postAs(t, h, RouteProvisionCold, coldReq(0x20e50016, 0x6c), multiKeyTestnet)
			refused(t, "import into an empty object", code, body, errOwnersRecord)

			code, body = postAs(t, h, RouteProvisionCold, coldReq(0x20e50015, 0x6b), multiKeyTestnet)
			refused(t, "import into a held object", code, body, errOwnersRecord)

			code, body = provisionOn(t, h, ownerScopes[0], 3, 0x20e50015)
			refused(t, "provision", code, body, errOwnersRecord)

			if !bytes.Equal(chip.bins[ownersID], rec) {
				t.Error("a corrupt record was rewritten")
			}

			if _, ok := chip.keys[0x20e50016]; ok {
				t.Error("a key was imported against a corrupt record")
			}
		})
	}
}

// A failed claim write fails closed as a device error, before any key is
// imported.
func TestColdOwnershipRecordWriteFailureFailsClosed(t *testing.T) {
	t.Parallel()

	chip := newFakeChip()
	h := ownerHandler(t, chip)
	chip.failWrite = true

	code, body := postAs(t, h, RouteProvisionCold, coldReq(0x20e50603, 0x6d), multiKeyTestnet)
	refused(t, "import with a failing claim write", code, body, errDevice)

	if _, ok := chip.keys[0x20e50603]; ok {
		t.Error("the key was imported without a claim")
	}
}

// Signing a pool key checks the record: a claim by another scope than the
// profile's is refused, and a record that cannot be read does not stop
// signing, which the record was never needed for.
func TestColdOwnershipCheckedAtSigning(t *testing.T) {
	t.Parallel()

	chip, s := seedMulti(t)
	prime := multiProfiles[2]
	cardano := Scope{Network: 1, Chain: scopeCardanoName}
	primeScope := Scope{Network: 1, Chain: scopePrimeName}

	chip.bins[ownersID] = ownersRecord(t, map[uint32]Scope{prime.cold: cardano})
	if resp := opcertFor(t, s, chip, prime, multiKeyPrime, 1); resp.Error != errColdOwner.Error() {
		t.Fatalf("prime signed with a key the record gives cardano: %q", resp.Error)
	}

	chip.bins[ownersID] = []byte{9}
	if resp := opcertFor(t, s, chip, prime, multiKeyPrime, 2); resp.Error != "" {
		t.Fatalf("an unreadable record stopped signing: %q", resp.Error)
	}

	delete(chip.bins, ownersID)
	if resp := opcertFor(t, s, chip, prime, multiKeyPrime, 3); resp.Error != "" {
		t.Fatalf("no record stopped signing: %q", resp.Error)
	}

	chip.bins[ownersID] = ownersRecord(t, map[uint32]Scope{prime.cold: primeScope})
	if resp := opcertFor(t, s, chip, prime, multiKeyPrime, 4); resp.Error != "" {
		t.Fatalf("prime refused with its own claim: %q", resp.Error)
	}
}

// A single-network image checks the claim against its own scope.
func TestColdOwnershipCheckedAtSigningSingleImage(t *testing.T) {
	t.Parallel()

	chip := newFakeChip()
	s := imageOn(t, chip, 0, "")

	code, body := post(t, s, "/provision/cold", coldReq(0x20e50600, 0x68))
	mustOK(t, "import", code, body)

	chain := uint64(3)
	code, body = post(t, s, "/provision/profile", ProvisionRequest{
		Name: "x@preview", Slot: 1, ColdKeyID: 0x20e50600, ChainCounter: &chain, RewardAccount: testReward,
	})
	mustOK(t, "profile", code, body)

	p := multiProfile{name: "x@preview", cold: 0x20e50600}

	if resp := opcertUnsigned(t, s, chip, p, 1); resp.Error != "" {
		t.Fatalf("signing with the image's own claim: %q", resp.Error)
	}

	chip.bins[ownersID] = ownersRecord(t, map[uint32]Scope{0x20e50600: {Network: 1, Chain: scopeCardanoName}})
	if resp := opcertUnsigned(t, s, chip, p, 2); resp.Error != errColdOwner.Error() {
		t.Fatalf("testnet image signed with cardano's key: %q", resp.Error)
	}
}

func opcertUnsigned(t *testing.T, s *Service, chip *fakeChip, p multiProfile, n byte) SignResponse {
	t.Helper()

	cold, _ := chip.PublicKeyEd25519(p.cold)

	return postSign(t, s, SignRequest{
		Version: Protocol, Purpose: "opcert-next", KeyHash: hashHex(cold), Role: "pool",
		Nonce: nonce(n), Payload: opCertPayload(bytes.Repeat([]byte{0x4b}, 32), 3, 1100), Profile: p.name,
	})
}

// /wipe/cold deletes a cold key that no profile names: its owner may, and a
// mainnet key may delete a testnet one or one with no owner, never the other
// mainnet chain's.
func TestColdOwnershipWipeCold(t *testing.T) {
	t.Parallel()

	const (
		unowned = 0x20e50601
		testnet = 0x20e50602
		cardano = 0x20e50603
		prime   = 0x20e50604
	)

	for _, c := range []struct {
		name string
		id   uint32
		by   ed25519.PrivateKey
		want error
	}{
		{"testnet deletes its own", testnet, multiKeyTestnet, nil},
		{"cardano deletes testnet's", testnet, multiKeyCardano, nil},
		{"prime deletes an unowned key", unowned, multiKeyPrime, nil},
		{"cardano deletes its own", cardano, multiKeyCardano, nil},
		{"testnet deletes an unowned key", unowned, multiKeyTestnet, errColdOwner},
		{"testnet deletes cardano's", cardano, multiKeyTestnet, errColdOwner},
		{"prime deletes cardano's", cardano, multiKeyPrime, errColdOwner},
		{"cardano deletes prime's", prime, multiKeyCardano, errColdOwner},
		{"a profile's key", multiProfiles[0].cold, multiKeyTestnet, errColdInUse},
		{"not a cold key object", profile.IdentityKeyID, multiKeyCardano, errColdOwner},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			chip, s := seedMulti(t)
			h := s.Handler()

			plant(chip, unowned)

			for id, k := range map[uint32]ed25519.PrivateKey{testnet: multiKeyTestnet, cardano: multiKeyCardano, prime: multiKeyPrime} {
				code, body := postAs(t, h, RouteProvisionCold, coldReq(id, 0x70+byte(id&0xf)), k)
				mustOK(t, "import", code, body)
			}

			code, body := postAs(t, h, RouteProvisionIdentity, IdentityRequest{}, multiKeyCardano)
			mustOK(t, "identity", code, body)

			var ident IdentityResponse
			if err := json.Unmarshal(body, &ident); err != nil {
				t.Fatal(err)
			}

			before := objectIDs(chip)
			req := WipeColdRequest{IdentityPublicKey: hexOf(ident.PublicKey), ColdKeyID: c.id}
			code, body = postAs(t, s.WipeHandler(), RouteWipeCold, req, c.by)

			if c.want != nil {
				refused(t, c.name, code, body, c.want)

				if after := objectIDs(chip); len(after) != len(before) {
					t.Fatal("a refused wipe deleted an object")
				}

				return
			}

			mustOK(t, c.name, code, body)

			if _, ok := chip.keys[c.id]; ok {
				t.Fatalf("%#08x still holds a key", c.id)
			}

			if _, ok := claimOf(t, chip, c.id); ok {
				t.Fatalf("%#08x keeps its claim", c.id)
			}

			// the emptied object is free to any scope
			code, body = postAs(t, h, RouteProvisionCold, coldReq(c.id, 0x7e), multiKeyPrime)
			mustOK(t, "prime imports into the freed object", code, body)
		})
	}
}
