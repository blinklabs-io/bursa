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
	"net/http"
	"sync"
	"testing"

	"github.com/blinklabs-io/bursa/armory/profile"
)

// spareColdID holds a cold key no profile in these fixtures uses.
const spareColdID = 0x20e50012

// newNetworkService returns a service fixed to network whose chip already
// holds a testnet profile "otg@preview" in slot 1 and the identity key.
func newNetworkService(t *testing.T, network uint8) (*Service, *fakeChip) {
	t.Helper()

	chip := newFakeChip()
	p := profile.Profile{Name: "otg@preview", NetworkID: 0, Slot: 1, ColdKeyID: 0x20e50011}
	rec, err := profile.Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	chip.bins[p.RecordID()] = rec
	chip.keys[p.ColdKeyID] = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
	_ = chip.GenerateEd25519(p.OwnerKeyID(), false)
	_ = chip.GenerateEd25519(profile.IdentityKeyID, false)
	chip.keys[spareColdID] = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))

	s := New(&sync.Mutex{}, t.Logf)
	s.SetNetwork(network, "")

	if err := s.SetChip(chip); err != nil {
		t.Fatal(err)
	}

	return s, chip
}

func TestFixedNetworkServesItsOwnProfiles(t *testing.T) {
	s, _ := newNetworkService(t, 0)

	if code, body := post(t, s, "/v1/inventory", InventoryRequest{Nonce: nonce(1), Profile: "otg@preview"}); code != http.StatusOK {
		t.Fatalf("testnet profile not served on a testnet build: %d %s", code, body)
	}
}

func TestFixedNetworkRefusesOtherNetworkProfiles(t *testing.T) {
	s, chip := newNetworkService(t, 1)

	if code, _ := post(t, s, "/v1/inventory", InventoryRequest{Nonce: nonce(1), Profile: "otg@preview"}); code == http.StatusOK {
		t.Error("inventory served for a testnet profile on a mainnet build")
	}

	// a request every other check accepts, so only the network check refuses
	cold := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32)).Public().(ed25519.PublicKey)
	code, body := post(t, s, "/v1/sign", SignRequest{
		Version: Protocol, Purpose: "opcert-next", Role: "pool", KeyHash: hashHex(cold), Nonce: nonce(2),
		Profile: "otg@preview", Payload: opCertPayload(make([]byte, 32), 0, 1),
	})
	var resp SignResponse
	if code == http.StatusOK {
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatal(err)
		}
	}
	if code == http.StatusOK && (resp.Error == "" || len(resp.Signature) != 0) {
		t.Error("signed for a testnet profile on a mainnet build")
	}

	before := string(chip.bins[profile.Profile{Slot: 1}.RecordID()])

	if code, _ := post(t, s, "/provision/floor", FloorRequest{Profile: "otg@preview", ChainCounter: 9}); code == http.StatusOK {
		t.Error("floor reset for a testnet profile on a mainnet build")
	}

	if code, _ := post(t, s, "/provision/reward", RewardRequest{Profile: "otg@preview", RewardAccount: testReward}); code == http.StatusOK {
		t.Error("reward account set for a testnet profile on a mainnet build")
	}

	if string(chip.bins[profile.Profile{Slot: 1}.RecordID()]) != before {
		t.Error("testnet profile record changed on a mainnet build")
	}
}

func TestFixedNetworkRefusesOtherNetworkProvisioning(t *testing.T) {
	s, chip := newNetworkService(t, 1)
	p := profile.Profile{Slot: 2}

	code, _ := post(t, s, "/provision/profile", ProvisionRequest{
		Name: "new@preview", NetworkID: 0, Slot: 2, ColdKeyID: spareColdID,
	})
	if code == http.StatusOK {
		t.Fatal("testnet profile provisioned on a mainnet build")
	}

	if _, ok := chip.bins[p.RecordID()]; ok {
		t.Error("profile record written")
	}

	if ok, _ := chip.Exists(p.OwnerKeyID()); ok {
		t.Error("owner key created")
	}
}

// newChainService returns a mainnet service fixed to chain whose chip holds
// a mainnet profile named name in slot 1.
func newChainService(t *testing.T, chain, name string) *Service {
	t.Helper()

	chip := newFakeChip()
	p := profile.Profile{Name: name, NetworkID: 1, Slot: 1, ColdKeyID: 0x20e50011}
	rec, err := profile.Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	chip.bins[p.RecordID()] = rec
	chip.keys[p.ColdKeyID] = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
	_ = chip.GenerateEd25519(p.OwnerKeyID(), false)
	_ = chip.GenerateEd25519(profile.IdentityKeyID, false)
	chip.keys[spareColdID] = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))

	s := New(&sync.Mutex{}, t.Logf)
	s.SetNetwork(1, chain)

	if err := s.SetChip(chip); err != nil {
		t.Fatal(err)
	}

	return s
}

func TestFixedChainServesItsOwnProfiles(t *testing.T) {
	s := newChainService(t, "prime-mainnet", "pool@prime-mainnet")

	if code, body := post(t, s, "/v1/inventory", InventoryRequest{Nonce: nonce(1), Profile: "pool@prime-mainnet"}); code != http.StatusOK {
		t.Fatalf("own chain profile not served: %d %s", code, body)
	}
}

func TestFixedChainRefusesOtherChainProfiles(t *testing.T) {
	s := newChainService(t, "prime-mainnet", "pool@cardano-mainnet")

	if code, _ := post(t, s, "/v1/inventory", InventoryRequest{Nonce: nonce(1), Profile: "pool@cardano-mainnet"}); code == http.StatusOK {
		t.Error("inventory served for another chain's profile")
	}

	if code, _ := post(t, s, "/provision/floor", FloorRequest{Profile: "pool@cardano-mainnet", ChainCounter: 9}); code == http.StatusOK {
		t.Error("floor reset for another chain's profile")
	}

	for _, name := range []string{"new@cardano-mainnet", "new", "new@prime-mainnet-2", "new@xprime-mainnet"} {
		if code, _ := post(t, s, "/provision/profile", ProvisionRequest{
			Name: name, NetworkID: 1, Slot: 2, ColdKeyID: spareColdID,
		}); code == http.StatusOK {
			t.Errorf("profile %q provisioned on a prime-mainnet build", name)
		}
	}

	// the same request for this chain succeeds, so the refusals above came
	// from the chain check
	if code, body := post(t, s, "/provision/profile", ProvisionRequest{
		Name: "new@prime-mainnet", NetworkID: 1, Slot: 2, ColdKeyID: spareColdID,
	}); code != http.StatusOK {
		t.Fatalf("own chain profile not provisioned: %d %s", code, body)
	}
}

func TestFixedNetworkProvisionsItsOwnNetwork(t *testing.T) {
	s, _ := newNetworkService(t, 0)

	if code, body := post(t, s, "/provision/profile", ProvisionRequest{
		Name: "new@preview", NetworkID: 0, Slot: 2, ColdKeyID: spareColdID,
	}); code != http.StatusOK {
		t.Fatalf("testnet profile not provisioned on a testnet build: %d %s", code, body)
	}
}
