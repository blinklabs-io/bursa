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
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/blinklabs-io/bursa/armory/profile"
)

// imageOn returns the service a firmware image fixed to network and chain
// runs on chip; images for different networks share one device.
func imageOn(t *testing.T, chip *fakeChip, network uint8, chain string) *Service {
	t.Helper()

	s := New(&sync.Mutex{}, t.Logf)
	s.SetNetwork(network, chain)

	if err := s.SetChip(chip); err != nil {
		t.Fatal(err)
	}

	return s
}

func scopeKey(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32))
}

// authAs reports whether s accepts a correctly signed request from k.
func authAs(t *testing.T, s *Service, k ed25519.PrivateKey) error {
	t.Helper()

	c, err := s.challenge(struct{}{})
	if err != nil {
		t.Fatal(err)
	}

	binding := []byte("binding")

	return s.authenticateHost(hostPub(k), ed25519.Sign(k, binding), c.Challenge, binding)
}

func listed(resp HostKeyResponse, k ed25519.PrivateKey) bool {
	for _, got := range resp.HostKeys {
		if bytes.Equal(got, hostPub(k)) {
			return true
		}
	}

	return false
}

// TestHostKeyIsScopedToImageNetwork checks a key registered by a testnet
// image is not trusted, listed or revocable by a mainnet image on the same
// device, and the reverse.
func TestHostKeyIsScopedToImageNetwork(t *testing.T) {
	t.Parallel()

	chip := newFakeChip()
	testnetKey, mainnetKey := scopeKey(1), scopeKey(2)

	testnet := imageOn(t, chip, 0, "")
	if _, err := testnet.addHostKey(HostKeyRequest{PublicKey: hostPub(testnetKey)}); err != nil {
		t.Fatal(err)
	}

	mainnet := imageOn(t, chip, 1, "")

	if err := authAs(t, mainnet, testnetKey); !errors.Is(err, errHostAuthMissing) {
		t.Fatalf("mainnet image trusts a testnet host key: %v", err)
	}

	if _, err := mainnet.addHostKey(HostKeyRequest{PublicKey: hostPub(mainnetKey)}); err != nil {
		t.Fatal(err)
	}

	if err := authAs(t, mainnet, mainnetKey); err != nil {
		t.Fatalf("mainnet image refuses its own host key: %v", err)
	}

	if err := authAs(t, mainnet, testnetKey); !errors.Is(err, errHostKeyUnknown) {
		t.Fatalf("mainnet image trusts a testnet host key: %v", err)
	}

	// the testnet image sees only its own key and cannot revoke the other
	testnet = imageOn(t, chip, 0, "")

	if err := authAs(t, testnet, testnetKey); err != nil {
		t.Fatalf("testnet image lost its host key: %v", err)
	}

	if err := authAs(t, testnet, mainnetKey); !errors.Is(err, errHostKeyUnknown) {
		t.Fatalf("testnet image trusts a mainnet host key: %v", err)
	}

	if _, err := testnet.revokeHostKey(HostKeyRequest{PublicKey: hostPub(mainnetKey)}); !errors.Is(err, errHostKeyUnknown) {
		t.Fatalf("testnet image revoked a mainnet host key: %v", err)
	}

	resp, err := testnet.addHostKey(HostKeyRequest{PublicKey: hostPub(testnetKey)})
	if err != nil || listed(resp, mainnetKey) {
		t.Fatalf("testnet image lists a mainnet host key: %v %v", resp, err)
	}

	// a testnet write keeps the mainnet entry
	if _, err := testnet.addHostKey(HostKeyRequest{PublicKey: hostPub(scopeKey(6))}); err != nil {
		t.Fatal(err)
	}

	mainnet = imageOn(t, chip, 1, "")
	if err := authAs(t, mainnet, mainnetKey); err != nil {
		t.Fatalf("mainnet host key lost after a testnet write: %v", err)
	}
}

// TestHostKeyIsScopedToImageChain checks two mainnet images for different
// chains do not share host keys.
func TestHostKeyIsScopedToImageChain(t *testing.T) {
	t.Parallel()

	chip := newFakeChip()
	k := scopeKey(3)

	a := imageOn(t, chip, 1, "prime-mainnet")
	if _, err := a.addHostKey(HostKeyRequest{PublicKey: hostPub(k)}); err != nil {
		t.Fatal(err)
	}

	if err := authAs(t, a, k); err != nil {
		t.Fatalf("own chain refused: %v", err)
	}

	b := imageOn(t, chip, 1, "cardano-mainnet")
	if err := authAs(t, b, k); !errors.Is(err, errHostAuthMissing) {
		t.Fatalf("other chain trusts the host key: %v", err)
	}
}

// TestLegacyHostKeyListScope checks a host key list written before keys were
// scoped still decodes: testnet images trust its keys, a mainnet image does
// not.
func TestLegacyHostKeyListScope(t *testing.T) {
	t.Parallel()

	chip := newFakeChip()
	k := scopeKey(4)

	legacy := make([]byte, hostKeysLen)
	copy(legacy, hostPub(k))
	chip.bins[hostKeysID] = legacy

	if err := authAs(t, imageOn(t, chip, 0, ""), k); err != nil {
		t.Fatalf("testnet image refuses a legacy host key: %v", err)
	}

	if err := authAs(t, imageOn(t, chip, 1, ""), k); !errors.Is(err, errHostAuthMissing) {
		t.Fatalf("mainnet image trusts a legacy host key: %v", err)
	}

	// a testnet write keeps the legacy entry readable by testnet images
	s := imageOn(t, chip, 0, "")
	if _, err := s.addHostKey(HostKeyRequest{PublicKey: hostPub(scopeKey(5))}); err != nil {
		t.Fatal(err)
	}

	s = imageOn(t, chip, 0, "")
	if err := authAs(t, s, k); err != nil {
		t.Fatalf("legacy host key lost after a rewrite: %v", err)
	}

	if err := authAs(t, imageOn(t, chip, 1, ""), k); !errors.Is(err, errHostAuthMissing) {
		t.Fatalf("rewrite promoted a legacy host key to mainnet: %v", err)
	}
}

// TestWipeProfileRefusesOtherNetwork checks a wipe image for one network does
// not remove another network's profile.
func TestWipeProfileRefusesOtherNetwork(t *testing.T) {
	t.Parallel()

	// the fixture holds testnet profile otg@preview; the image serves mainnet
	s, chip := newNetworkService(t, 1)

	pub, err := chip.PublicKeyEd25519(profile.IdentityKeyID)
	if err != nil {
		t.Fatal(err)
	}

	p := profile.Profile{Slot: 1}
	before := len(objectIDs(chip))

	code, body := wipePost(t, s, "/wipe/profile", WipeProfileRequest{
		IdentityPublicKey: hex.EncodeToString(pub), Profile: "otg@preview",
	})
	if code == http.StatusOK {
		t.Fatalf("mainnet wipe image removed a testnet profile: %s", body)
	}

	if _, ok := chip.bins[p.RecordID()]; !ok {
		t.Error("testnet profile record deleted")
	}

	if _, ok := s.profiles["otg@preview"]; !ok {
		t.Error("testnet profile dropped from the service")
	}

	if got := len(objectIDs(chip)); got != before {
		t.Errorf("objects %d -> %d", before, got)
	}
}

// TestOtherScopeHostKeyStillRequiresAuth checks an image whose own scope has
// no host key still refuses an unauthenticated request while another scope
// has one: a device with a registered host key refuses requests without it.
func TestOtherScopeHostKeyStillRequiresAuth(t *testing.T) {
	t.Parallel()

	chip := newFakeChip()

	mainnet := imageOn(t, chip, 1, "")
	if _, err := mainnet.addHostKey(HostKeyRequest{PublicKey: hostPub(scopeKey(7))}); err != nil {
		t.Fatal(err)
	}

	testnet := imageOn(t, chip, 0, "")
	if err := testnet.authenticateHost(nil, nil, nil, []byte("binding")); !errors.Is(err, errHostKeyUnknown) {
		t.Fatalf("testnet image accepted an unauthenticated request: %v", err)
	}

	// the testnet image registers its own key and authenticates with it
	k := scopeKey(8)
	if _, err := testnet.addHostKey(HostKeyRequest{PublicKey: hostPub(k)}); err != nil {
		t.Fatal(err)
	}

	if err := authAs(t, testnet, k); err != nil {
		t.Fatalf("testnet image refuses its own host key: %v", err)
	}
}

// TestUnknownHostKeyScopeRefusesSigning checks a scoped list with an unknown
// scope kind is unreadable, so signing is refused rather than the entry being
// trusted.
func TestUnknownHostKeyScopeRefusesSigning(t *testing.T) {
	t.Parallel()

	chip := newFakeChip()
	k := scopeKey(9)

	list := make([]byte, hostListSize)
	copy(list, hostPub(k))
	list[ed25519.PublicKeySize] = 2
	chip.bins[hostKeysID] = list

	if err := authAs(t, imageOn(t, chip, 0, ""), k); !errors.Is(err, errHostKeysBad) {
		t.Fatalf("unknown scope kind accepted: %v", err)
	}
}
