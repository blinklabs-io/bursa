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
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/blinklabs-io/bursa/armory/policy"
	"github.com/blinklabs-io/bursa/armory/profile"
	"github.com/fxamacker/cbor/v2"
)

var (
	pinVRF  = strings.Repeat("11", 32)
	pinMeta = strings.Repeat("22", 32)
)

// poolRegCert is a pool registration for pool and owner with the given VRF
// key hash and parameters, naming testReward and carrying metadata when meta
// is not nil.
func poolRegCert(pool, owner [28]byte, vrf byte, pledge, cost uint64, meta *byte) []any {
	reward, _ := hex.DecodeString(testReward)

	var md any
	if meta != nil {
		md = []any{"https://example.test/p.json", bytes.Repeat([]byte{*meta}, 32)}
	}

	return []any{
		uint64(3), pool[:], bytes.Repeat([]byte{vrf}, 32), pledge, cost,
		cbor.Tag{Number: 30, Content: []uint64{1, 100}},
		reward, []any{owner[:]}, []any{}, md,
	}
}

func pinnedSetup(t *testing.T) (*Service, *fakeChip, ed25519.PublicKey, [28]byte, [28]byte) {
	t.Helper()

	s, chip := newTestService(t)
	resp := provisionTestProfile(t, s)
	cold, _ := chip.PublicKeyEd25519(testColdID)

	return s, chip, cold, keyHash(cold), keyHash(resp.OwnerPublicKey)
}

// setPinsReq pins the poolRegCert registration with metadata: no relays and
// its metadata URL.
func setPinsReq() PinsRequest {
	url := "https://example.test/p.json"
	d, _ := policy.RelaysDigest(nil, &url)

	return PinsRequest{
		Profile: "otg@preview", VRFKeyHash: pinVRF, MetadataHash: pinMeta,
		PledgeMin: 100, PledgeMax: 1000, CostMax: 500, MarginMaxNum: 1, MarginMaxDen: 10,
		RelaysDigest: hex.EncodeToString(d[:]),
	}
}

// with returns c with field i replaced.
func with(c []any, i int, v any) []any {
	c = append([]any(nil), c...)
	c[i] = v

	return c
}

func signReg(t *testing.T, s *Service, cold []byte, n byte, cert []any) SignResponse {
	t.Helper()

	return sign(t, s, SignRequest{
		Purpose: "tx-body", KeyHash: hashHex(cold), Role: "pool",
		Nonce: nonce(n), Payload: certBody(cert), Profile: "otg@preview", Era: conwayEra(),
	})
}

func TestProvisionPins(t *testing.T) {
	t.Parallel()

	s, chip, _, _, _ := pinnedSetup(t)
	id := s.profiles["otg@preview"].PinsID()

	if _, ok := chip.bins[id]; ok {
		t.Fatal("pins object exists before provisioning")
	}

	if code, body := post(t, s, "/provision/pins", setPinsReq()); code != http.StatusOK {
		t.Fatalf("pins: %d %s", code, body)
	}

	got, err := profile.DecodePins(chip.bins[id])
	if err != nil || got.PledgeMax != 1000 || got.MetadataHash == nil || got.MarginMaxDen != 10 {
		t.Fatalf("stored pins %+v, %v", got, err)
	}

	// the profile record is untouched
	rec, _ := profile.Decode(chip.bins[s.profiles["otg@preview"].RecordID()])
	if rec != s.profiles["otg@preview"] {
		t.Errorf("profile record changed: %+v", rec)
	}

	// replacing rewrites the same object
	next := setPinsReq()
	next.MetadataHash, next.PledgeMax = "", 2000

	if code, body := post(t, s, "/provision/pins", next); code != http.StatusOK {
		t.Fatalf("replace: %d %s", code, body)
	}

	if got, _ = profile.DecodePins(chip.bins[id]); got.PledgeMax != 2000 || got.MetadataHash != nil {
		t.Errorf("pins not replaced: %+v", got)
	}
}

func TestProvisionPinsRefused(t *testing.T) {
	t.Parallel()

	s, chip, _, _, _ := pinnedSetup(t)

	for name, mutate := range map[string]func(*PinsRequest){
		"unknown profile":  func(r *PinsRequest) { r.Profile = "nope" },
		"short vrf":        func(r *PinsRequest) { r.VRFKeyHash = "11" },
		"vrf not hex":      func(r *PinsRequest) { r.VRFKeyHash = strings.Repeat("zz", 32) },
		"short metadata":   func(r *PinsRequest) { r.MetadataHash = "22" },
		"pledge range":     func(r *PinsRequest) { r.PledgeMin = 2000 },
		"zero denominator": func(r *PinsRequest) { r.MarginMaxDen = 0 },
		"margin above one": func(r *PinsRequest) { r.MarginMaxNum = 11; r.MarginMaxDen = 10 },
		"no relays digest": func(r *PinsRequest) { r.RelaysDigest = "" },
		"short relays":     func(r *PinsRequest) { r.RelaysDigest = r.RelaysDigest[2:] },
		"32-byte relays":   func(r *PinsRequest) { r.RelaysDigest = pinVRF },
	} {
		req := setPinsReq()
		mutate(&req)

		if code, _ := post(t, s, "/provision/pins", req); code == http.StatusOK {
			t.Errorf("%s: accepted", name)
		}
	}

	if _, ok := chip.bins[s.profiles["otg@preview"].PinsID()]; ok {
		t.Error("a refused request wrote a pins object")
	}

	chip.failWrite = true

	if code, _ := post(t, s, "/provision/pins", setPinsReq()); code == http.StatusOK {
		t.Error("accepted although the chip write failed")
	}
}

func TestPinsGatePoolRegistration(t *testing.T) {
	t.Parallel()

	s, _, cold, pool, owner := pinnedSetup(t)
	meta := byte(0x22)

	// unpinned: a registration with any VRF key still signs
	if r := signReg(t, s, cold, 1, poolRegCert(pool, owner, 0x99, 500, 400, nil)); r.Error != "" {
		t.Fatalf("unpinned profile refused: %s", r.Error)
	}

	if code, body := post(t, s, "/provision/pins", setPinsReq()); code != http.StatusOK {
		t.Fatalf("pins: %d %s", code, body)
	}

	other := byte(0x23)

	for i, c := range []struct {
		name  string
		cert  []any
		allow bool
		want  string
	}{
		{"matching", poolRegCert(pool, owner, 0x11, 500, 400, &meta), true, ""},
		{"other vrf", poolRegCert(pool, owner, 0x99, 500, 400, &meta), false, "VRF"},
		{"other metadata", poolRegCert(pool, owner, 0x11, 500, 400, &other), false, "metadata"},
		{"no metadata", poolRegCert(pool, owner, 0x11, 500, 400, nil), false, "metadata"},
		{"pledge", poolRegCert(pool, owner, 0x11, 1001, 400, &meta), false, "pledge"},
		{"cost", poolRegCert(pool, owner, 0x11, 500, 501, &meta), false, "cost"},
		{"relay added", with(poolRegCert(pool, owner, 0x11, 500, 400, &meta), 8, []any{[]any{uint64(1), uint64(3001), "evil.example"}}), false, "relays"},
		{"other metadata URL", with(poolRegCert(pool, owner, 0x11, 500, 400, &meta), 9, []any{"https://evil.example/p.json", bytes.Repeat([]byte{meta}, 32)}), false, "metadata URL"},
	} {
		r := signReg(t, s, cold, byte(i+10), c.cert)

		switch {
		case c.allow && r.Error != "":
			t.Errorf("%s: refused: %s", c.name, r.Error)
		case !c.allow && (r.Error == "" || r.Signature != nil):
			t.Errorf("%s: signed", c.name)
		case !c.allow && !strings.Contains(r.Error, c.want):
			t.Errorf("%s: refused by another rule: %s", c.name, r.Error)
		}
	}

	// the pins do not stop a retirement
	if r := signReg(t, s, cold, 90, retirement(pool)); r.Error != "" {
		t.Errorf("retirement refused: %s", r.Error)
	}
}

// TestPinsDamagedObjectRefuses checks a pins object that cannot be decoded is
// not read as "no pins".
func TestPinsDamagedObjectRefuses(t *testing.T) {
	t.Parallel()

	s, chip, cold, pool, owner := pinnedSetup(t)

	if code, body := post(t, s, "/provision/pins", setPinsReq()); code != http.StatusOK {
		t.Fatalf("pins: %d %s", code, body)
	}

	chip.bins[s.profiles["otg@preview"].PinsID()][0] = 9

	if r := signReg(t, s, cold, 1, poolRegCert(pool, owner, 0x99, 500, 400, nil)); r.Error == "" || r.Signature != nil {
		t.Fatal("registration signed with damaged pins")
	}

	// provisioning again repairs it
	if code, body := post(t, s, "/provision/pins", setPinsReq()); code != http.StatusOK {
		t.Fatalf("repair: %d %s", code, body)
	}
}

func TestWipeProfileDeletesPins(t *testing.T) {
	t.Parallel()

	s, chip := newTestService(t)
	id := identityHex(t, s)
	provisionTestProfile(t, s)
	gone := s.profiles["otg@preview"]

	if code, body := post(t, s, "/provision/pins", setPinsReq()); code != http.StatusOK {
		t.Fatalf("pins: %d %s", code, body)
	}

	chip.bins[(profile.Profile{Slot: 1}).PinsID()] = []byte("another profile's pins")

	if !objectIDs(chip)[gone.PinsID()] {
		t.Fatal("pins object missing before the wipe")
	}

	if code, body := wipePost(t, s, "/wipe/profile", WipeProfileRequest{IdentityPublicKey: id, Profile: "otg@preview"}); code != http.StatusOK {
		t.Fatalf("wipe profile: %d %s", code, body)
	}

	left := objectIDs(chip)

	if left[gone.PinsID()] {
		t.Error("pins object of the removed profile remains")
	}

	if !left[(profile.Profile{Slot: 1}).PinsID()] {
		t.Error("another slot's pins object was deleted")
	}
}

func TestWipeDeviceDeletesPins(t *testing.T) {
	t.Parallel()

	s, chip := newTestService(t)
	id := identityHex(t, s)
	provisionTestProfile(t, s)
	pinsID := s.profiles["otg@preview"].PinsID()

	if code, body := post(t, s, "/provision/pins", setPinsReq()); code != http.StatusOK {
		t.Fatalf("pins: %d %s", code, body)
	}

	if code, body := wipePost(t, s, "/wipe/device", WipeDeviceRequest{IdentityPublicKey: id}); code != http.StatusOK {
		t.Fatalf("wipe device: %d %s", code, body)
	}

	if objectIDs(chip)[pinsID] {
		t.Error("pins object survived a device wipe")
	}
}

func TestStartupReportShowsPinned(t *testing.T) {
	t.Parallel()

	_, chip, _, _, _ := pinnedSetup(t)
	pins, _ := profile.EncodePins(profile.Pins{MarginMaxDen: 1})
	chip.bins[(profile.Profile{Slot: 0}).PinsID()] = pins

	var log strings.Builder

	s := New(&sync.Mutex{}, func(f string, a ...any) { fmt.Fprintf(&log, f+"\n", a...) })
	if err := s.SetChip(chip); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(log.String(), "registration pins set") {
		t.Errorf("startup report does not show the profile is pinned:\n%s", log.String())
	}

	delete(chip.bins, (profile.Profile{Slot: 0}).PinsID())
	log.Reset()

	if err := s.SetChip(chip); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(log.String(), "registration pins none") {
		t.Errorf("startup report does not show the profile is unpinned:\n%s", log.String())
	}
}
