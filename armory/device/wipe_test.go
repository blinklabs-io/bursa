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
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/armory/profile"
)

// outsideIDs are SE050 objects the armory does not own; a wipe leaves them.
var outsideIDs = []uint32{0x7fff0201, 0x20e60000, 0x20e50400}

func wipePost(t *testing.T, s *Service, path string, req any) (int, []byte) {
	t.Helper()

	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.WipeHandler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b)))

	return w.Code, w.Body.Bytes()
}

// identityHex provisions the identity key and returns it as the hex a wipe
// request carries.
func identityHex(t *testing.T, s *Service) string {
	t.Helper()

	code, body := post(t, s, "/provision/identity", struct{}{})
	if code != http.StatusOK {
		t.Fatalf("identity: %d %s", code, body)
	}

	var resp IdentityResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}

	return hex.EncodeToString(resp.PublicKey)
}

func plant(c *fakeChip, ids ...uint32) {
	for i, id := range ids {
		c.keys[id] = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(0x40 + i)}, 32))
	}
}

func objectIDs(c *fakeChip) map[uint32]bool {
	ids := map[uint32]bool{}
	for id := range c.keys {
		ids[id] = true
	}

	for id := range c.bins {
		ids[id] = true
	}

	return ids
}

// TestWipeRoutesOnlyInWipeHandler checks the signing and provisioning
// handlers, and the combined one, serve no wipe endpoint.
func TestWipeRoutesOnlyInWipeHandler(t *testing.T) {
	s, _ := newTestService(t)

	for name, h := range map[string]http.Handler{
		"signing": s.SigningHandler(), "provisioning": s.ProvisioningHandler(), "combined": s.Handler(),
	} {
		for _, path := range []string{"/wipe/objects", "/wipe/profile", "/wipe/device"} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte("{}"))))

			if w.Code != http.StatusNotFound {
				t.Errorf("%s handler serves %s: %d", name, path, w.Code)
			}
		}
	}

	if code, body := wipePost(t, s, "/wipe/objects", struct{}{}); code != http.StatusOK {
		t.Fatalf("wipe handler: /wipe/objects %d %s", code, body)
	}
}

// TestWipeDeviceDeletesEveryArmoryObject fills every armory object range,
// wipes the device and checks only objects outside the armory remain.
func TestWipeDeviceDeletesEveryArmoryObject(t *testing.T) {
	s, chip := newTestService(t)
	id := identityHex(t, s)
	provisionTestProfile(t, s)
	registerHostKey(t, s, hostPub(testHostKey))

	last := profile.Profile{Slot: profile.MaxSlot}
	plant(chip, 0x20e50001, 0x20e50008, 0x20e5000f, coldKeyLast, last.OwnerKeyID(), 0x20e50200, 0x20e50210, 0x20e5021f)
	chip.bins[last.RecordID()] = []byte("unreadable")
	chip.bins[profile.SignLogHeadID] = []byte("head")
	plant(chip, outsideIDs...)

	code, body := wipePost(t, s, "/wipe/objects", struct{}{})
	if code != http.StatusOK {
		t.Fatalf("objects: %d %s", code, body)
	}

	var listed WipeResponse
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatal(err)
	}

	code, body = wipePost(t, s, "/wipe/device", WipeDeviceRequest{IdentityPublicKey: id})
	if code != http.StatusOK {
		t.Fatalf("wipe: %d %s", code, body)
	}

	var resp WipeResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}

	left := objectIDs(chip)
	if len(left) != len(outsideIDs) {
		t.Fatalf("objects left after wipe: %v", left)
	}

	for _, o := range outsideIDs {
		if !left[o] {
			t.Errorf("object %#x outside the armory was deleted", o)
		}
	}

	if len(resp.Deleted) != len(listed.Objects) || len(resp.Deleted) == 0 {
		t.Errorf("deleted %v, listed %v", resp.Deleted, listed.Objects)
	}

	// the identity key goes last, so a retry still matches the confirmation
	if resp.Deleted[len(resp.Deleted)-1] != "0x20e50020" {
		t.Errorf("identity key not deleted last: %v", resp.Deleted)
	}

	if len(s.profiles) != 0 {
		t.Errorf("profiles still served after wipe: %v", s.profiles)
	}
}

// TestWipeRefusesWrongConfirmation checks a wipe deletes nothing unless the
// request carries the device identity key.
func TestWipeRefusesWrongConfirmation(t *testing.T) {
	s, chip := newTestService(t)
	id := identityHex(t, s)
	provisionTestProfile(t, s)
	before := len(objectIDs(chip))

	other := hex.EncodeToString(bytes.Repeat([]byte{1}, 32))

	for name, req := range map[string]any{
		"device, empty":   WipeDeviceRequest{},
		"device, other":   WipeDeviceRequest{IdentityPublicKey: other},
		"profile, empty":  WipeProfileRequest{Profile: "otg@preview"},
		"profile, other":  WipeProfileRequest{IdentityPublicKey: other, Profile: "otg@preview"},
		"profile, absent": WipeProfileRequest{IdentityPublicKey: id, Profile: "nope@preview"},
	} {
		path := "/wipe/device"
		if _, ok := req.(WipeProfileRequest); ok {
			path = "/wipe/profile"
		}

		if code, _ := wipePost(t, s, path, req); code == http.StatusOK {
			t.Errorf("%s: accepted", name)
		}

		if got := len(objectIDs(chip)); got != before {
			t.Fatalf("%s: %d objects, want %d", name, got, before)
		}
	}
}

// TestWipeWithoutIdentityKey checks a device with no identity key is wiped
// only with an empty confirmation.
func TestWipeWithoutIdentityKey(t *testing.T) {
	s, chip := newTestService(t)
	provisionTestProfile(t, s)

	if code, _ := wipePost(t, s, "/wipe/device", WipeDeviceRequest{IdentityPublicKey: "00"}); code == http.StatusOK {
		t.Fatal("a confirmation was accepted for a device with no identity key")
	}

	if code, body := wipePost(t, s, "/wipe/device", WipeDeviceRequest{}); code != http.StatusOK {
		t.Fatalf("wipe: %d %s", code, body)
	}

	if left := objectIDs(chip); len(left) != 0 {
		t.Fatalf("objects left: %v", left)
	}
}

// TestWipeDeviceRetriesAfterFailure checks a wipe stopped by a failed delete
// finishes when the same request is sent again.
func TestWipeDeviceRetriesAfterFailure(t *testing.T) {
	s, chip := newTestService(t)
	id := identityHex(t, s)
	provisionTestProfile(t, s)

	chip.deletes, chip.failDeleteAfter = 0, 2

	code, body := wipePost(t, s, "/wipe/device", WipeDeviceRequest{IdentityPublicKey: id})
	if code == http.StatusOK {
		t.Fatal("wipe reported success after a failed delete")
	}

	if !strings.Contains(string(body), "send the request again") {
		t.Errorf("error body %q does not ask for a retry", body)
	}

	if _, ok := chip.keys[profile.IdentityKeyID]; !ok {
		t.Fatal("identity key deleted before the wipe finished")
	}

	chip.failDeleteAfter = 0

	if code, body := wipePost(t, s, "/wipe/device", WipeDeviceRequest{IdentityPublicKey: id}); code != http.StatusOK {
		t.Fatalf("retry: %d %s", code, body)
	}

	if left := objectIDs(chip); len(left) != 0 {
		t.Fatalf("objects left after retry: %v", left)
	}
}

// TestWipeProfileFreesItsSlot removes one profile, keeps the other and the
// identity key, and reuses the freed slot and cold key object.
func TestWipeProfileFreesItsSlot(t *testing.T) {
	s, chip := newTestService(t)
	id := identityHex(t, s)
	provisionTestProfile(t, s)
	plant(chip, freeColdID)

	chain := uint64(0)
	if code, body := post(t, s, "/provision/profile", ProvisionRequest{
		Name: "keep@preview", Slot: 1, ColdKeyID: freeColdID, ChainCounter: &chain, RewardAccount: testReward,
	}); code != http.StatusOK {
		t.Fatalf("second profile: %d %s", code, body)
	}

	gone, kept := s.profiles["otg@preview"], s.profiles["keep@preview"]
	chip.bins[profile.SignLogHeadID] = []byte("head")

	code, body := wipePost(t, s, "/wipe/profile", WipeProfileRequest{IdentityPublicKey: id, Profile: "otg@preview"})
	if code != http.StatusOK {
		t.Fatalf("wipe profile: %d %s", code, body)
	}

	left := objectIDs(chip)
	for _, o := range []uint32{gone.OwnerKeyID(), gone.ColdKeyID, gone.RecordID()} {
		if left[o] {
			t.Errorf("object %#x of the removed profile remains", o)
		}
	}

	for _, o := range []uint32{kept.OwnerKeyID(), kept.ColdKeyID, kept.RecordID(), profile.SignLogHeadID, profile.IdentityKeyID} {
		if !left[o] {
			t.Errorf("object %#x outside the removed profile was deleted", o)
		}
	}

	if _, ok := s.profiles["otg@preview"]; ok {
		t.Error("removed profile still served")
	}

	// the slot and the cold key object can be provisioned again
	plant(chip, testColdID)
	if code, body := post(t, s, "/provision/profile", ProvisionRequest{
		Name: "new@preview", Slot: 0, ColdKeyID: testColdID, ChainCounter: &chain, RewardAccount: testReward,
	}); code != http.StatusOK {
		t.Fatalf("reuse slot 0: %d %s", code, body)
	}
}

// TestWipeProfileRetriesAfterFailure checks the record goes last, so a
// removal stopped by a failed delete finishes when sent again by name.
func TestWipeProfileRetriesAfterFailure(t *testing.T) {
	s, chip := newTestService(t)
	id := identityHex(t, s)
	provisionTestProfile(t, s)
	p := s.profiles["otg@preview"]
	req := WipeProfileRequest{IdentityPublicKey: id, Profile: "otg@preview"}

	chip.deletes, chip.failDeleteAfter = 0, 1

	if code, _ := wipePost(t, s, "/wipe/profile", req); code == http.StatusOK {
		t.Fatal("removal reported success after a failed delete")
	}

	if _, ok := chip.bins[p.RecordID()]; !ok {
		t.Fatal("record deleted before the profile's keys")
	}

	chip.failDeleteAfter = 0

	if code, body := wipePost(t, s, "/wipe/profile", req); code != http.StatusOK {
		t.Fatalf("retry: %d %s", code, body)
	}

	if left := objectIDs(chip); left[p.RecordID()] || left[p.ColdKeyID] || left[p.OwnerKeyID()] {
		t.Fatalf("profile objects left after retry: %v", left)
	}
}

// storeRecord writes a profile record and its owner key straight to the
// chip, as a record written outside provisioning would be found.
func storeRecord(t *testing.T, c *fakeChip, p profile.Profile) {
	t.Helper()

	rec, err := profile.Encode(p)
	if err != nil {
		t.Fatal(err)
	}

	c.bins[p.RecordID()] = rec

	if err = c.GenerateEd25519(p.OwnerKeyID(), false); err != nil {
		t.Fatal(err)
	}
}

// TestWipeProfileRefusesForeignColdKey checks a record naming a cold key
// outside the cold key range is refused before anything is deleted.
func TestWipeProfileRefusesForeignColdKey(t *testing.T) {
	s, chip := newTestService(t)
	id := identityHex(t, s)
	p := profile.Profile{Name: "odd@preview", Slot: 0, ColdKeyID: outsideIDs[0]}
	storeRecord(t, chip, p)
	plant(chip, outsideIDs...)

	if err := s.SetChip(chip); err != nil {
		t.Fatal(err)
	}

	if _, ok := s.profiles[p.Name]; !ok {
		t.Fatal("record not loaded")
	}

	if code, _ := wipePost(t, s, "/wipe/profile", WipeProfileRequest{IdentityPublicKey: id, Profile: p.Name}); code == http.StatusOK {
		t.Error("wipe accepted a record naming an object outside the cold key range")
	}

	left := objectIDs(chip)
	for _, o := range []uint32{p.ColdKeyID, p.OwnerKeyID(), p.RecordID()} {
		if !left[o] {
			t.Errorf("object %#x deleted", o)
		}
	}
}

// TestWipeProfileRefusesWhileRecordUnreadable checks a profile is not
// removed while an unreadable record may name the same cold key.
func TestWipeProfileRefusesWhileRecordUnreadable(t *testing.T) {
	s, chip := newTestService(t)
	id := identityHex(t, s)
	p := profile.Profile{Name: "good@preview", Slot: 1, ColdKeyID: testColdID}
	storeRecord(t, chip, p)
	chip.bins[profile.Profile{Slot: 0}.RecordID()] = []byte("{torn")

	if err := s.SetChip(chip); err != nil {
		t.Fatal(err)
	}

	if code, _ := wipePost(t, s, "/wipe/profile", WipeProfileRequest{IdentityPublicKey: id, Profile: p.Name}); code == http.StatusOK {
		t.Error("wipe accepted while a record is unreadable")
	}

	left := objectIDs(chip)
	for _, o := range []uint32{p.ColdKeyID, p.OwnerKeyID(), p.RecordID()} {
		if !left[o] {
			t.Errorf("object %#x deleted", o)
		}
	}
}

// TestWipeProfileKeepsSharedColdKey checks a wipe keeps a cold key another
// stored profile still names.
func TestWipeProfileKeepsSharedColdKey(t *testing.T) {
	s, chip := newTestService(t)
	id := identityHex(t, s)
	gone := profile.Profile{Name: "gone@preview", Slot: 0, ColdKeyID: testColdID}
	kept := profile.Profile{Name: "kept@preview", Slot: 1, ColdKeyID: testColdID}
	storeRecord(t, chip, gone)
	storeRecord(t, chip, kept)

	if err := s.SetChip(chip); err != nil {
		t.Fatal(err)
	}

	if code, body := wipePost(t, s, "/wipe/profile", WipeProfileRequest{IdentityPublicKey: id, Profile: gone.Name}); code != http.StatusOK {
		t.Fatalf("wipe profile: %d %s", code, body)
	}

	left := objectIDs(chip)
	if left[gone.OwnerKeyID()] || left[gone.RecordID()] {
		t.Error("removed profile's owner key or record remains")
	}

	for _, o := range []uint32{testColdID, kept.OwnerKeyID(), kept.RecordID()} {
		if !left[o] {
			t.Errorf("object %#x still named by a profile was deleted", o)
		}
	}
}

// TestWipeProfileRefusesMisplacedRecord checks a record whose stored slot is
// not the slot it was read from is refused before anything is deleted, so
// the profile in the claimed slot keeps its owner key and record.
func TestWipeProfileRefusesMisplacedRecord(t *testing.T) {
	s, chip := newTestService(t)
	id := identityHex(t, s)
	plant(chip, freeColdID)
	other := profile.Profile{Name: "other@preview", Slot: 1, ColdKeyID: freeColdID}
	storeRecord(t, chip, other)

	moved := profile.Profile{Name: "moved@preview", Slot: 1, ColdKeyID: testColdID}
	rec, err := profile.Encode(moved)
	if err != nil {
		t.Fatal(err)
	}

	chip.bins[profile.Profile{Slot: 0}.RecordID()] = rec

	if err = s.SetChip(chip); err != nil {
		t.Fatal(err)
	}

	before := objectIDs(chip)

	for _, name := range []string{moved.Name, other.Name} {
		if code, _ := wipePost(t, s, "/wipe/profile", WipeProfileRequest{IdentityPublicKey: id, Profile: name}); code == http.StatusOK {
			t.Errorf("%s: wipe accepted while a record names another slot", name)
		}
	}

	if left := objectIDs(chip); len(left) != len(before) {
		t.Errorf("objects deleted: before %v, after %v", before, left)
	}
}

// TestWipeProfileRefusesDuplicateNames checks two records with one name are
// treated as ambiguous: neither is removed and their shared cold key stays.
func TestWipeProfileRefusesDuplicateNames(t *testing.T) {
	s, chip := newTestService(t)
	id := identityHex(t, s)
	first := profile.Profile{Name: "twin@preview", Slot: 0, ColdKeyID: testColdID}
	second := profile.Profile{Name: "twin@preview", Slot: 1, ColdKeyID: testColdID}
	storeRecord(t, chip, first)
	storeRecord(t, chip, second)

	if err := s.SetChip(chip); err != nil {
		t.Fatal(err)
	}

	before := objectIDs(chip)

	if code, _ := wipePost(t, s, "/wipe/profile", WipeProfileRequest{IdentityPublicKey: id, Profile: first.Name}); code == http.StatusOK {
		t.Error("wipe accepted while two records share a name")
	}

	if left := objectIDs(chip); len(left) != len(before) {
		t.Errorf("objects deleted: before %v, after %v", before, left)
	}
}
