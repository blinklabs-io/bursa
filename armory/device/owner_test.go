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
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/armory/profile"
)

var ownerSeed = bytes.Repeat([]byte{0x51}, 32)

func ownerProfileRequest(seed []byte) ProvisionRequest {
	return ProvisionRequest{
		Name: "otg@preview", Slot: 0, ColdKeyID: testColdID,
		RewardAccount: testReward, OwnerSigningKey: coldKeyHex(seed),
	}
}

func TestProvisionProfileImportsOwnerKey(t *testing.T) {
	t.Parallel()

	s, chip, logs := newLoggedService(t)

	code, body := post(t, s, "/provision/profile", ownerProfileRequest(ownerSeed))
	if code != http.StatusOK {
		t.Fatalf("provision: %d %s", code, body)
	}

	var resp ProvisionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}

	want := ed25519.NewKeyFromSeed(ownerSeed).Public().(ed25519.PublicKey)
	if !bytes.Equal(resp.OwnerPublicKey, want) {
		t.Fatalf("owner key %x, want %x", resp.OwnerPublicKey, want)
	}

	p := profile.Profile{Slot: 0}
	if pub, _ := chip.PublicKeyEd25519(p.OwnerKeyID()); !bytes.Equal(pub, want) {
		t.Fatal("chip owner key is not the imported key")
	}

	if ok, _ := chip.Exists(p.RecordID()); !ok {
		t.Fatal("profile record not written")
	}

	if strings.Contains(string(body)+logs(), hex.EncodeToString(ownerSeed)) {
		t.Fatal("seed leaked into the response or log")
	}
}

// An owner key left by an interrupted provisioning is confirmed when it is
// the imported key, and the profile is refused when it is not.
func TestProvisionProfileOwnerKeyNeverOverwrites(t *testing.T) {
	t.Parallel()

	p := profile.Profile{Slot: 0}

	t.Run("same key", func(t *testing.T) {
		t.Parallel()

		s, chip := newTestService(t)
		_ = chip.ImportEd25519(p.OwnerKeyID(), ownerSeed, false)

		if code, body := post(t, s, "/provision/profile", ownerProfileRequest(ownerSeed)); code != http.StatusOK {
			t.Fatalf("provision: %d %s", code, body)
		}
	})

	t.Run("different key", func(t *testing.T) {
		t.Parallel()

		s, chip := newTestService(t)
		_ = chip.GenerateEd25519(p.OwnerKeyID(), false)
		before, _ := chip.PublicKeyEd25519(p.OwnerKeyID())

		code, body := post(t, s, "/provision/profile", ownerProfileRequest(ownerSeed))
		if code == http.StatusOK || !strings.Contains(string(body), "owner key object already exists with a different key") {
			t.Fatalf("got %d %s, want the different owner key refused", code, body)
		}

		if after, _ := chip.PublicKeyEd25519(p.OwnerKeyID()); !bytes.Equal(before, after) {
			t.Fatal("owner key was overwritten")
		}

		if ok, _ := chip.Exists(p.RecordID()); ok {
			t.Fatal("profile record written for a refused owner key")
		}
	})
}

func TestProvisionProfileMalformedOwnerKey(t *testing.T) {
	t.Parallel()

	p := profile.Profile{Slot: 0}

	for name, key := range map[string]string{
		"not hex":   "zz",
		"short":     "5820" + strings.Repeat("51", 31),
		"extended":  "5880" + strings.Repeat("51", 128),
		"no prefix": strings.Repeat("51", 34),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s, chip := newTestService(t)
			req := ownerProfileRequest(ownerSeed)
			req.OwnerSigningKey = key

			if code, _ := post(t, s, "/provision/profile", req); code == http.StatusOK {
				t.Fatal("provisioned with a malformed owner key")
			}

			for _, id := range []uint32{p.OwnerKeyID(), p.RecordID()} {
				if ok, _ := chip.Exists(id); ok {
					t.Fatalf("object %#08x created", id)
				}
			}
		})
	}
}

func TestProvisionProfileOwnerLostImportReply(t *testing.T) {
	t.Parallel()

	s, chip := newTestService(t)
	chip.lostImportReply = true

	code, body := post(t, s, "/provision/profile", ownerProfileRequest(ownerSeed))
	if code != http.StatusOK {
		t.Fatalf("got %d %s, want the stored owner key confirmed", code, body)
	}

	var resp ProvisionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(resp.OwnerPublicKey, ed25519.NewKeyFromSeed(ownerSeed).Public().(ed25519.PublicKey)) {
		t.Fatal("response owner key is not the imported key")
	}
}

// A profile refused for any other reason imports no owner key.
func TestProvisionProfileRefusalImportsNoOwnerKey(t *testing.T) {
	t.Parallel()

	for name, req := range map[string]ProvisionRequest{
		"same slot":     {Name: "other", Slot: 0, ColdKeyID: 0x20e50011},
		"same name":     {Name: "otg@preview", Slot: 1, ColdKeyID: 0x20e50011},
		"same cold key": {Name: "other", Slot: 1, ColdKeyID: testColdID},
		"no cold key":   {Name: "other", Slot: 1, ColdKeyID: 0x20e50012},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s, chip := newTestService(t)
			provisionTestProfile(t, s)
			_ = chip.ImportEd25519(0x20e50011, coldSeed, false)

			req.OwnerSigningKey = coldKeyHex(ownerSeed)
			if code, _ := post(t, s, "/provision/profile", req); code == http.StatusOK {
				t.Fatal("provisioned")
			}

			if ok, _ := chip.Exists(profile.Profile{Slot: req.Slot}.OwnerKeyID()); ok && req.Slot != 0 {
				t.Fatal("owner key imported for a refused profile")
			}

			if pub, _ := chip.PublicKeyEd25519(profile.Profile{Slot: 0}.OwnerKeyID()); bytes.Equal(pub, ed25519.NewKeyFromSeed(ownerSeed).Public().(ed25519.PublicKey)) {
				t.Fatal("slot 0 owner key replaced")
			}
		})
	}
}

func TestProvisionProfileOwnerImportFails(t *testing.T) {
	t.Parallel()

	s, chip := newTestService(t)
	chip.failImport = true

	if code, _ := post(t, s, "/provision/profile", ownerProfileRequest(ownerSeed)); code == http.StatusOK {
		t.Fatal("provisioned after a failed import")
	}

	if ok, _ := chip.Exists(profile.Profile{Slot: 0}.RecordID()); ok {
		t.Fatal("profile record written after a failed import")
	}
}
