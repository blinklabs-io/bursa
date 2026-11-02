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
)

// The exported request types marshal their key fields as the cborHex string
// the device decodes, so a host can build a request from the struct.
func TestKeyRequestsMarshalAsHex(t *testing.T) {
	t.Parallel()

	key, err := hex.DecodeString(coldKeyHex(coldSeed))
	if err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		req   any
		field string
		back  func([]byte) ([]byte, error)
	}{
		"cold": {ColdRequest{ColdKeyID: freeColdID, SigningKey: key}, "signing_key", func(b []byte) ([]byte, error) {
			var r ColdRequest
			err := json.Unmarshal(b, &r)

			return r.SigningKey, err
		}},
		"owner": {ProvisionRequest{Name: "otg@preview", ColdKeyID: testColdID, OwnerSigningKey: key}, "owner_signing_key", func(b []byte) ([]byte, error) {
			var r ProvisionRequest
			err := json.Unmarshal(b, &r)

			return r.OwnerSigningKey, err
		}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			b, err := json.Marshal(tc.req)
			if err != nil {
				t.Fatal(err)
			}

			if want := `"` + tc.field + `":"` + coldKeyHex(coldSeed) + `"`; !strings.Contains(string(b), want) {
				t.Fatalf("marshalled %s, want %s", b, want)
			}

			got, err := tc.back(b)
			if err != nil || !bytes.Equal(got, key) {
				t.Fatalf("round trip gave %x, %v, want %x", got, err, key)
			}
		})
	}

	t.Run("no key", func(t *testing.T) {
		t.Parallel()

		b, err := json.Marshal(ColdRequest{ColdKeyID: freeColdID, Generate: true})
		if err != nil || strings.Contains(string(b), "signing_key") {
			t.Fatalf("marshalled %s, %v, want no signing_key", b, err)
		}
	})

	t.Run("served", func(t *testing.T) {
		t.Parallel()

		s, _ := newTestService(t)

		code, res, body := postCold(t, s, "/provision/cold", ColdRequest{ColdKeyID: freeColdID, SigningKey: key})
		if want := ed25519.NewKeyFromSeed(coldSeed).Public().(ed25519.PublicKey); code != http.StatusOK || res.PublicKey != hex.EncodeToString(want) {
			t.Fatalf("got %d %s, want the key imported", code, body)
		}

		code, raw := post(t, s, "/provision/profile", ProvisionRequest{
			Name: "otg@preview", ColdKeyID: testColdID, RewardAccount: testReward, OwnerSigningKey: key,
		})
		if code != http.StatusOK {
			t.Fatalf("profile: %d %s", code, raw)
		}
	})
}
