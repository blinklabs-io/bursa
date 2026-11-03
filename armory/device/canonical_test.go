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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// The canonical request binds a private key by the SHA-256 of its decoded
// bytes and never carries the key, so encoding/json never sees it.
func TestCanonicalRequestBindsKeyByDigest(t *testing.T) {
	t.Parallel()

	keyHex := strings.Repeat("a7", 32)
	cborHex := "5820" + keyHex
	raw, err := hex.DecodeString(cborHex)
	if err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])

	for name, req := range map[string]hostAuthed{
		"cold import":     &ColdRequest{ColdKeyID: testColdID + 1, SigningKey: cborHex},
		"owner provision": &ProvisionRequest{Name: "otg@preview", OwnerSigningKey: cborHex},
	} {
		canonical, err := canonicalRequest(req)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		if bytes.Contains(canonical, []byte(keyHex)) || bytes.Contains(canonical, raw) {
			t.Errorf("%s: canonical request carries the key: %s", name, canonical)
		}

		if !bytes.Contains(canonical, []byte(digest)) {
			t.Errorf("%s: canonical request lacks the key digest: %s", name, canonical)
		}

		var got string

		switch r := req.(type) {
		case *ColdRequest:
			got = r.SigningKey
		case *ProvisionRequest:
			got = r.OwnerSigningKey
		}

		if got != cborHex {
			t.Errorf("%s: canonicalRequest did not restore the key", name)
		}
	}
}

// A signature made over one key is refused when the request carries another.
func TestAdminSignatureBindsKey(t *testing.T) {
	t.Parallel()

	keyA := "5820" + strings.Repeat("a7", 32)
	keyB := "5820" + strings.Repeat("b8", 32)

	cases := map[string]struct {
		route string
		mk    func(key string) any
	}{
		"cold import": {RouteProvisionCold, func(k string) any {
			return ColdRequest{ColdKeyID: testColdID + 1, SigningKey: k}
		}},
		"owner provision": {RouteProvisionProfile, func(k string) any {
			return ProvisionRequest{Name: "otg@preview", OwnerSigningKey: k}
		}},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s, _ := newHostAuthService(t)
			h := s.ProvisioningHandler()

			code, b := rawPost(h, "/v1/challenge", []byte("{}"))
			if code != http.StatusOK {
				t.Fatalf("challenge: %d %s", code, b)
			}

			var ch ChallengeResponse
			if err := json.Unmarshal(b, &ch); err != nil {
				t.Fatal(err)
			}

			signed, err := SignAdminRequest(tc.route, jsonOf(t, tc.mk(keyA)), testHostKey, ch.Challenge)
			if err != nil {
				t.Fatal(err)
			}

			swapped := bytes.Replace(signed, []byte(keyA), []byte(keyB), 1)
			if bytes.Equal(swapped, signed) {
				t.Fatal("key not found in the signed request")
			}

			if code, b := rawPost(h, tc.route, swapped); code == http.StatusOK {
				t.Fatalf("request with another key served: %s", b)
			}
		})
	}
}
