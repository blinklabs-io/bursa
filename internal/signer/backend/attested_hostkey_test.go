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

package backend

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestAttestedRequestBindingVector pins the bytes the armory firmware signs
// over too (armory/device TestRequestBindingVector).
func TestAttestedRequestBindingVector(t *testing.T) {
	t.Parallel()
	era := uint(6)
	req := AttestedRequest{
		Version: AttestedProtocol, Purpose: "opcert-next", KeyHash: strings.Repeat("ab", 28), Role: KeyTypePool,
		Nonce: bytes.Repeat([]byte{1}, 32), Payload: bytes.Repeat([]byte{2}, 48), Profile: "otg@preview",
		Era: &era, Challenge: bytes.Repeat([]byte{3}, 32),
	}
	const want = "a398cde575f763d683168b38b24f539dc61fe9235f2140f36321c92ee0d944d0"
	if got := hex.EncodeToString(AttestedRequestBinding(req)); got != want {
		t.Fatalf("AttestedRequestBinding = %s, want %s", got, want)
	}
}

// hostAuthDevice serves /v1/challenge and a /v1/sign that accepts only a
// request signed by key over a challenge it issued, once.
type hostAuthDevice struct {
	mu         sync.Mutex
	key        ed25519.PublicKey
	challenge  func(n int) any
	issued     [][]byte
	challenges int
	signs      int
	inventory  int
	refused    string
}

func (d *hostAuthDevice) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch r.URL.Path {
	case "/v1/challenge":
		d.challenges++
		c := bytes.Repeat([]byte{byte(d.challenges)}, 32)
		d.issued = append(d.issued, c)
		resp := any(map[string]any{"version": AttestedProtocol, "challenge": c})
		if d.challenge != nil {
			resp = d.challenge(d.challenges)
		}
		_ = json.NewEncoder(w).Encode(resp)
	case "/v1/inventory":
		d.inventory++
		_ = json.NewEncoder(w).Encode(AttestedInventory{Version: AttestedProtocol})
	case "/v1/sign":
		d.signs++
		var req AttestedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := AttestedResponse{Version: AttestedProtocol, Nonce: req.Nonce, Signature: []byte{1}}
		switch {
		case !bytes.Equal(req.HostKey, d.key):
			resp.Error = "host key not registered"
		case !ed25519.Verify(req.HostKey, AttestedRequestBinding(req), req.HostSignature):
			resp.Error = "host signature does not verify"
		default:
			resp.Error = "unknown or used challenge"
			for i, c := range d.issued {
				if bytes.Equal(c, req.Challenge) {
					d.issued = append(d.issued[:i], d.issued[i+1:]...)
					resp.Error = ""
					break
				}
			}
		}
		d.refused = resp.Error
		_ = json.NewEncoder(w).Encode(resp)
	default:
		http.NotFound(w, r)
	}
}

func newHostKeyEnclave(t *testing.T, d *hostAuthDevice) *HTTPEnclave {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(nil)
	d.key = key.Public().(ed25519.PublicKey)
	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	e, err := NewHostKeyHTTPEnclave(srv.URL, "otg@preview", key)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func hostKeyRequest() AttestedRequest {
	return AttestedRequest{
		Version: AttestedProtocol, Purpose: PurposeTxBody, KeyHash: strings.Repeat("ab", 28), Role: KeyTypePool,
		Nonce: bytes.Repeat([]byte{1}, 32), Payload: []byte{0xa0}, Profile: "otg@preview",
	}
}

func TestHostKeyEnclaveAuthenticatesEverySign(t *testing.T) {
	t.Parallel()
	d := &hostAuthDevice{}
	e := newHostKeyEnclave(t, d)

	for i := range 2 {
		resp, err := e.Sign(t.Context(), hostKeyRequest())
		if err != nil || resp.Error != "" {
			t.Fatalf("sign %d: resp=%+v err=%v", i, resp, err)
		}
	}
	if d.challenges != 2 || d.signs != 2 {
		t.Fatalf("challenges=%d signs=%d, want one challenge per signature", d.challenges, d.signs)
	}

	if _, err := e.Inventory(t.Context(), bytes.Repeat([]byte{2}, 32)); err != nil {
		t.Fatal(err)
	}
	if d.challenges != 2 {
		t.Fatal("inventory fetched a challenge")
	}
}

func TestHostKeyEnclaveRefusesBadChallenge(t *testing.T) {
	t.Parallel()
	for name, challenge := range map[string]func(int) any{
		"short challenge": func(int) any {
			return map[string]any{"version": AttestedProtocol, "challenge": []byte{1, 2, 3}}
		},
		"other version": func(n int) any {
			return map[string]any{"version": "other/1", "challenge": bytes.Repeat([]byte{byte(n)}, 32)}
		},
		"unknown field": func(n int) any {
			return map[string]any{"version": AttestedProtocol, "challenge": bytes.Repeat([]byte{byte(n)}, 32), "x": 1}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := &hostAuthDevice{challenge: challenge}
			e := newHostKeyEnclave(t, d)
			if _, err := e.Sign(t.Context(), hostKeyRequest()); err == nil {
				t.Fatal("signed with a bad challenge response")
			}
			if d.signs != 0 {
				t.Fatal("sign request sent after a bad challenge response")
			}
		})
	}
}

func TestPlainEnclaveSendsNoHostFields(t *testing.T) {
	t.Parallel()
	pub, _, _ := ed25519.GenerateKey(nil)
	d := &hostAuthDevice{key: pub}
	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	e, err := NewProfiledHTTPEnclave(srv.URL, "otg@preview")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Sign(t.Context(), hostKeyRequest()); err != nil {
		t.Fatal(err)
	}
	if d.challenges != 0 || d.refused != "host key not registered" {
		t.Fatalf("challenges=%d refused=%q, want no challenge and no host key", d.challenges, d.refused)
	}
}
