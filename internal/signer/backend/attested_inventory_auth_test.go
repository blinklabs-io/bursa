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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestAttestedInventoryRequestBindingVector pins the bytes the armory
// firmware verifies too (armory/device TestInventoryRequestBindingVector).
func TestAttestedInventoryRequestBindingVector(t *testing.T) {
	t.Parallel()
	const want = "25a68ec406d4ac5178c76c4362792d33c7bf8330af3efe1028db60d03a11860e"
	got := hex.EncodeToString(AttestedInventoryRequestBinding(
		bytes.Repeat([]byte{1}, 32), "otg@preview", bytes.Repeat([]byte{2}, 32),
	))
	if got != want {
		t.Fatalf("AttestedInventoryRequestBinding = %s, want %s", got, want)
	}
}

// A device that refuses an unauthenticated inventory request (a multi image
// of the armory) is asked again with the host key's signature.
func TestHostKeyEnclaveInventoryRetriesSigned(t *testing.T) {
	t.Parallel()
	_, key, _ := ed25519.GenerateKey(nil)
	challenge := bytes.Repeat([]byte{9}, 32)
	var calls atomic.Int32
	var signedOK atomic.Bool
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1/challenge":
				_ = json.NewEncoder(w).
					Encode(map[string]any{"version": AttestedProtocol, "challenge": challenge})
			case "/v1/inventory":
				calls.Add(1)
				var req struct {
					Nonce         []byte `json:"nonce"`
					Profile       string `json:"profile"`
					Challenge     []byte `json:"challenge"`
					HostKey       []byte `json:"host_key"`
					HostSignature []byte `json:"host_signature"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				if len(req.HostKey) == 0 {
					http.Error(
						w,
						"host key not registered",
						http.StatusBadRequest,
					)
					return
				}
				binding := AttestedInventoryRequestBinding(
					req.Nonce,
					req.Profile,
					req.Challenge,
				)
				if !bytes.Equal(req.Challenge, challenge) ||
					!ed25519.Verify(req.HostKey, binding, req.HostSignature) {
					http.Error(
						w,
						"host signature does not verify",
						http.StatusBadRequest,
					)
					return
				}
				signedOK.Store(true)
				_ = json.NewEncoder(w).
					Encode(AttestedInventory{Version: AttestedProtocol})
			default:
				http.NotFound(w, r)
			}
		}),
	)
	t.Cleanup(srv.Close)

	e, err := NewHostKeyHTTPEnclave(srv.URL, "otg@preview", key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Inventory(t.Context(), bytes.Repeat([]byte{4}, 32)); err != nil {
		t.Fatalf("inventory: %v", err)
	}
	if calls.Load() != 2 || !signedOK.Load() {
		t.Fatalf(
			"inventory calls = %d, signed accepted = %v; want an unsigned try then a signed one",
			calls.Load(),
			signedOK.Load(),
		)
	}
}

// Without a host key there is nothing to sign with: one request, and its
// refusal is the answer.
func TestPlainEnclaveInventoryRefusalIsFinal(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			http.Error(w, "refused", http.StatusBadRequest)
		}),
	)
	t.Cleanup(srv.Close)
	e, err := NewProfiledHTTPEnclave(srv.URL, "otg@preview")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Inventory(t.Context(), bytes.Repeat([]byte{4}, 32)); err == nil ||
		calls.Load() != 1 {
		t.Fatalf(
			"err = %v, calls = %d, want one refused request",
			err,
			calls.Load(),
		)
	}
}

// A host-key enclave on a device that answers the unauthenticated request (a
// single-scope armory image) sends that one request, unsigned.
func TestHostKeyEnclaveInventoryAnsweredUnsigned(t *testing.T) {
	t.Parallel()
	_, key, _ := ed25519.GenerateKey(nil)
	var calls, signed atomic.Int32
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			if r.URL.Path != "/v1/inventory" {
				http.NotFound(w, r)
				return
			}
			var req map[string]json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			for _, f := range []string{"challenge", "host_key", "host_signature"} {
				if _, ok := req[f]; ok {
					signed.Add(1)
				}
			}
			_ = json.NewEncoder(w).
				Encode(AttestedInventory{Version: AttestedProtocol})
		}),
	)
	t.Cleanup(srv.Close)
	e, err := NewHostKeyHTTPEnclave(srv.URL, "otg@preview", key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Inventory(t.Context(), bytes.Repeat([]byte{4}, 32)); err != nil {
		t.Fatalf("inventory: %v", err)
	}
	if calls.Load() != 1 || signed.Load() != 0 {
		t.Fatalf(
			"calls = %d, authentication fields sent = %d; want one unsigned request",
			calls.Load(),
			signed.Load(),
		)
	}
}

// When the challenge for the signed retry fails, that failure is reported
// alongside the refusal of the unsigned request.
func TestHostKeyEnclaveInventoryReportsChallengeFailure(t *testing.T) {
	t.Parallel()
	_, key, _ := ed25519.GenerateKey(nil)
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/challenge" {
				http.Error(
					w,
					"challenge table full",
					http.StatusServiceUnavailable,
				)
				return
			}
			http.Error(w, "host key not registered", http.StatusBadRequest)
		}),
	)
	t.Cleanup(srv.Close)
	e, err := NewHostKeyHTTPEnclave(srv.URL, "otg@preview", key)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Inventory(t.Context(), bytes.Repeat([]byte{4}, 32))
	// the enclave client reports the status, not the body
	if err == nil || !strings.Contains(err.Error(), "HTTP 400") ||
		!strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf(
			"err = %v, want both the refusal and the challenge failure",
			err,
		)
	}
}

// A malformed challenge for the signed retry is a protocol error.
func TestHostKeyEnclaveInventoryMalformedChallenge(t *testing.T) {
	t.Parallel()
	_, key, _ := ed25519.GenerateKey(nil)
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/challenge" {
				_ = json.NewEncoder(w).
					Encode(map[string]any{"version": "other/9", "challenge": []byte{1, 2}})
				return
			}
			http.Error(w, "host key not registered", http.StatusBadRequest)
		}),
	)
	t.Cleanup(srv.Close)
	e, err := NewHostKeyHTTPEnclave(srv.URL, "otg@preview", key)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Inventory(t.Context(), bytes.Repeat([]byte{4}, 32))
	if err == nil || !errors.Is(err, ErrAttestedProtocol) ||
		!strings.Contains(err.Error(), "HTTP 400") {
		t.Fatalf("err = %v, want the refusal and %v", err, ErrAttestedProtocol)
	}
}
