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
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// enclaveHandler serves a fakeEnclave over the HTTPEnclave wire format.
func enclaveHandler(e *fakeEnclave) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/inventory", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Nonce []byte `json:"nonce"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		inv, _ := e.Inventory(r.Context(), in.Nonce)
		_ = json.NewEncoder(w).Encode(inv)
	})
	mux.HandleFunc("/v1/sign", func(w http.ResponseWriter, r *http.Request) {
		var req AttestedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp, _ := e.Sign(r.Context(), req)
		_ = json.NewEncoder(w).Encode(resp)
	})
	return mux
}

func TestHTTPEnclaveEndToEnd(t *testing.T) {
	t.Parallel()
	e := newFakeEnclave(t, KeyTypePool)
	srv := httptest.NewServer(enclaveHandler(e))
	t.Cleanup(srv.Close)

	enc, err := NewHTTPEnclave(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	b := NewAttestedBackend("enclave", enc, stubVerifier{})
	if err := b.Load(t.Context()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	ref, err := b.GetKey(t.Context(), e.hashOf(0))
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 48)
	sig, err := SignFor(t.Context(), ref, PurposeOpCert, payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !ed25519.Verify(ref.PublicKey(), payload, sig) {
		t.Fatal("signature does not verify")
	}
}

func TestHTTPEnclaveUnixSocket(t *testing.T) {
	t.Parallel()
	e := newFakeEnclave(t, KeyTypePayment)
	path := filepath.Join(t.TempDir(), "enclave.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	srv := &http.Server{Handler: enclaveHandler(e)}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	enc, err := NewHTTPEnclave("unix://" + path)
	if err != nil {
		t.Fatal(err)
	}
	if err := NewAttestedBackend("enclave", enc, stubVerifier{}).Load(t.Context()); err != nil {
		t.Fatalf("Load over unix socket: %v", err)
	}
}

func TestHTTPEnclaveRejectsBadResponses(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"server error", http.StatusInternalServerError, `{}`, nil},
		{"unknown field", http.StatusOK, `{"version":"bursa-attested-signer/1","keys":[],"attestation":"AA==","extra":1}`, ErrAttestedProtocol},
		{"trailing data", http.StatusOK, `{"version":"bursa-attested-signer/1"} {}`, ErrAttestedProtocol},
		{"trailing close bracket", http.StatusOK, `{"version":"bursa-attested-signer/1"}]`, ErrAttestedProtocol},
		{"trailing close brace", http.StatusOK, `{"version":"bursa-attested-signer/1"}}`, ErrAttestedProtocol},
		{"not json", http.StatusOK, `nope`, ErrAttestedProtocol},
		// Valid JSON that only an enforced size cap refuses: a truncated read
		// of the padding would still decode.
		{"oversized", http.StatusOK, `{"version":"bursa-attested-signer/1","keys":[],"attestation":"AA=="}` + strings.Repeat(" ", attestedMaxResponse+1), ErrAttestedProtocol},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)
			enc, err := NewHTTPEnclave(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			_, err = enc.Inventory(t.Context(), make([]byte, attestedNonceSize))
			if err == nil {
				t.Fatal("expected an error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestNewHTTPEnclaveValidatesAddress(t *testing.T) {
	t.Parallel()
	for _, addr := range []string{"", "ftp://host", "http://", "unix://", "vsock://16:5000", "://bad"} {
		if _, err := NewHTTPEnclave(addr); err == nil {
			t.Errorf("address %q accepted", addr)
		}
	}
}
