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

package confidentialspace

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// The workload signs only explicit-counter opcerts. opcert-next would let the
// host re-issue an existing issue number for a new KES key, and a profiled
// request needs a binding signature the workload does not produce. A refused
// request must not consume its nonce or advance the durable counter.
func TestWorkloadRefusesUnsupportedSignScope(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*backend.AttestedRequest){
		"opcert-next": func(r *backend.AttestedRequest) { r.Purpose = backend.PurposeOpCertNext },
		"profile":     func(r *backend.AttestedRequest) { r.Profile = "pool@mainnet" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newTestWorkload(t, &memoryStore{}, &testWrapper{}, &testTokens{})
			payload := lcommon.OpCertSignableBytes(bytes.Repeat([]byte{0x23}, 32), 0, 11)
			req := backend.AttestedRequest{
				Version: backend.AttestedProtocol,
				Purpose: backend.PurposeOpCert,
				KeyHash: w.hash.String(),
				Role:    backend.KeyTypePool,
				Nonce:   bytes.Repeat([]byte{0x24}, 32),
				Payload: payload,
			}
			refused := req
			mutate(&refused)
			resp, err := w.Sign(t.Context(), refused)
			if err != nil || resp.Error == "" || resp.Signature != nil {
				t.Fatalf("refused response=%+v err=%v", resp, err)
			}

			resp, err = w.Sign(t.Context(), req)
			if err != nil || resp.Error != "" ||
				!ed25519.Verify(w.pub, payload, resp.Signature) {
				t.Fatalf("valid response=%+v err=%v", resp, err)
			}
		})
	}
}

func TestWorkloadHandlerRefusesProfiledInventory(t *testing.T) {
	t.Parallel()
	w := newTestWorkload(t, &memoryStore{}, &testWrapper{}, &testTokens{})
	req := httptest.NewRequest(
		http.MethodPost,
		"/v1/inventory",
		strings.NewReader(`{"nonce":"","profile":"pool@mainnet"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{}},
		VerifiedChains:   [][]*x509.Certificate{{{}}},
	}
	rw := httptest.NewRecorder()
	w.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rw.Code, http.StatusBadRequest)
	}
}
