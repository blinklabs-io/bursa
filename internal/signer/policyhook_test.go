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

package signer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/signer/policy"
)

func testSummary() OperationSummary {
	return summarizeTx("alice", "cafe", &bursa.TxInspection{TxId: "abc", Fee: "1000000",
		Outputs: []bursa.TxOutput{{Address: "addr1x", Lovelace: "1000000"}}},
		policy.TxOps{Certificates: []string{policy.CertStakeDelegation},
			Voters: []policy.VoterInfo{{Kind: policy.VoterDrepKey, DrepId: "beef"}}})
}

func TestHTTPPolicyHook_Allow(t *testing.T) {
	var gotType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var sum OperationSummary
		_ = json.NewDecoder(r.Body).Decode(&sum)
		gotType = sum.Type
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"allow": true}`))
	}))
	defer srv.Close()

	h := NewHTTPPolicyHook(srv.URL, time.Second)
	if err := h.Authorize(context.Background(), testSummary()); err != nil {
		t.Fatalf("expected allow, got %v", err)
	}
	if gotType != "tx" {
		t.Fatalf("hook did not receive summary type; got %q", gotType)
	}
}

func TestHTTPPolicyHook_DenyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"allow": false, "reason": "nope"}`))
	}))
	defer srv.Close()

	h := NewHTTPPolicyHook(srv.URL, time.Second)
	if err := h.Authorize(context.Background(), testSummary()); err == nil {
		t.Fatalf("expected deny on allow=false body")
	}
}

func TestHTTPPolicyHook_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	h := NewHTTPPolicyHook(srv.URL, time.Second)
	if err := h.Authorize(context.Background(), testSummary()); err == nil {
		t.Fatalf("expected deny on non-200 status")
	}
}

func TestHTTPPolicyHook_TimeoutFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"allow": true}`))
	}))
	defer srv.Close()

	h := NewHTTPPolicyHook(srv.URL, 10*time.Millisecond)
	if err := h.Authorize(context.Background(), testSummary()); err == nil {
		t.Fatalf("expected deny (fail closed) on timeout")
	}
}

func TestHTTPPolicyHook_TransportErrorFailsClosed(t *testing.T) {
	// Point at a closed server to force a transport error.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	h := NewHTTPPolicyHook(url, 100*time.Millisecond)
	if err := h.Authorize(context.Background(), testSummary()); err == nil {
		t.Fatalf("expected deny (fail closed) on transport error")
	}
}
