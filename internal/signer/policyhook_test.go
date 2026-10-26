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
	sum, err := summarizeTx("alice", "cafe", &bursa.TxInspection{TxId: "abc", Fee: "1000000",
		Outputs:          []bursa.TxOutput{{Address: "addr1x", Lovelace: "1000000"}},
		CertificateCount: 1, VotingProcedureCount: 1},
		policy.TxOps{Certificates: []string{policy.CertStakeDelegation},
			Voters: []policy.VoterInfo{{Kind: policy.VoterDrepKey, DrepId: "beef"}}})
	if err != nil {
		panic(err)
	}
	return sum
}

func newTestHTTPPolicyHook(t *testing.T, srv *httptest.Server, timeout time.Duration) *HTTPPolicyHook {
	t.Helper()
	h, err := NewHTTPPolicyHook(srv.URL, timeout)
	if err != nil {
		t.Fatalf("NewHTTPPolicyHook: %v", err)
	}
	h.client.Transport = srv.Client().Transport
	return h
}

func TestSummarizeTx_Collateral(t *testing.T) {
	returnOutput := &bursa.TxOutput{Address: "addr1return", Lovelace: "4000000", HasAssets: true}
	sum := summarizeTx("alice", "cafe", &bursa.TxInspection{
		TxId:             "abc",
		CollateralInputs: []bursa.TxInput{{TxId: "def", Index: 2}},
		CollateralReturn: returnOutput,
		TotalCollateral:  "1000000",
	}, policy.TxOps{})
	if len(sum.CollateralInputs) != 1 || sum.CollateralInputs[0].TxId != "def" {
		t.Fatalf("unexpected collateral inputs: %+v", sum.CollateralInputs)
	}
	if sum.CollateralReturn == nil || sum.CollateralReturn.Address != "addr1return" || !sum.CollateralReturn.HasAssets {
		t.Fatalf("unexpected collateral return: %+v", sum.CollateralReturn)
	}
	if sum.TotalCollateral != "1000000" {
		t.Fatalf("total collateral = %q, want 1000000", sum.TotalCollateral)
	}
}

func TestHTTPPolicyHook_Allow(t *testing.T) {
	var gotSummary OperationSummary
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotSummary)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"allow": true}`))
	}))
	defer srv.Close()

	h := newTestHTTPPolicyHook(t, srv, time.Second)
	if err := h.Authorize(context.Background(), testSummary()); err != nil {
		t.Fatalf("expected allow, got %v", err)
	}
	if gotSummary.Type != "tx" {
		t.Fatalf("hook did not receive summary type; got %q", gotSummary.Type)
	}
	if gotSummary.CertificateCount != 1 || gotSummary.VotingProcedureCount != 1 ||
		len(gotSummary.Voters) != 1 || gotSummary.Voters[0].DrepID != "beef" {
		t.Fatalf("hook did not receive operation details: %+v", gotSummary)
	}
}

func TestHTTPPolicyHook_DenyBody(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"allow": false, "reason": "nope"}`))
	}))
	defer srv.Close()

	h := newTestHTTPPolicyHook(t, srv, time.Second)
	if err := h.Authorize(context.Background(), testSummary()); err == nil {
		t.Fatalf("expected deny on allow=false body")
	}
}

func TestHTTPPolicyHook_TrailingDataFailsClosed(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"allow": true}not-json`))
	}))
	defer srv.Close()

	h := newTestHTTPPolicyHook(t, srv, time.Second)
	if err := h.Authorize(context.Background(), testSummary()); err == nil {
		t.Fatal("expected deny (fail closed) on trailing response data")
	}
}

func TestNewHTTPPolicyHook_EmptyHostnameFailsClosed(t *testing.T) {
	if _, err := NewHTTPPolicyHook("https://:443/policy", time.Second); err == nil {
		t.Fatal("expected empty hostname to be rejected")
	}
}

func TestHTTPPolicyHook_NonOKStatus(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	h := newTestHTTPPolicyHook(t, srv, time.Second)
	if err := h.Authorize(context.Background(), testSummary()); err == nil {
		t.Fatalf("expected deny on non-200 status")
	}
}

func TestHTTPPolicyHook_TimeoutFailsClosed(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"allow": true}`))
	}))
	defer srv.Close()

	h := newTestHTTPPolicyHook(t, srv, 10*time.Millisecond)
	if err := h.Authorize(context.Background(), testSummary()); err == nil {
		t.Fatalf("expected deny (fail closed) on timeout")
	}
}

func TestHTTPPolicyHook_TransportErrorFailsClosed(t *testing.T) {
	// Point at a closed server to force a transport error.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	h := newTestHTTPPolicyHook(t, srv, 100*time.Millisecond)
	srv.Close()

	if err := h.Authorize(context.Background(), testSummary()); err == nil {
		t.Fatalf("expected deny (fail closed) on transport error")
	}
}

func TestHTTPPolicyHook_RedirectFailsClosed(t *testing.T) {
	allow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"allow": true}`))
	}))
	t.Cleanup(allow.Close)
	srv := httptest.NewTLSServer(http.RedirectHandler(allow.URL, http.StatusFound))
	t.Cleanup(srv.Close)

	h := newTestHTTPPolicyHook(t, srv, time.Second)
	if err := h.Authorize(context.Background(), testSummary()); err == nil {
		t.Fatal("expected deny (fail closed) on redirect")
	}
}
