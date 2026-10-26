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
	return summarizeTx("alice", "cafe", &bursa.TxInspection{
		TxId: "abc", Fee: "1000000",
		Outputs: []bursa.TxOutput{{Address: "addr1x", Lovelace: "1000000"}},
	},
		policy.TxOps{
			Certificates: []string{policy.CertStakeDelegation},
			Voters:       []policy.VoterInfo{{Kind: policy.VoterDrepKey, DrepId: "beef"}},
		})
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

func TestSummarizeTx_ValueEffects(t *testing.T) {
	sum := summarizeTx("alice", "cafe", &bursa.TxInspection{
		TreasuryDonationLovelace:        "4000000",
		CertificateDepositTotal:         "3000000",
		CertificateRefundTotal:          "2000000",
		UnresolvedCertificateDeposits:   1,
		UnresolvedCertificateRefunds:    2,
		CertificateValueEffectsComplete: true,
		ProposalProcedureCount:          1,
		ProposalDepositTotal:            "5000000",
	}, policy.TxOps{})
	if sum.TreasuryDonation != "4000000" ||
		sum.CertificateDepositTotal != "3000000" ||
		sum.CertificateRefundTotal != "2000000" ||
		sum.UnresolvedCertificateDeposits != 1 ||
		sum.UnresolvedCertificateRefunds != 2 ||
		!sum.CertificateValueEffectsComplete ||
		sum.ProposalProcedureCount != 1 ||
		sum.ProposalDepositTotal != "5000000" {
		t.Fatalf("unexpected value effects summary: %+v", sum)
	}
	body, err := json.Marshal(sum)
	if err != nil {
		t.Fatalf("marshal summary: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("unmarshal summary: %v", err)
	}
	for key, want := range map[string]any{
		"treasury_donation":                  "4000000",
		"certificate_deposit_total":          "3000000",
		"certificate_refund_total":           "2000000",
		"unresolved_certificate_deposits":    float64(1),
		"unresolved_certificate_refunds":     float64(2),
		"certificate_value_effects_complete": true,
		"proposal_procedure_count":           float64(1),
		"proposal_deposit_total":             "5000000",
	} {
		if got := payload[key]; got != want {
			t.Fatalf("JSON field %s = %#v, want %#v", key, got, want)
		}
	}
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
