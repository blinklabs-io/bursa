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

package policy

import (
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

func mustHash(t *testing.T, s string) backend.KeyHash {
	t.Helper()
	h, err := backend.ParseKeyHash(s)
	if err != nil {
		t.Fatalf("ParseKeyHash: %v", err)
	}
	return h
}

const hashA = "00000000000000000000000000000000000000000000000000000001"

func TestEngine_PolicyFor(t *testing.T) {
	e, err := NewEngine([]KeyPolicy{{Hash: hashA, Backend: "software", AllowedRequests: []string{"tx"}}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if _, ok := e.PolicyFor(mustHash(t, hashA)); !ok {
		t.Fatalf("expected policy for hashA")
	}
	if _, ok := e.PolicyFor(mustHash(t, "00000000000000000000000000000000000000000000000000000002")); ok {
		t.Fatalf("did not expect policy for unknown hash")
	}
}

func TestNewEngine_RejectsBadHash(t *testing.T) {
	if _, err := NewEngine([]KeyPolicy{{Hash: "xyz"}}); err == nil {
		t.Fatalf("expected error for invalid hash")
	}
}

func engineWith(t *testing.T, p KeyPolicy) (*Engine, backend.KeyHash) {
	t.Helper()
	p.Hash = hashA
	e, err := NewEngine([]KeyPolicy{p})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e, mustHash(t, hashA)
}

func TestEvaluateTx_DenyNoPolicy(t *testing.T) {
	e, err := NewEngine(nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	d := e.EvaluateTx(mustHash(t, hashA), &bursa.TxInspection{})
	if d.Allow {
		t.Fatalf("expected deny when no policy")
	}
}

func TestEvaluateTx_DenyNilInspection(t *testing.T) {
	e, h := engineWith(t, KeyPolicy{AllowedRequests: []string{"tx"}, Tx: &TxPolicy{}})
	if e.EvaluateTx(h, nil).Allow {
		t.Fatalf("expected deny for nil inspection")
	}
}

func TestEvaluateTx_DenyRequestTypeNotAllowed(t *testing.T) {
	e, h := engineWith(t, KeyPolicy{AllowedRequests: []string{"cip8"}, Tx: &TxPolicy{}})
	if e.EvaluateTx(h, &bursa.TxInspection{}).Allow {
		t.Fatalf("expected deny: tx not in allowed_requests")
	}
}

func TestEvaluateTx_MaxOutputAda(t *testing.T) {
	e, h := engineWith(t, KeyPolicy{
		AllowedRequests: []string{"tx"},
		Tx:              &TxPolicy{MaxOutputAda: 100}, // 100 ADA = 100_000_000 lovelace
	})
	over := &bursa.TxInspection{Outputs: []bursa.TxOutput{{Address: "addr1xyz", Lovelace: "100000001"}}}
	if e.EvaluateTx(h, over).Allow {
		t.Fatalf("expected deny: output exceeds max_output_ada")
	}
	ok := &bursa.TxInspection{Outputs: []bursa.TxOutput{{Address: "addr1xyz", Lovelace: "100000000"}}}
	if !e.EvaluateTx(h, ok).Allow {
		t.Fatalf("expected allow at exactly max")
	}
}

func TestEvaluateTx_OutputAllowlist(t *testing.T) {
	e, h := engineWith(t, KeyPolicy{
		AllowedRequests: []string{"tx"},
		Tx:              &TxPolicy{AllowedOutputs: []string{"addr1good"}},
	})
	bad := &bursa.TxInspection{Outputs: []bursa.TxOutput{{Address: "addr1bad", Lovelace: "1"}}}
	if e.EvaluateTx(h, bad).Allow {
		t.Fatalf("expected deny: output not in allowlist")
	}
}

func TestEvaluateTx_CertsMintWithdrawals(t *testing.T) {
	e, h := engineWith(t, KeyPolicy{AllowedRequests: []string{"tx"}, Tx: &TxPolicy{}})
	if e.EvaluateTx(h, &bursa.TxInspection{CertificateCount: 1}).Allow {
		t.Fatalf("expected deny: certs not allowed")
	}
	if e.EvaluateTx(h, &bursa.TxInspection{HasMint: true}).Allow {
		t.Fatalf("expected deny: mint not allowed")
	}
	if e.EvaluateTx(h, &bursa.TxInspection{WithdrawalCount: 1}).Allow {
		t.Fatalf("expected deny: withdrawals not allowed")
	}
}

func TestEvaluateTx_NetworkAndValidity(t *testing.T) {
	e, h := engineWith(t, KeyPolicy{
		AllowedRequests: []string{"tx"},
		Tx:              &TxPolicy{Networks: []string{"mainnet"}, RequireValidityUpperBound: true},
	})
	// testnet output address -> deny
	d := e.EvaluateTx(h, &bursa.TxInspection{TTL: 1, Outputs: []bursa.TxOutput{{Address: "addr_test1abc", Lovelace: "1"}}})
	if d.Allow {
		t.Fatalf("expected deny: testnet address on mainnet-only policy")
	}
	// mainnet, but no TTL -> deny
	if e.EvaluateTx(h, &bursa.TxInspection{TTL: 0, Outputs: []bursa.TxOutput{{Address: "addr1abc", Lovelace: "1"}}}).Allow {
		t.Fatalf("expected deny: missing validity upper bound")
	}
	// mainnet + TTL -> allow
	if !e.EvaluateTx(h, &bursa.TxInspection{TTL: 5, Outputs: []bursa.TxOutput{{Address: "addr1abc", Lovelace: "1"}}}).Allow {
		t.Fatalf("expected allow")
	}
	// Unknown address format must not be treated as mainnet.
	if e.EvaluateTx(h, &bursa.TxInspection{TTL: 5, Outputs: []bursa.TxOutput{{Address: "not-an-address", Lovelace: "1"}}}).Allow {
		t.Fatalf("expected deny: unknown address network")
	}
}

func TestNewEngine_RejectsDuplicateHash(t *testing.T) {
	policies := []KeyPolicy{
		{Hash: hashA, Backend: "software", AllowedRequests: []string{"tx"}},
		{Hash: hashA, Backend: "software", AllowedRequests: []string{"cip8"}},
	}
	if _, err := NewEngine(policies); err == nil {
		t.Fatalf("expected error for duplicate key hash")
	}
}

func TestEvaluateTx_MaxTotalOutAda(t *testing.T) {
	e, h := engineWith(t, KeyPolicy{
		AllowedRequests: []string{"tx"},
		Tx:              &TxPolicy{MaxTotalOutAda: 50}, // 50 ADA = 50_000_000 lovelace
	})
	// Two outputs of 30 ADA each = 60 ADA total → deny
	over := &bursa.TxInspection{Outputs: []bursa.TxOutput{
		{Address: "addr1a", Lovelace: "30000000"},
		{Address: "addr1b", Lovelace: "30000000"},
	}}
	if e.EvaluateTx(h, over).Allow {
		t.Fatalf("expected deny: total outputs exceed max_total_out_ada")
	}
	// Exactly 50 ADA in one output → allow
	exact := &bursa.TxInspection{Outputs: []bursa.TxOutput{
		{Address: "addr1a", Lovelace: "50000000"},
	}}
	if !e.EvaluateTx(h, exact).Allow {
		t.Fatalf("expected allow at exactly max_total_out_ada")
	}
}

func TestEvaluateTx_FeeCountsTowardTotal(t *testing.T) {
	e, h := engineWith(t, KeyPolicy{
		AllowedRequests: []string{"tx"},
		Tx:              &TxPolicy{MaxTotalOutAda: 10}, // 10 ADA = 10_000_000 lovelace
	})
	// A single 1-ADA change output passes the lovelace-output checks, but the
	// fee carries away the rest: outputs (1) + fee (9.000001) > 10 ADA → deny.
	// This is the fee-drain bypass: without counting the fee, this was allowed.
	drain := &bursa.TxInspection{
		Fee:     "9000001",
		Outputs: []bursa.TxOutput{{Address: "addr1a", Lovelace: "1000000"}},
	}
	if e.EvaluateTx(h, drain).Allow {
		t.Fatalf("expected deny: outputs plus fee exceed max_total_out_ada")
	}
	// Outputs (1) + fee (1) = 2 ADA, well under the cap → allow.
	ok := &bursa.TxInspection{
		Fee:     "1000000",
		Outputs: []bursa.TxOutput{{Address: "addr1a", Lovelace: "1000000"}},
	}
	if !e.EvaluateTx(h, ok).Allow {
		t.Fatalf("expected allow: outputs plus fee within max_total_out_ada")
	}
}

func TestEvaluateTx_MaxFeeAda(t *testing.T) {
	e, h := engineWith(t, KeyPolicy{
		AllowedRequests: []string{"tx"},
		Tx:              &TxPolicy{MaxFeeAda: 2}, // 2 ADA fee cap
	})
	if e.EvaluateTx(h, &bursa.TxInspection{Fee: "2000001"}).Allow {
		t.Fatalf("expected deny: fee exceeds max_fee_ada")
	}
	if !e.EvaluateTx(h, &bursa.TxInspection{Fee: "2000000"}).Allow {
		t.Fatalf("expected allow: fee at exactly max_fee_ada")
	}
}

func TestEvaluateTx_UnparseableFeeDenied(t *testing.T) {
	e, h := engineWith(t, KeyPolicy{AllowedRequests: []string{"tx"}, Tx: &TxPolicy{}})
	if e.EvaluateTx(h, &bursa.TxInspection{Fee: "not-a-number"}).Allow {
		t.Fatalf("expected deny: unparseable fee must fail closed")
	}
}

func TestEvaluateTx_MultiAssetDeniedByDefault(t *testing.T) {
	withAssets := &bursa.TxInspection{Outputs: []bursa.TxOutput{
		{Address: "addr1a", Lovelace: "1000000", HasAssets: true},
	}}
	// Default policy: native-asset movement must be denied.
	e, h := engineWith(t, KeyPolicy{AllowedRequests: []string{"tx"}, Tx: &TxPolicy{}})
	if e.EvaluateTx(h, withAssets).Allow {
		t.Fatalf("expected deny: native assets not allowed by default")
	}
	// Explicit opt-in allows it.
	e2, h2 := engineWith(t, KeyPolicy{
		AllowedRequests: []string{"tx"},
		Tx:              &TxPolicy{AllowMultiAsset: true},
	})
	if !e2.EvaluateTx(h2, withAssets).Allow {
		t.Fatalf("expected allow: allow_multi_asset opts in")
	}
}

func TestEvaluateTx_GovernanceDeniedByDefault(t *testing.T) {
	e, h := engineWith(t, KeyPolicy{AllowedRequests: []string{"tx"}, Tx: &TxPolicy{}})
	if e.EvaluateTx(h, &bursa.TxInspection{VotingProcedureCount: 1}).Allow {
		t.Fatalf("expected deny: voting procedures not allowed by default")
	}
	if e.EvaluateTx(h, &bursa.TxInspection{ProposalProcedureCount: 1}).Allow {
		t.Fatalf("expected deny: proposal procedures not allowed by default")
	}
	if e.EvaluateTx(h, &bursa.TxInspection{HasTreasuryDonation: true}).Allow {
		t.Fatalf("expected deny: treasury donation not allowed by default")
	}

	// Each gate opts in independently.
	eVote, hVote := engineWith(t, KeyPolicy{
		AllowedRequests: []string{"tx"},
		Tx:              &TxPolicy{AllowVotes: true},
	})
	if !eVote.EvaluateTx(hVote, &bursa.TxInspection{VotingProcedureCount: 1}).Allow {
		t.Fatalf("expected allow: allow_votes opts in")
	}
	eProp, hProp := engineWith(t, KeyPolicy{
		AllowedRequests: []string{"tx"},
		Tx:              &TxPolicy{AllowProposals: true},
	})
	if !eProp.EvaluateTx(hProp, &bursa.TxInspection{ProposalProcedureCount: 1}).Allow {
		t.Fatalf("expected allow: allow_proposals opts in")
	}
	eTreas, hTreas := engineWith(t, KeyPolicy{
		AllowedRequests: []string{"tx"},
		Tx:              &TxPolicy{AllowTreasury: true},
	})
	if !eTreas.EvaluateTx(hTreas, &bursa.TxInspection{HasTreasuryDonation: true}).Allow {
		t.Fatalf("expected allow: allow_treasury opts in")
	}
}

func TestEvaluateTx_DenyNilTxPolicy(t *testing.T) {
	e, h := engineWith(t, KeyPolicy{
		AllowedRequests: []string{"tx"},
		Tx:              nil,
	})
	if e.EvaluateTx(h, &bursa.TxInspection{}).Allow {
		t.Fatalf("expected deny: tx in allowed_requests but Tx policy is nil")
	}
}

func TestEvaluateCIP8(t *testing.T) {
	e, h := engineWith(t, KeyPolicy{
		AllowedRequests: []string{"cip8"},
		CIP8:            &CIP8Policy{MaxPayloadBytes: 16, RequireAddressMatch: true},
	})
	if e.EvaluateCIP8(h, 32, true).Allow {
		t.Fatalf("expected deny: payload too large")
	}
	if e.EvaluateCIP8(h, 8, false).Allow {
		t.Fatalf("expected deny: address mismatch required")
	}
	if !e.EvaluateCIP8(h, 8, true).Allow {
		t.Fatalf("expected allow")
	}
	// key with cip8 not allowed
	e2, h2 := engineWith(t, KeyPolicy{AllowedRequests: []string{"tx"}, CIP8: &CIP8Policy{}})
	if e2.EvaluateCIP8(h2, 1, true).Allow {
		t.Fatalf("expected deny: cip8 not in allowed_requests")
	}
}
