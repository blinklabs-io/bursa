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

func TestCertificateKindName(t *testing.T) {
	if got := CertificateKindName(2); got != CertStakeDelegation {
		t.Fatalf("cert type 2: want %q, got %q", CertStakeDelegation, got)
	}
	if got := CertificateKindName(16); got != CertDrepRegistration {
		t.Fatalf("cert type 16: want %q, got %q", CertDrepRegistration, got)
	}
	// Unknown type must not collide with any real kind (fails closed under gating).
	if got := CertificateKindName(99); got != "unknown_certificate_99" {
		t.Fatalf("unknown cert type: got %q", got)
	}
}

func TestVoterKindName(t *testing.T) {
	if got := VoterKindName(2); got != VoterDrepKey {
		t.Fatalf("voter type 2: want %q, got %q", VoterDrepKey, got)
	}
	if !IsDrepVoterKind(VoterDrepScript) || IsDrepVoterKind(VoterStakingPoolKey) {
		t.Fatalf("IsDrepVoterKind classification wrong")
	}
	if got := VoterKindName(200); got != "unknown_voter_200" {
		t.Fatalf("unknown voter type: got %q", got)
	}
}

// A tx with one certificate; kinds supplied via WithOps.
func certTx() *bursa.TxInspection {
	return &bursa.TxInspection{TTL: 1, CertificateCount: 1}
}

func TestEvaluateTx_CertificateAllowList(t *testing.T) {
	e, h := engineWith(t, KeyPolicy{
		AllowedRequests: []string{"tx"},
		// allow-list mode: only stake_delegation permitted (AllowCertificates left false)
		Tx: &TxPolicy{AllowedCertificates: []string{CertStakeDelegation, CertVoteDelegation}},
	})

	// stake_delegation is listed -> allow
	if d := e.EvaluateTx(h, certTx(), WithOps(TxOps{Certificates: []string{CertStakeDelegation}})); !d.Allow {
		t.Fatalf("expected allow for stake_delegation: %s", d.Reason)
	}
	// pool_retirement is NOT listed -> deny
	if d := e.EvaluateTx(h, certTx(), WithOps(TxOps{Certificates: []string{CertPoolRetirement}})); d.Allow {
		t.Fatalf("expected deny for pool_retirement not in allowed_certificates")
	}
	// mixed: one listed, one not -> deny
	if d := e.EvaluateTx(h, &bursa.TxInspection{TTL: 1, CertificateCount: 2},
		WithOps(TxOps{Certificates: []string{CertStakeDelegation, CertPoolRetirement}})); d.Allow {
		t.Fatalf("expected deny when any cert kind is not permitted")
	}
	// allow-list mode but kinds unavailable (empty ops) -> fail closed
	if d := e.EvaluateTx(h, certTx()); d.Allow {
		t.Fatalf("expected deny: allow-list mode with no decoded kinds must fail closed")
	}
}

func TestEvaluateTx_CertificateAllowAllBoolStillWorks(t *testing.T) {
	e, h := engineWith(t, KeyPolicy{
		AllowedRequests: []string{"tx"},
		Tx:              &TxPolicy{AllowCertificates: true}, // allow-all, no list
	})
	// Any cert kind passes under the allow-all bool.
	if d := e.EvaluateTx(h, certTx(), WithOps(TxOps{Certificates: []string{CertPoolRetirement}})); !d.Allow {
		t.Fatalf("expected allow-all bool to permit any cert: %s", d.Reason)
	}
}

func TestEvaluateTx_CertificateDenyByDefault(t *testing.T) {
	e, h := engineWith(t, KeyPolicy{AllowedRequests: []string{"tx"}, Tx: &TxPolicy{}})
	if d := e.EvaluateTx(h, certTx(), WithOps(TxOps{Certificates: []string{CertStakeDelegation}})); d.Allow {
		t.Fatalf("expected deny-by-default: no bool, no list")
	}
}

func voteTx() *bursa.TxInspection {
	return &bursa.TxInspection{TTL: 1, VotingProcedureCount: 1}
}

func TestEvaluateTx_VoteVoterKindGate(t *testing.T) {
	e, h := engineWith(t, KeyPolicy{
		AllowedRequests: []string{"tx"},
		Tx:              &TxPolicy{AllowedVoterKinds: []string{VoterDrepKey}},
	})
	// DRep voter -> allow
	if d := e.EvaluateTx(h, voteTx(), WithOps(TxOps{Voters: []VoterInfo{{Kind: VoterDrepKey, DrepId: "aa"}}})); !d.Allow {
		t.Fatalf("expected allow for drep_key voter: %s", d.Reason)
	}
	// Staking-pool voter -> deny (not in allowed_voter_kinds)
	if d := e.EvaluateTx(h, voteTx(), WithOps(TxOps{Voters: []VoterInfo{{Kind: VoterStakingPoolKey}}})); d.Allow {
		t.Fatalf("expected deny for staking_pool_key voter")
	}
}

func TestEvaluateTx_VoteDrepIdAllowList(t *testing.T) {
	e, h := engineWith(t, KeyPolicy{
		AllowedRequests: []string{"tx"},
		Tx:              &TxPolicy{AllowedDrepIds: []string{"deadbeef"}},
	})
	// Allowed DRep id -> allow
	if d := e.EvaluateTx(h, voteTx(), WithOps(TxOps{Voters: []VoterInfo{{Kind: VoterDrepKey, DrepId: "deadbeef"}}})); !d.Allow {
		t.Fatalf("expected allow for listed drep id: %s", d.Reason)
	}
	// Different DRep id -> deny
	if d := e.EvaluateTx(h, voteTx(), WithOps(TxOps{Voters: []VoterInfo{{Kind: VoterDrepKey, DrepId: "00"}}})); d.Allow {
		t.Fatalf("expected deny for unlisted drep id")
	}
	// Non-DRep voter under a drep-id list -> deny (no id to match)
	if d := e.EvaluateTx(h, voteTx(), WithOps(TxOps{Voters: []VoterInfo{{Kind: VoterStakingPoolKey}}})); d.Allow {
		t.Fatalf("expected deny for non-drep voter under drep-id allow-list")
	}
}

func TestEvaluateTx_VoteAllowAllBoolStillWorks(t *testing.T) {
	e, h := engineWith(t, KeyPolicy{AllowedRequests: []string{"tx"}, Tx: &TxPolicy{AllowVotes: true}})
	if d := e.EvaluateTx(h, voteTx(), WithOps(TxOps{Voters: []VoterInfo{{Kind: VoterStakingPoolKey}}})); !d.Allow {
		t.Fatalf("expected allow_votes bool to permit any voter: %s", d.Reason)
	}
}

const hashB = "00000000000000000000000000000000000000000000000000000042"

// buildEngineWithOverride wires one key (base policy) plus a per-caller override.
func buildEngineWithOverride(t *testing.T, base KeyPolicy, caller string, ov *CallerTxOverride) (*Engine, backend.KeyHash) {
	t.Helper()
	base.Hash = hashB
	e, err := NewEngine([]KeyPolicy{base})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	h := mustHash(t, hashB)
	e.SetCallerPolicies(map[string]map[backend.KeyHash]*CallerTxOverride{
		caller: {h: ov},
	})
	return e, h
}

func TestEvaluateTx_CallerOverrideNarrows(t *testing.T) {
	// Base policy: up to 100 ADA fee, certs allowed (allow-all).
	base := KeyPolicy{
		AllowedRequests: []string{"tx"},
		Tx:              &TxPolicy{MaxFeeAda: 100, AllowCertificates: true},
	}
	// Caller "bob" is restricted to a 1-ADA fee cap and no certificates.
	ov := &CallerTxOverride{MaxFeeAda: 1, ForbidCertificates: true}
	e, h := buildEngineWithOverride(t, base, "bob", ov)

	feeTx := &bursa.TxInspection{TTL: 1, Fee: "5000000"} // 5 ADA

	// alice (no override) is bounded only by the base policy -> allow.
	if d := e.EvaluateTx(h, feeTx, WithCaller("alice")); !d.Allow {
		t.Fatalf("alice (no override) expected allow: %s", d.Reason)
	}
	// bob's override caps fee at 1 ADA -> deny.
	if d := e.EvaluateTx(h, feeTx, WithCaller("bob")); d.Allow {
		t.Fatalf("bob (override) expected deny on fee cap")
	}
	// bob signing a cert tx -> denied by ForbidCertificates even though base allows.
	if d := e.EvaluateTx(h, &bursa.TxInspection{TTL: 1, CertificateCount: 1},
		WithCaller("bob"), WithOps(TxOps{Certificates: []string{CertStakeDelegation}})); d.Allow {
		t.Fatalf("bob (override) expected deny on forbid_certificates")
	}
	// alice may still sign the cert tx (base allows certs).
	if d := e.EvaluateTx(h, &bursa.TxInspection{TTL: 1, CertificateCount: 1},
		WithCaller("alice"), WithOps(TxOps{Certificates: []string{CertStakeDelegation}})); !d.Allow {
		t.Fatalf("alice expected allow on cert tx: %s", d.Reason)
	}
}

func TestEvaluateTx_CallerOverrideCannotWiden(t *testing.T) {
	// Base policy denies certificates entirely.
	base := KeyPolicy{AllowedRequests: []string{"tx"}, Tx: &TxPolicy{}}
	// A (misguided) override that "allows" a cert kind must NOT grant it, because
	// the base decision is required and already denies.
	ov := &CallerTxOverride{AllowedCertificates: []string{CertStakeDelegation}}
	e, h := buildEngineWithOverride(t, base, "carol", ov)

	if d := e.EvaluateTx(h, &bursa.TxInspection{TTL: 1, CertificateCount: 1},
		WithCaller("carol"), WithOps(TxOps{Certificates: []string{CertStakeDelegation}})); d.Allow {
		t.Fatalf("override must not widen: cert denied by base must stay denied")
	}
}

func TestSetCallerPolicies_ClearAndCopy(t *testing.T) {
	base := KeyPolicy{AllowedRequests: []string{"tx"}, Tx: &TxPolicy{AllowCertificates: true}}
	ov := &CallerTxOverride{ForbidCertificates: true}
	e, h := buildEngineWithOverride(t, base, "dave", ov)

	// Mutating the caller's original override slice/struct must not affect the engine.
	ov.ForbidCertificates = false
	certTxn := &bursa.TxInspection{TTL: 1, CertificateCount: 1}
	if d := e.EvaluateTx(h, certTxn, WithCaller("dave"), WithOps(TxOps{Certificates: []string{CertStakeDelegation}})); d.Allow {
		t.Fatalf("engine must retain deep-copied override (post-mutation)")
	}

	// Clearing overrides restores base behavior (certs allowed).
	e.SetCallerPolicies(nil)
	if d := e.EvaluateTx(h, certTxn, WithCaller("dave"), WithOps(TxOps{Certificates: []string{CertStakeDelegation}})); !d.Allow {
		t.Fatalf("after clearing overrides, base policy should allow certs: %s", d.Reason)
	}
}
