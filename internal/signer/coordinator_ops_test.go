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
	"errors"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/policy"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
)

// coordForEngine wires a coordinator around a caller-provided engine and card.
func coordForEngine(t *testing.T, k *fakeKey, eng *policy.Engine, card fakeCardano, hook PolicyHook) *Coordinator {
	t.Helper()
	return New(Deps{
		Resolver:   backend.NewResolver(fakeBackend{key: k}),
		Policy:     eng,
		Watermark:  watermark.NewMemWatermark(),
		WMMode:     watermark.ModeEnforce,
		Cardano:    card,
		PolicyHook: hook,
	})
}

// TestSignTx_CallerOverride verifies the per-caller override reaches the engine
// through the request context: caller "bob" is denied a cert tx the base policy
// (and caller "alice") allow.
func TestSignTx_CallerOverride(t *testing.T) {
	k := newFakeKey(t)
	base := policy.KeyPolicy{
		Hash:            k.hash.String(),
		AllowedRequests: []string{"tx"},
		Tx:              &policy.TxPolicy{AllowCertificates: true},
	}
	eng, err := policy.NewEngine([]policy.KeyPolicy{base})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	eng.SetCallerPolicies(map[string]map[backend.KeyHash]*policy.CallerTxOverride{
		"bob": {k.hash: {ForbidCertificates: true}},
	})
	card := fakeCardano{
		insp:      &bursa.TxInspection{TxId: "abc", CertificateCount: 1},
		ops:       policy.TxOps{Certificates: []string{policy.CertStakeDelegation}},
		txid:      make([]byte, 32),
		assembled: []byte{0x01},
	}
	c := coordForEngine(t, k, eng, card, nil)

	// alice: allowed by base policy.
	res, perr, err := c.SignTx(WithCaller(context.Background(), "alice"), []byte(testTxCbor), testTxEra, []string{k.hash.String()})
	if err != nil {
		t.Fatalf("SignTx(alice): %v", err)
	}
	if len(perr) != 0 || len(res.Witnesses) != 1 {
		t.Fatalf("alice expected 1 witness, no errors; got perr=%+v wits=%d", perr, len(res.Witnesses))
	}

	// bob: denied by the caller override.
	res, perr, err = c.SignTx(WithCaller(context.Background(), "bob"), []byte(testTxCbor), testTxEra, []string{k.hash.String()})
	if err != nil {
		t.Fatalf("SignTx(bob): %v", err)
	}
	if len(res.Witnesses) != 0 || len(perr) != 1 || perr[0].Code != CodeDenied {
		t.Fatalf("bob expected one denied signer, got res=%+v perr=%+v", res, perr)
	}
}

// TestSignTx_OperationsError confirms an undecodable operation set fails the
// request closed (bad request), never signing.
func TestSignTx_OperationsError(t *testing.T) {
	k := newFakeKey(t)
	pol := policy.KeyPolicy{Hash: k.hash.String(), AllowedRequests: []string{"tx"}, Tx: &policy.TxPolicy{}}
	eng, err := policy.NewEngine([]policy.KeyPolicy{pol})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	card := fakeCardano{
		insp:   &bursa.TxInspection{TxId: "abc"},
		opsErr: errors.New("cannot decode operations"),
		txid:   make([]byte, 32),
	}
	c := coordForEngine(t, k, eng, card, nil)
	_, _, err = c.SignTx(context.Background(), []byte(testTxCbor), testTxEra, []string{k.hash.String()})
	if err == nil || !IsBadRequest(err) {
		t.Fatalf("expected bad-request hard error on operations decode failure, got %v", err)
	}
}

type stubHook struct{ err error }

func (h stubHook) Authorize(context.Context, OperationSummary) error { return h.err }

type recordingHook struct {
	calls   int
	summary OperationSummary
}

func (h *recordingHook) Authorize(_ context.Context, summary OperationSummary) error {
	h.calls++
	h.summary = summary
	return nil
}

// TestSignTx_PolicyHook confirms the hook gates signing after static policy:
// an allow response signs; a deny/error response fails closed.
func TestSignTx_PolicyHook(t *testing.T) {
	newCoord := func(t *testing.T, hook PolicyHook) (*Coordinator, *fakeKey) {
		k := newFakeKey(t)
		pol := policy.KeyPolicy{
			Hash:            k.hash.String(),
			AllowedRequests: []string{"tx"},
			Tx:              &policy.TxPolicy{},
		}
		eng, err := policy.NewEngine([]policy.KeyPolicy{pol})
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
		card := fakeCardano{
			insp:      &bursa.TxInspection{TxId: "abc"},
			txid:      make([]byte, 32),
			assembled: []byte{0x01},
		}
		return coordForEngine(t, k, eng, card, hook), k
	}

	t.Run("allow", func(t *testing.T) {
		c, k := newCoord(t, stubHook{err: nil})
		res, perr, err := c.SignTx(context.Background(), []byte(testTxCbor), testTxEra, []string{k.hash.String()})
		if err != nil {
			t.Fatalf("SignTx: %v", err)
		}
		if len(perr) != 0 || len(res.Witnesses) != 1 {
			t.Fatalf("hook-allow expected 1 witness, got perr=%+v wits=%d", perr, len(res.Witnesses))
		}
	})

	t.Run("deny fails closed", func(t *testing.T) {
		c, k := newCoord(t, stubHook{err: errors.New("hook says no")})
		res, perr, err := c.SignTx(context.Background(), []byte(testTxCbor), testTxEra, []string{k.hash.String()})
		if err != nil {
			t.Fatalf("SignTx: %v", err)
		}
		if len(res.Witnesses) != 0 || len(perr) != 1 || perr[0].Code != CodeDenied {
			t.Fatalf("hook-deny expected one denied signer, got res=%+v perr=%+v", res, perr)
		}
	})
}

func TestSignTx_PolicyHookReceivesTransactionEffects(t *testing.T) {
	k := newFakeKey(t)
	eng, err := policy.NewEngine([]policy.KeyPolicy{{
		Hash:            k.hash.String(),
		AllowedRequests: []string{"tx"},
		Tx: &policy.TxPolicy{
			AllowCertificates:         true,
			AllowMint:                 true,
			AllowWithdrawals:          true,
			AllowMultiAsset:           true,
			AllowVotes:                true,
			AllowProposals:            true,
			AllowTreasury:             true,
			RequireValidityUpperBound: true,
		},
	}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	card := fakeCardano{
		insp: &bursa.TxInspection{
			TxId:                   "abc",
			Fee:                    "170000",
			TTL:                    42,
			Outputs:                []bursa.TxOutput{{Address: "addr1x", Lovelace: "1000000", HasAssets: true}},
			CertificateCount:       1,
			WithdrawalCount:        2,
			HasMint:                true,
			VotingProcedureCount:   1,
			ProposalProcedureCount: 2,
			HasTreasuryDonation:    true,
		},
		ops: policy.TxOps{
			Certificates: []string{policy.CertStakeDelegation},
			Voters:       []policy.VoterInfo{{Kind: policy.VoterDrepKey, DrepId: "beef"}},
		},
		txid:      make([]byte, 32),
		assembled: []byte{0x01},
	}
	hook := &recordingHook{}
	c := coordForEngine(t, k, eng, card, hook)

	res, perr, err := c.SignTx(WithCaller(context.Background(), "alice"), []byte(testTxCbor), testTxEra, []string{k.hash.String()})
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}
	if len(perr) != 0 || len(res.Witnesses) != 1 {
		t.Fatalf("expected one witness and no signer errors, got perr=%+v wits=%d", perr, len(res.Witnesses))
	}
	if hook.calls != 1 {
		t.Fatalf("expected one policy hook call, got %d", hook.calls)
	}
	sum := hook.summary
	if sum.Caller != "alice" || sum.TxID != "abc" || sum.Fee != "170000" || sum.TTL != 42 {
		t.Fatalf("unexpected base summary: %+v", sum)
	}
	if len(sum.Outputs) != 1 || !sum.Outputs[0].HasAssets {
		t.Fatalf("expected native-asset output in summary, got %+v", sum.Outputs)
	}
	if sum.CertificateCount != 1 || len(sum.Certificates) != 1 || sum.Certificates[0] != policy.CertStakeDelegation {
		t.Fatalf("unexpected certificate summary: %+v", sum)
	}
	if !sum.HasMint || sum.WithdrawalCount != 2 || sum.VotingProcedureCount != 1 ||
		sum.ProposalProcedureCount != 2 || !sum.HasTreasuryDonation {
		t.Fatalf("missing transaction effects in summary: %+v", sum)
	}
	if len(sum.Voters) != 1 || sum.Voters[0].Kind != policy.VoterDrepKey || sum.Voters[0].DrepID != "beef" {
		t.Fatalf("unexpected paired voter summary: %+v", sum.Voters)
	}
	if len(sum.VoterKinds) != 1 || sum.VoterKinds[0] != policy.VoterDrepKey ||
		len(sum.DrepIds) != 1 || sum.DrepIds[0] != "beef" {
		t.Fatalf("unexpected legacy voter summary: kinds=%v ids=%v", sum.VoterKinds, sum.DrepIds)
	}
}

func TestSignTx_PolicyHookRejectsIncompleteOperations(t *testing.T) {
	k := newFakeKey(t)
	eng, err := policy.NewEngine([]policy.KeyPolicy{{
		Hash:            k.hash.String(),
		AllowedRequests: []string{"tx"},
		Tx:              &policy.TxPolicy{AllowCertificates: true},
	}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	card := fakeCardano{
		insp:      &bursa.TxInspection{TxId: "abc", CertificateCount: 1},
		txid:      make([]byte, 32),
		assembled: []byte{0x01},
	}
	hook := &recordingHook{}
	c := coordForEngine(t, k, eng, card, hook)

	res, perr, err := c.SignTx(context.Background(), []byte(testTxCbor), testTxEra, []string{k.hash.String()})
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}
	if len(res.Witnesses) != 0 || len(perr) != 1 || perr[0].Code != CodeDenied {
		t.Fatalf("incomplete certificate operations must deny signing, got res=%+v perr=%+v", res, perr)
	}
	if hook.calls != 0 {
		t.Fatalf("incomplete certificate operations reached policy hook %d times", hook.calls)
	}
}
