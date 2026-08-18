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
	res, perr, err := c.SignTx(WithCaller(context.Background(), "alice"), []byte("11"), []string{k.hash.String()})
	if err != nil {
		t.Fatalf("SignTx(alice): %v", err)
	}
	if len(perr) != 0 || len(res.Witnesses) != 1 {
		t.Fatalf("alice expected 1 witness, no errors; got perr=%+v wits=%d", perr, len(res.Witnesses))
	}

	// bob: denied by the caller override.
	res, perr, err = c.SignTx(WithCaller(context.Background(), "bob"), []byte("11"), []string{k.hash.String()})
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
	_, _, err = c.SignTx(context.Background(), []byte("11"), []string{k.hash.String()})
	if err == nil || !IsBadRequest(err) {
		t.Fatalf("expected bad-request hard error on operations decode failure, got %v", err)
	}
}

type stubHook struct{ err error }

func (h stubHook) Authorize(context.Context, OperationSummary) error { return h.err }

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
		res, perr, err := c.SignTx(context.Background(), []byte("11"), []string{k.hash.String()})
		if err != nil {
			t.Fatalf("SignTx: %v", err)
		}
		if len(perr) != 0 || len(res.Witnesses) != 1 {
			t.Fatalf("hook-allow expected 1 witness, got perr=%+v wits=%d", perr, len(res.Witnesses))
		}
	})

	t.Run("deny fails closed", func(t *testing.T) {
		c, k := newCoord(t, stubHook{err: errors.New("hook says no")})
		res, perr, err := c.SignTx(context.Background(), []byte("11"), []string{k.hash.String()})
		if err != nil {
			t.Fatalf("SignTx: %v", err)
		}
		if len(res.Witnesses) != 0 || len(perr) != 1 || perr[0].Code != CodeDenied {
			t.Fatalf("hook-deny expected one denied signer, got res=%+v perr=%+v", res, perr)
		}
	})
}
