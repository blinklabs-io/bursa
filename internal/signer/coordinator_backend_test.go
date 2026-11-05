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
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/policy"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
)

// fakeKey reports its custody backend as "fake".
const resolvedBackend = "fake"

func backendTxCoordinator(t *testing.T, polBackend string) (*Coordinator, *fakeKey) {
	t.Helper()
	k := newFakeKey(t)
	card := fakeCardano{
		insp:      &bursa.TxInspection{TxId: "abc", TTL: 10, Outputs: []bursa.TxOutput{{Address: "addr1ok", Lovelace: "1000000"}}},
		txid:      make([]byte, 32),
		assembled: []byte{0x01, 0x02},
	}
	c, _ := newCoordinator(t, k,
		policy.KeyPolicy{Backend: polBackend, AllowedRequests: []string{"tx"}, Tx: &policy.TxPolicy{}},
		watermark.NewMemWatermark(), card)
	return c, k
}

func TestSignTx_PolicyBackend(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		polBackend string
		wantSigned bool
	}{
		{"matching backend", resolvedBackend, true},
		{"empty backend is not enforced", "", true},
		{"mismatched backend", "vault-prod", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, k := backendTxCoordinator(t, tc.polBackend)
			res, perr, err := c.SignTx(context.Background(), []byte(testTxCbor), testTxEra, []string{k.hash.String()})
			if err != nil {
				t.Fatalf("SignTx: %v", err)
			}
			if tc.wantSigned {
				if len(perr) != 0 || len(res.Witnesses) != 1 {
					t.Fatalf("expected one witness, got res=%+v perr=%+v", res, perr)
				}
				return
			}
			if len(res.Witnesses) != 0 || len(perr) != 1 || perr[0].Code != CodeDenied {
				t.Fatalf("expected one denied signer, got res=%+v perr=%+v", res, perr)
			}
			if !strings.Contains(perr[0].Reason, "backend") {
				t.Fatalf("denial reason does not name the backend: %q", perr[0].Reason)
			}
			if n := k.signCalls.Load(); n != 0 {
				t.Fatalf("custody signing ran %d times for a denied request", n)
			}
		})
	}
}

func TestSignOpCert_PolicyBackend(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		polBackend string
		wantCode   ErrorCode
	}{
		{"matching backend", resolvedBackend, ""},
		{"empty backend is not enforced", "", ""},
		{"mismatched backend", "vault-prod", CodeDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			k := newFakeKey(t)
			k.typ = backend.KeyTypePool
			eng, err := policy.NewEngine([]policy.KeyPolicy{{
				Hash: k.hash.String(), Backend: tc.polBackend, AllowedRequests: []string{"opcert"},
			}})
			if err != nil {
				t.Fatalf("NewEngine: %v", err)
			}
			c := New(Deps{
				Resolver:  backend.NewResolver(fakeBackend{key: k}),
				Policy:    eng,
				Watermark: watermark.NewMemWatermark(),
				WMMode:    watermark.ModeEnforce,
				Cardano:   fakeCardano{},
				Metrics:   NewMetrics(),
			})
			res, code, err := c.SignOpCert(context.Background(), make([]byte, kesVkeySize), 5, 100, k.hash.String())
			if tc.wantCode == "" {
				if err != nil || res == nil {
					t.Fatalf("expected signed opcert, got code=%s err=%v", code, err)
				}
				return
			}
			if err == nil || code != tc.wantCode || res != nil {
				t.Fatalf("expected %s, got res=%v code=%s err=%v", tc.wantCode, res, code, err)
			}
			if !strings.Contains(err.Error(), "backend") {
				t.Fatalf("denial reason does not name the backend: %v", err)
			}
			if n := k.signCalls.Load(); n != 0 {
				t.Fatalf("custody signing ran %d times for a denied request", n)
			}
		})
	}
}

func TestSignCIP8_PolicyBackend(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		polBackend string
		wantCode   ErrorCode
	}{
		{"matching backend", resolvedBackend, ""},
		{"empty backend is not enforced", "", ""},
		{"mismatched backend", "vault-prod", CodeDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pub, priv, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			base := &fakeKey{pub: pub, priv: priv, hash: backend.HashPublicKey(pub)}
			k := &loadedFakeKey{fakeKey: base, lk: &bursa.LoadedKey{SKey: []byte(priv), VKey: pub}}
			eng, err := policy.NewEngine([]policy.KeyPolicy{{
				Hash: base.hash.String(), Backend: tc.polBackend,
				AllowedRequests: []string{"cip8"}, CIP8: &policy.CIP8Policy{MaxPayloadBytes: 64},
			}})
			if err != nil {
				t.Fatalf("NewEngine: %v", err)
			}
			c := New(Deps{Resolver: backend.NewResolver(loadedBackend{k}), Policy: eng, Watermark: watermark.NewMemWatermark(), Cardano: fakeCardano{}})
			res, code, err := c.SignCIP8(context.Background(), []byte("hello"), addrForKey(t, pub), base.hash.String())
			if tc.wantCode == "" {
				if err != nil || res == nil {
					t.Fatalf("expected signed CIP-8, got code=%s err=%v", code, err)
				}
				return
			}
			if err == nil || code != tc.wantCode || res != nil {
				t.Fatalf("expected %s, got res=%v code=%s err=%v", tc.wantCode, res, code, err)
			}
			if !strings.Contains(err.Error(), "backend") {
				t.Fatalf("denial reason does not name the backend: %v", err)
			}
			if n := k.signCalls.Load(); n != 0 {
				t.Fatalf("custody signing ran %d times for a denied request", n)
			}
		})
	}
}
