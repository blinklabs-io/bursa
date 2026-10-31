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
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/policy"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
)

// summaryKey is a key whose custody boundary reports a summary of the body it
// signs, as an attested key under protocol version 2 does.
type summaryKey struct {
	*fakeKey
	summary string
}

func (k *summaryKey) SignTxBodySummary(context.Context, []byte, uint) ([]byte, string, error) {
	// fakeCardano reports an all-zero tx id, which the coordinator verifies
	sig, err := k.Sign(context.Background(), make([]byte, 32))
	return sig, k.summary, err
}

type summaryBackend struct{ key *summaryKey }

func (b summaryBackend) Name() string { return "summary" }
func (b summaryBackend) ListKeys(context.Context) ([]backend.KeyRef, error) {
	return []backend.KeyRef{b.key}, nil
}

func (b summaryBackend) GetKey(_ context.Context, h backend.KeyHash) (backend.KeyRef, error) {
	if h == b.key.hash {
		return b.key, nil
	}
	return nil, backend.ErrKeyNotFound
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) lines() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Split(bytes.TrimSpace(s.b.Bytes()), []byte("\n"))
}

func TestSignTx_ReportsCustodySummary(t *testing.T) {
	t.Parallel()
	k := &summaryKey{fakeKey: newFakeKey(t), summary: "pool retirement: epoch 500"}
	eng, err := policy.NewEngine([]policy.KeyPolicy{{Hash: k.hash.String(), AllowedRequests: []string{"tx"}, Tx: &policy.TxPolicy{}}})
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	c := New(Deps{
		Resolver:  backend.NewResolver(summaryBackend{key: k}),
		Policy:    eng,
		Watermark: watermark.NewMemWatermark(),
		Cardano: fakeCardano{
			insp: &bursa.TxInspection{TxId: "abc", TTL: 10}, txid: make([]byte, 32), assembled: []byte{1},
		},
		Metrics: NewMetrics(),
		Logger:  slog.New(slog.NewJSONHandler(logs, nil)),
	})

	res, perr, err := c.SignTx(context.Background(), []byte(testTxCbor), testTxEra, []string{k.hash.String()})
	if err != nil || len(perr) != 0 {
		t.Fatalf("SignTx: %v %+v", err, perr)
	}
	if len(res.Witnesses) != 1 {
		t.Fatalf("witnesses = %d", len(res.Witnesses))
	}
	if len(res.Summaries) != 1 || res.Summaries[0] != k.summary {
		t.Fatalf("summaries = %q, want [%q]", res.Summaries, k.summary)
	}

	var signed map[string]any
	for _, line := range logs.lines() {
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if rec["msg"] == "sign" && rec["result"] == "signed" {
			signed = rec
		}
	}
	if signed == nil {
		t.Fatal("no signed log line")
	}
	if signed["summary"] != k.summary {
		t.Fatalf("signed log line summary = %v, want %q", signed["summary"], k.summary)
	}
}

// A key with no summary adds none to the result or the log line.
func TestSignTx_NoSummaryForPlainKey(t *testing.T) {
	t.Parallel()
	k := newFakeKey(t)
	c, _ := newCoordinator(t, k,
		policy.KeyPolicy{AllowedRequests: []string{"tx"}, Tx: &policy.TxPolicy{}},
		watermark.NewMemWatermark(),
		fakeCardano{insp: &bursa.TxInspection{TxId: "abc", TTL: 10}, txid: make([]byte, 32), assembled: []byte{1}})
	res, perr, err := c.SignTx(context.Background(), []byte(testTxCbor), testTxEra, []string{k.hash.String()})
	if err != nil || len(perr) != 0 || len(res.Witnesses) != 1 {
		t.Fatalf("SignTx: %v %+v %+v", err, perr, res)
	}
	if len(res.Summaries) != 0 {
		t.Fatalf("summaries = %q", res.Summaries)
	}
}
