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

package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/operation"
	"github.com/blinklabs-io/bursa/internal/signer/policy"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
)

// summaryKey reports a custody summary for the body it signs.
type summaryKey struct {
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	hash    backend.KeyHash
	summary string
}

func (k *summaryKey) Hash() backend.KeyHash        { return k.hash }
func (k *summaryKey) PublicKey() ed25519.PublicKey { return k.pub }
func (k *summaryKey) Type() backend.KeyType        { return backend.KeyTypePayment }
func (k *summaryKey) Extended() bool               { return false }
func (k *summaryKey) Backend() string              { return "summary" }
func (k *summaryKey) Sign(context.Context, []byte) ([]byte, error) {
	return ed25519.Sign(k.priv, make([]byte, 32)), nil
}

func (k *summaryKey) SignTxBody(ctx context.Context, _ []byte, _ uint) ([]byte, string, error) {
	sig, err := k.Sign(ctx, nil)
	return sig, k.summary, err
}

type summaryBackend struct{ key *summaryKey }

func (summaryBackend) Name() string { return "summary" }
func (b summaryBackend) ListKeys(context.Context) ([]backend.KeyRef, error) {
	return []backend.KeyRef{b.key}, nil
}

func (b summaryBackend) GetKey(context.Context, backend.KeyHash) (backend.KeyRef, error) {
	return b.key, nil
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// TestHandleSignTxAuditsCustodySummary: the audit line of a signed tx request
// carries the summary the custody boundary reported, and the response body
// keeps its shape.
func TestHandleSignTxAuditsCustodySummary(t *testing.T) {
	t.Parallel()
	pub, priv, _ := ed25519.GenerateKey(nil)
	k := &summaryKey{pub: pub, priv: priv, hash: backend.HashPublicKey(pub), summary: "pool retirement: epoch 500"}
	b := summaryBackend{key: k}
	eng, _ := policy.NewEngine([]policy.KeyPolicy{{Hash: k.hash.String(), AllowedRequests: []string{"tx"}, Tx: &policy.TxPolicy{}}})
	coord := signer.New(signer.Deps{
		Resolver:  backend.NewResolver(b),
		Policy:    eng,
		Watermark: watermark.NewMemWatermark(),
		Cardano:   operation.Cardano(fakeCardano{pub: pub}),
	})
	srv := NewServer(coord, backend.NewResolver(b), eng, nil, func(string) (string, error) { return "tester", nil })
	logs := &lockedBuffer{}
	srv.logger = slog.New(slog.NewJSONHandler(logs, nil))

	body, _ := json.Marshal(SignRequest{Type: "tx", Cbor: ambiguousBabbageTxHex, Era: "babbage", Signers: []string{k.hash.String()}})
	rr := httptest.NewRecorder()
	srv.handleSign(rr, httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "summary") {
		t.Fatalf("response carries the summary: %s", rr.Body.String())
	}

	var audit map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if rec["msg"] == "sign request" && rec["outcome"] == "signed" {
			audit = rec
		}
	}
	if audit == nil {
		t.Fatalf("no signed audit line in %s", logs.String())
	}
	if audit["summary"] != k.summary {
		t.Fatalf("audit summary = %v, want %q", audit["summary"], k.summary)
	}
}
