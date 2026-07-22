// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/spend"
	"github.com/blinklabs-io/bursa/ui/internal/supervisor"
)

// --- fakeSpender extensions for the vkey import-tx endpoints -----------------
//
// The fields these methods read/write are declared on fakeSpender itself (see
// api_test.go) so the many existing call sites that construct a bare
// &fakeSpender{} keep satisfying the extended Spender interface unchanged;
// only the methods live here, next to the tests that exercise them.

func (f *fakeSpender) DecodeTx(txCbor string) (spend.TxSummary, error) {
	f.gotDecodeCBOR = txCbor
	if f.decodeErr != nil {
		return spend.TxSummary{}, f.decodeErr
	}
	return f.decodeResult, nil
}

func (f *fakeSpender) CosignTx(_ context.Context, txCbor, password string, partial bool) (spend.CosignResult, error) {
	f.gotCosignCBOR = txCbor
	f.gotCosignPass = password
	f.gotCosignPartial = partial
	if f.cosignErr != nil {
		return spend.CosignResult{}, f.cosignErr
	}
	return f.cosignResult, nil
}

func (f *fakeSpender) SubmitTxCbor(_ context.Context, txCbor string) (spend.TxResult, error) {
	f.gotSubmitTxCBOR = txCbor
	if f.submitTxErr != nil {
		return spend.TxResult{}, f.submitTxErr
	}
	return f.submitTxResult, nil
}

// --- POST /wallet/decode-tx ---------------------------------------------------

func TestDecodeTxHandler_OK(t *testing.T) {
	sp := &fakeSpender{decodeResult: spend.TxSummary{Kind: "vkey", Fee: "170000"}}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, &fakeMultiSig{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"tx_cbor":"84a4..."}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/decode-tx", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("decode-tx status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"kind":"vkey"`) {
		t.Errorf("body missing kind: %s", rec.Body.String())
	}
	if sp.gotDecodeCBOR != "84a4..." {
		t.Errorf("tx_cbor not passed through: %q", sp.gotDecodeCBOR)
	}
}

func TestDecodeTxHandler_InvalidJSON(t *testing.T) {
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, &fakeMultiSig{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`not json`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/decode-tx", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("decode-tx invalid json = %d, want 400", rec.Code)
	}
}

// --- POST /wallet/cosign-tx ---------------------------------------------------

func TestCosignTxHandler_InvalidTxIs400(t *testing.T) {
	sp := &fakeSpender{cosignErr: fmt.Errorf("%w: bad", spend.ErrInvalidTx)}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, &fakeMultiSig{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"tx_cbor":"zz","password":"p"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/cosign-tx", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("cosign-tx status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestCosignTxHandler_OK_DefaultsPartialSignTrue(t *testing.T) {
	sp := &fakeSpender{cosignResult: spend.CosignResult{TxCBOR: "84...merged"}}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, &fakeMultiSig{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"tx_cbor":"84a4...","password":"pw"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/cosign-tx", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("cosign-tx status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if sp.gotCosignCBOR != "84a4..." || sp.gotCosignPass != "pw" {
		t.Errorf("args not passed through: cbor=%q pass=%q", sp.gotCosignCBOR, sp.gotCosignPass)
	}
	if !sp.gotCosignPartial {
		t.Errorf("partial_sign should default to true when omitted")
	}
	if !strings.Contains(rec.Body.String(), "84...merged") {
		t.Errorf("body missing merged tx_cbor: %s", rec.Body.String())
	}
}

func TestCosignTxHandler_PartialSignFalseIsHonored(t *testing.T) {
	sp := &fakeSpender{}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, &fakeMultiSig{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"tx_cbor":"84a4...","password":"pw","partial_sign":false}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/cosign-tx", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("cosign-tx status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if sp.gotCosignPartial {
		t.Errorf("partial_sign=false should be honored, got true")
	}
}

// --- POST /wallet/submit-tx ---------------------------------------------------

func TestSubmitTxHandler_RequiresReady(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateSyncing}}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, &fakeMultiSig{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"tx_cbor":"84a4..."}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/submit-tx", body))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("submit-tx while syncing = %d, want 503, body=%s", rec.Code, rec.Body.String())
	}
}

func TestSubmitTxHandler_ReturnsTxHash(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	sp := &fakeSpender{submitTxResult: spend.TxResult{TxHash: "cafebabe"}}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, &fakeMultiSig{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"tx_cbor":"84a4..."}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/submit-tx", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("submit-tx = %d, body=%s", rec.Code, rec.Body.String())
	}
	if sp.gotSubmitTxCBOR != "84a4..." {
		t.Errorf("tx_cbor not passed through: %q", sp.gotSubmitTxCBOR)
	}
	if !strings.Contains(rec.Body.String(), "cafebabe") {
		t.Errorf("tx hash missing: %s", rec.Body.String())
	}
}

func TestSubmitTxHandler_InvalidTxIs400(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	sp := &fakeSpender{submitTxErr: fmt.Errorf("%w: bad hex", spend.ErrInvalidTx)}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, &fakeMultiSig{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"tx_cbor":"zz"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/submit-tx", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("submit-tx invalid tx = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}
