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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/multisig"
	"github.com/blinklabs-io/bursa/ui/internal/spend"
	"github.com/blinklabs-io/bursa/ui/internal/supervisor"
)

// multisigEffectRoutes are the multisig paths that sign or broadcast a
// caller-supplied transaction. Each must refuse an incomplete effect summary
// before the multisig service is reached (which is what unlocks the keystore
// or submits).
var multisigEffectRoutes = []struct {
	name    string
	path    string
	body    string
	reached func(*fakeMultiSig) bool
}{
	{
		name:    "cosign-tx",
		path:    "/wallet/cosign-tx",
		body:    `{"tx_cbor":"84a4","password":"pw"}`,
		reached: func(ms *fakeMultiSig) bool { return ms.gotCosignCBOR != "" || ms.gotCosignPassword != "" },
	},
	{
		name:    "submit-tx",
		path:    "/wallet/submit-tx",
		body:    `{"tx_cbor":"84a4"}`,
		reached: func(ms *fakeMultiSig) bool { return ms.gotSubmitImportCBOR != "" },
	},
	{
		name:    "multisig-sign",
		path:    "/wallet/multisig/sign",
		body:    `{"unsigned_tx_cbor":"84a4","password":"pw"}`,
		reached: func(ms *fakeMultiSig) bool { return ms.gotSignTxCBOR != "" || ms.gotSignPassword != "" },
	},
	{
		name:    "multisig-submit",
		path:    "/wallet/multisig/acct-1/submit",
		body:    `{"unsigned_tx_cbor":"84a4","witnesses":["80"]}`,
		reached: func(ms *fakeMultiSig) bool { return ms.gotSubmitID != "" || ms.gotSubmitTxCBOR != "" },
	},
}

func TestMultisigRoutes_RejectIncompleteEffects(t *testing.T) {
	t.Parallel()
	resolvedInput := []spend.TxSummaryInput{{TxHash: strings.Repeat("a", 64), Index: 1, Resolved: true}}
	totalCollateral := "5000000"
	summaries := map[string]spend.TxSummary{
		"unresolved input": {
			Inputs: []spend.TxSummaryInput{{TxHash: strings.Repeat("a", 64), Index: 1}},
		},
		"unresolved collateral": {
			Inputs:           resolvedInput,
			CollateralInputs: []spend.TxSummaryInput{{TxHash: strings.Repeat("b", 64), Index: 2}},
			TotalCollateral:  &totalCollateral,
		},
		"collateral without total": {
			Inputs:           resolvedInput,
			CollateralInputs: []spend.TxSummaryInput{{TxHash: strings.Repeat("b", 64), Index: 2, Resolved: true}},
		},
		"unsupported effect": {
			UnsupportedEffects: []string{"governance proposal details"},
		},
	}
	for _, route := range multisigEffectRoutes {
		for caseName, summary := range summaries {
			t.Run(route.name+"/"+caseName, func(t *testing.T) {
				t.Parallel()
				ms := &fakeMultiSig{
					inspect: multisig.TxInfo{IsMultiSig: true, Threshold: 1},
				}
				sp := &fakeSpender{decodeResult: summary}
				st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
				h := NewHandler(testSessionToken, st, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, ms, "preview", http.NotFoundHandler())
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, localReq(http.MethodPost, route.path, bytes.NewBufferString(route.body)))
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("%s status = %d, want 400, body=%s", route.name, rec.Code, rec.Body.String())
				}
				if !strings.Contains(rec.Body.String(), "transaction effects are incomplete") {
					t.Errorf("%s body missing effects error: %s", route.name, rec.Body.String())
				}
				if route.reached(ms) {
					t.Errorf("%s reached the multisig service despite incomplete effects", route.name)
				}
			})
		}
	}
}

func TestMultisigRoutes_CompleteEffectsStillProceed(t *testing.T) {
	t.Parallel()
	complete := spend.TxSummary{
		Inputs: []spend.TxSummaryInput{{TxHash: strings.Repeat("a", 64), Index: 1, Resolved: true}},
	}
	for _, route := range multisigEffectRoutes {
		t.Run(route.name, func(t *testing.T) {
			t.Parallel()
			ms := &fakeMultiSig{
				inspect: multisig.TxInfo{IsMultiSig: true, Threshold: 1},
			}
			sp := &fakeSpender{decodeResult: complete}
			st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
			h := NewHandler(testSessionToken, st, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, ms, "preview", http.NotFoundHandler())
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, localReq(http.MethodPost, route.path, bytes.NewBufferString(route.body)))
			if rec.Code != http.StatusOK {
				t.Fatalf("%s status = %d, want 200, body=%s", route.name, rec.Code, rec.Body.String())
			}
			if !route.reached(ms) {
				t.Errorf("%s did not reach the multisig service", route.name)
			}
		})
	}
}

func TestMultisigRoutes_RejectUndecodableTx(t *testing.T) {
	t.Parallel()
	for _, route := range multisigEffectRoutes {
		t.Run(route.name, func(t *testing.T) {
			t.Parallel()
			ms := &fakeMultiSig{
				inspect: multisig.TxInfo{IsMultiSig: true, Threshold: 1},
			}
			sp := &fakeSpender{decodeErr: fmt.Errorf("%w: truncated body", spend.ErrInvalidTx)}
			st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
			h := NewHandler(testSessionToken, st, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, ms, "preview", http.NotFoundHandler())
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, localReq(http.MethodPost, route.path, bytes.NewBufferString(route.body)))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s status = %d, want 400, body=%s", route.name, rec.Code, rec.Body.String())
			}
			if route.reached(ms) {
				t.Errorf("%s reached the multisig service despite a decode failure", route.name)
			}
		})
	}
}
