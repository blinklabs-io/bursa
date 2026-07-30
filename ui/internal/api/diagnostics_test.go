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
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/diagnostics"
)

type fakeDiagnostics struct {
	report      diagnostics.Report
	logAvail    bool
	zipBytes    []byte
	zipErr      error
	reportCalls int
}

func (f *fakeDiagnostics) Report(context.Context) diagnostics.Report {
	f.reportCalls++
	return f.report
}
func (f *fakeDiagnostics) LogAvailable() bool { return f.logAvail }
func (f *fakeDiagnostics) WriteLogsZip(w io.Writer) error {
	if f.zipErr != nil {
		return f.zipErr
	}
	_, _ = w.Write(f.zipBytes)
	return nil
}

// diagHandler builds a handler wired only with a diagnostics provider (the rest
// are the shared fakes). st drives the (deliberately absent) gate so the test
// can confirm /diagnostics works in a non-ready state.
func diagHandler(st Statuser, d Diagnostics) http.Handler {
	return NewHandler(
		st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{},
		nil, &fakePoolOps{}, nil, &fakeMultiSig{}, "preview", http.NotFoundHandler(),
		WithDiagnostics(d),
	)
}

func TestDiagnosticsReport(t *testing.T) {
	d := &fakeDiagnostics{report: diagnostics.Report{
		Node:  diagnostics.NodeInfo{Network: "preview", DingoVersion: "v0.66.2"},
		Sync:  diagnostics.SyncInfo{State: "syncing", Tip: 42},
		Peers: diagnostics.PeersInfo{Available: true, Total: 7, Configured: []diagnostics.ConfiguredPeer{}},
	}}
	// A non-ready node: /diagnostics must still respond (it is ungated like
	// /status), which is exactly when a user needs it.
	h := diagHandler(fakeStatuser{}, d)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, localReq(http.MethodGet, "/diagnostics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got diagnostics.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Node.Network != "preview" || got.Sync.State != "syncing" || got.Peers.Total != 7 {
		t.Errorf("unexpected report: %+v", got)
	}
	if d.reportCalls != 1 {
		t.Errorf("Report calls = %d, want 1", d.reportCalls)
	}
}

func TestDiagnosticsLogsExport(t *testing.T) {
	d := &fakeDiagnostics{logAvail: true, zipBytes: []byte("PK\x03\x04zip")}
	h := diagHandler(fakeStatuser{}, d)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, localReq(http.MethodGet, "/diagnostics/logs", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/zip" {
		t.Errorf("Content-Type = %q, want application/zip", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd == "" {
		t.Error("missing Content-Disposition")
	}
	if rec.Body.String() != "PK\x03\x04zip" {
		t.Errorf("unexpected body %q", rec.Body.String())
	}
}

func TestDiagnosticsLogsUnavailable(t *testing.T) {
	d := &fakeDiagnostics{logAvail: false}
	h := diagHandler(fakeStatuser{}, d)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, localReq(http.MethodGet, "/diagnostics/logs", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestDiagnosticsCrossOriginRefused confirms the diagnostics routes inherit the
// mux-wide sameOriginGuard (a non-loopback Host is refused).
func TestDiagnosticsCrossOriginRefused(t *testing.T) {
	h := diagHandler(fakeStatuser{}, &fakeDiagnostics{})
	req := httptest.NewRequest(http.MethodGet, "/diagnostics", nil)
	req.Host = "evil.example"
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}
