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
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/ui/internal/connector"
)

// fakeConnectorBackend is a minimal Backend implementation for tests in this package.
type fakeConnectorBackend struct{}

func (f *fakeConnectorBackend) NetworkID() int { return 0 }
func (f *fakeConnectorBackend) Utxos(_ context.Context, _ string, _ *connector.Paginate) ([]string, error) {
	return nil, nil
}
func (f *fakeConnectorBackend) Balance(_ context.Context) (string, error) { return "", nil }
func (f *fakeConnectorBackend) UsedAddresses(_ context.Context, _ *connector.Paginate) ([]string, error) {
	return nil, nil
}
func (f *fakeConnectorBackend) UnusedAddresses(_ context.Context) ([]string, error) { return nil, nil }
func (f *fakeConnectorBackend) ChangeAddress(_ context.Context) (string, error)     { return "", nil }
func (f *fakeConnectorBackend) RewardAddresses(_ context.Context) ([]string, error) { return nil, nil }
func (f *fakeConnectorBackend) Collateral(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}
func (f *fakeConnectorBackend) SignTx(_ context.Context, _ string, _ bool, _ string) (string, error) {
	return "", nil
}
func (f *fakeConnectorBackend) SignData(_, _, _ string) (string, string, error)      { return "", "", nil }
func (f *fakeConnectorBackend) SubmitTx(_ context.Context, _ string) (string, error) { return "", nil }
func (f *fakeConnectorBackend) PubDRepKey(_ string) (string, error)                  { return "", nil }
func (f *fakeConnectorBackend) RegisteredPubStakeKeys(_ string) ([]string, error) {
	return nil, nil
}
func (f *fakeConnectorBackend) UnregisteredPubStakeKeys(_ string) ([]string, error) {
	return nil, nil
}

// newTestService creates a real connector.Service, pairs it with the given
// extensionID, and returns the service along with the bearer token minted.
func newTestService(t *testing.T, extensionID string) (*connector.Service, string) {
	t.Helper()
	svc := connector.NewService(t.TempDir(), &fakeConnectorBackend{}, nil)
	code := svc.BeginPair(extensionID)
	token, err := svc.ConfirmPair(extensionID, code)
	if err != nil {
		t.Fatalf("ConfirmPair: %v", err)
	}
	return svc, token
}

// newOKHandler returns a handler that flips *called to true and responds 200,
// so a test can assert whether the middleware actually passed the request
// through to the next handler.
func newOKHandler(called *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*called = true
		w.WriteHeader(http.StatusOK)
	})
}

// sixDigitRe matches any 6-digit sequence in a string.
var sixDigitRe = regexp.MustCompile(`\b\d{6}\b`)

func TestConnectorPairRoute(t *testing.T) {
	const extID = "chrome-extension://testpair"

	newSvc := func(t *testing.T) *connector.Service {
		t.Helper()
		return connector.NewService(t.TempDir(), &fakeConnectorBackend{}, nil)
	}

	t.Run("initiate: empty code → 202, no code in body", func(t *testing.T) {
		svc := newSvc(t)
		mux := http.NewServeMux()
		registerConnector(mux, svc)

		body := `{"extension_id":"` + extID + `","code":""}`
		req := httptest.NewRequest(http.MethodPost, "/connector/pair", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202", rec.Code)
		}
		// Security: ensure no 6-digit code leaked in response body.
		if sixDigitRe.MatchString(rec.Body.String()) {
			t.Errorf("response body contains a 6-digit code (security leak): %q", rec.Body.String())
		}
		var resp map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("response is not valid JSON: %v", err)
		}
		if resp["status"] != "pending" {
			t.Errorf("status field = %q, want \"pending\"", resp["status"])
		}
	})

	t.Run("confirm: correct code → 200 with non-empty token", func(t *testing.T) {
		svc := newSvc(t)
		mux := http.NewServeMux()
		registerConnector(mux, svc)

		// Learn the code directly (simulates in-app display).
		code := svc.BeginPair(extID)

		body := `{"extension_id":"` + extID + `","code":"` + code + `"}`
		req := httptest.NewRequest(http.MethodPost, "/connector/pair", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
		}
		var resp map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("response is not valid JSON: %v", err)
		}
		if resp["token"] == "" {
			t.Error("expected non-empty token in response, got empty")
		}
	})

	t.Run("confirm: wrong code → 403", func(t *testing.T) {
		svc := newSvc(t)
		mux := http.NewServeMux()
		registerConnector(mux, svc)

		// Start a pair so the extension_id is known to the service.
		svc.BeginPair(extID)

		body := `{"extension_id":"` + extID + `","code":"000000"}`
		req := httptest.NewRequest(http.MethodPost, "/connector/pair", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("malformed JSON → 400", func(t *testing.T) {
		svc := newSvc(t)
		mux := http.NewServeMux()
		registerConnector(mux, svc)

		req := httptest.NewRequest(http.MethodPost, "/connector/pair", strings.NewReader("{bad json"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("empty extension_id → 400", func(t *testing.T) {
		svc := newSvc(t)
		mux := http.NewServeMux()
		registerConnector(mux, svc)

		body := `{"extension_id":"","code":""}`
		req := httptest.NewRequest(http.MethodPost, "/connector/pair", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

// decideWhenPending polls svc.Pending() until at least one request appears (or
// 2 seconds elapse), then calls svc.Decide with the given Decision.
func decideWhenPending(t *testing.T, svc *connector.Service, d connector.Decision) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pending := svc.Pending()
		if len(pending) > 0 {
			if err := svc.Decide(pending[0].ID, d); err != nil {
				t.Errorf("Decide: %v", err)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Error("decideWhenPending: no pending request within 2s")
}

// TestConnectorErrorCode unit-tests the connectorErrorCode helper across the
// full method/error matrix without any HTTP layer.
func TestConnectorErrorCode(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		err        error
		wantStatus int
		wantCode   int
		wantInfo   string
	}{
		// ErrNotGranted → 403, -3
		{"ErrNotGranted/getBalance", "getBalance", connector.ErrNotGranted, 403, -3, "connector: origin not granted"},
		// ErrRefused → 403, -3
		{"ErrRefused/unknown", "unknown", connector.ErrRefused, 403, -3, "connector: refused"},
		// ErrTimeout → 408, -3
		{"ErrTimeout", "signTx", connector.ErrTimeout, 408, -3, "request timed out"},
		// ErrUserDeclined by method
		{"ErrUserDeclined/signData", "signData", connector.ErrUserDeclined, 403, 3, "connector: user declined"},
		{"ErrUserDeclined/signTx", "signTx", connector.ErrUserDeclined, 403, 2, "connector: user declined"},
		{"ErrUserDeclined/submitTx", "submitTx", connector.ErrUserDeclined, 403, 1, "connector: user declined"},
		{"ErrUserDeclined/other", "enable", connector.ErrUserDeclined, 403, -3, "connector: user declined"},
		// internal error → 500, -2
		{"internalError", "getBalance", errors.New("boom"), 500, -2, "boom"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, code, info := connectorErrorCode(tc.method, tc.err)
			if status != tc.wantStatus {
				t.Errorf("httpStatus = %d, want %d", status, tc.wantStatus)
			}
			if code != tc.wantCode {
				t.Errorf("error_code = %d, want %d", code, tc.wantCode)
			}
			if info != tc.wantInfo {
				t.Errorf("info = %q, want %q", info, tc.wantInfo)
			}
		})
	}
}

// TestConnectorRequest tests the POST /connector/request route.
func TestConnectorRequest(t *testing.T) {
	const extID = "chrome-extension://reqtest"

	// newSvcServer creates a paired service and an httptest.Server with
	// registerConnector wired up and the middleware applied. Returns the service,
	// server, and the bearer token.
	newSvcServer := func(t *testing.T) (*connector.Service, *httptest.Server, string) {
		t.Helper()
		svc, token := newTestService(t, extID)
		mux := http.NewServeMux()
		registerConnector(mux, svc)
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		return svc, srv, token
	}

	// post sends a POST /connector/request with the given JSON body (no auth headers).
	// The returned *http.Response body is already read and closed.
	postRequest := func(t *testing.T, srv *httptest.Server, token, body string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/connector/request", strings.NewReader(body))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", extID)
		req.Header.Set("X-Bursa-Token", token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		return resp
	}

	t.Run("ungranted origin → 403 error_code -3", func(t *testing.T) {
		_, srv, token := newSvcServer(t)

		body := `{"origin":"https://a.io","method":"getBalance","params":null}`
		resp := postRequest(t, srv, token, body)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
		var out struct {
			ErrorCode int    `json:"error_code"`
			Info      string `json:"info"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if out.ErrorCode != -3 {
			t.Errorf("error_code = %d, want -3", out.ErrorCode)
		}
	})

	t.Run("malformed body → 400 error_code -1", func(t *testing.T) {
		_, srv, token := newSvcServer(t)

		resp := postRequest(t, srv, token, "{bad json")
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
		var out struct {
			ErrorCode int `json:"error_code"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if out.ErrorCode != -1 {
			t.Errorf("error_code = %d, want -1", out.ErrorCode)
		}
	})

	t.Run("empty method → 400 error_code -1", func(t *testing.T) {
		_, srv, token := newSvcServer(t)

		body := `{"origin":"https://a.io","method":"","params":null}`
		resp := postRequest(t, srv, token, body)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
		var out struct {
			ErrorCode int `json:"error_code"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if out.ErrorCode != -1 {
			t.Errorf("error_code = %d, want -1", out.ErrorCode)
		}
	})

	t.Run("enable approved → 200 result true", func(t *testing.T) {
		svc, srv, token := newSvcServer(t)

		// Fire enable in a goroutine (it blocks until decided).
		type result struct {
			resp *http.Response
		}
		ch := make(chan result, 1)
		go func() {
			body := `{"origin":"https://b.io","method":"enable","params":null}`
			resp := postRequest(t, srv, token, body)
			ch <- result{resp: resp}
		}()

		// Wait for the request to appear in the queue, then approve.
		decideWhenPending(t, svc, connector.Decision{Approved: true})

		res := <-ch
		defer res.resp.Body.Close()

		if res.resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", res.resp.StatusCode)
		}
		var out struct {
			Result json.RawMessage `json:"result"`
		}
		if err := json.NewDecoder(res.resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if string(out.Result) != "true" {
			t.Errorf("result = %s, want true", out.Result)
		}
	})

	t.Run("signTx rejected → 403 error_code 2", func(t *testing.T) {
		svc, srv, token := newSvcServer(t)

		// First grant the origin via enable.
		enableDone := make(chan struct{})
		go func() {
			defer close(enableDone)
			body := `{"origin":"https://c.io","method":"enable","params":null}`
			resp := postRequest(t, srv, token, body)
			resp.Body.Close()
		}()
		decideWhenPending(t, svc, connector.Decision{Approved: true})
		<-enableDone

		// Now fire signTx in a goroutine and reject it.
		type result struct {
			resp *http.Response
		}
		ch := make(chan result, 1)
		go func() {
			body := `{"origin":"https://c.io","method":"signTx","params":{"tx":"aabbcc","partialSign":false}}`
			resp := postRequest(t, srv, token, body)
			ch <- result{resp: resp}
		}()

		decideWhenPending(t, svc, connector.Decision{Approved: false})

		res := <-ch
		defer res.resp.Body.Close()

		if res.resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", res.resp.StatusCode)
		}
		var out struct {
			ErrorCode int `json:"error_code"`
		}
		if err := json.NewDecoder(res.resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if out.ErrorCode != 2 {
			t.Errorf("error_code = %d, want 2 (TxSignError.UserDeclined)", out.ErrorCode)
		}
	})
}

// TestConnectorEvents tests GET /connector/events using a real httptest.Server
// (ResponseRecorder cannot flush mid-handler, so a live server is required).
func TestConnectorEvents(t *testing.T) {
	svc := connector.NewService(t.TempDir(), &fakeConnectorBackend{}, nil)

	mux := http.NewServeMux()
	registerConnector(mux, svc)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Use a 3 s deadline so the test cannot hang if something goes wrong.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/connector/events", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want \"text/event-stream\"", ct)
	}

	// Fire enable in a goroutine: it enqueues and blocks until decided.
	// The SSE stream should emit a data event for this pending request.
	go func() {
		//nolint:errcheck // background; we only care about whether a request appears
		svc.Handle(context.Background(), "https://a.io", "enable", nil) //nolint:errcheck
	}()

	// Read the SSE response line-by-line until we see a matching data event or
	// the context deadline expires.
	scanner := bufio.NewScanner(resp.Body)
	found := false
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		// Must contain both "method":"enable" and "origin":"https://a.io".
		if strings.Contains(payload, `"method":"enable"`) && strings.Contains(payload, `"origin":"https://a.io"`) {
			found = true
			break
		}
	}

	if !found {
		t.Error("did not receive expected SSE data event for pending enable request")
	}

	// Clean up: decide the pending request so the goroutine unblocks.
	for _, pending := range svc.Pending() {
		_ = svc.Decide(pending.ID, connector.Decision{Approved: false})
	}
	// cancel() (deferred above) ends the SSE stream.
}

// TestConnectorGrants tests GET /connector/grants, POST /connector/grants/revoke,
// POST /connector/decide, POST /connector/unpair, and the same-origin guard.
func TestConnectorGrants(t *testing.T) {
	const extID = "chrome-extension://granttest"

	newSvc := func(t *testing.T) *connector.Service {
		t.Helper()
		return connector.NewService(t.TempDir(), &fakeConnectorBackend{}, nil)
	}

	// newSvcPaired returns a paired service + its mux.
	newSvcPaired := func(t *testing.T) (*connector.Service, *http.ServeMux) {
		t.Helper()
		svc, _ := newTestService(t, extID)
		mux := http.NewServeMux()
		registerConnector(mux, svc)
		return svc, mux
	}

	t.Run("GET /connector/grants returns grants + paired info", func(t *testing.T) {
		svc, mux := newSvcPaired(t)

		// Grant an origin by doing enable+decide via the service directly.
		done := make(chan struct{})
		go func() {
			defer close(done)
			//nolint:errcheck
			svc.Handle(context.Background(), "https://dapp.io", "enable", nil)
		}()
		decideWhenPending(t, svc, connector.Decision{Approved: true})
		<-done

		req := httptest.NewRequest(http.MethodGet, "/connector/grants", nil)
		// No Origin header → same-origin.
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Origins     []string `json:"origins"`
			Paired      bool     `json:"paired"`
			ExtensionID string   `json:"extension_id"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !resp.Paired {
			t.Error("expected paired = true")
		}
		if resp.ExtensionID != extID {
			t.Errorf("extension_id = %q, want %q", resp.ExtensionID, extID)
		}
		found := false
		for _, o := range resp.Origins {
			if o == "https://dapp.io" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected https://dapp.io in origins, got %v", resp.Origins)
		}
	})

	t.Run("GET /connector/grants unpaired has paired=false and empty extension_id", func(t *testing.T) {
		svc := newSvc(t)
		mux := http.NewServeMux()
		registerConnector(mux, svc)

		req := httptest.NewRequest(http.MethodGet, "/connector/grants", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var resp struct {
			Origins     []string `json:"origins"`
			Paired      bool     `json:"paired"`
			ExtensionID string   `json:"extension_id"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.Paired {
			t.Error("expected paired = false for unpaired service")
		}
		if resp.ExtensionID != "" {
			t.Errorf("extension_id = %q, want empty", resp.ExtensionID)
		}
	})

	t.Run("POST /connector/grants/revoke removes a granted origin", func(t *testing.T) {
		svc, mux := newSvcPaired(t)

		// Grant an origin first.
		done := make(chan struct{})
		go func() {
			defer close(done)
			//nolint:errcheck
			svc.Handle(context.Background(), "https://revoke.io", "enable", nil)
		}()
		decideWhenPending(t, svc, connector.Decision{Approved: true})
		<-done

		// Verify it's granted.
		grants := svc.Grants()
		found := false
		for _, g := range grants {
			if g == "https://revoke.io" {
				found = true
			}
		}
		if !found {
			t.Fatalf("grant not present before revoke: %v", grants)
		}

		body := `{"origin":"https://revoke.io"}`
		req := httptest.NewRequest(http.MethodPost, "/connector/grants/revoke", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
		}
		var resp map[string]bool
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !resp["ok"] {
			t.Error("expected ok=true")
		}
		// Verify revoked.
		for _, g := range svc.Grants() {
			if g == "https://revoke.io" {
				t.Error("origin still present after revoke")
			}
		}
	})

	t.Run("POST /connector/grants/revoke empty origin → 400", func(t *testing.T) {
		_, mux := newSvcPaired(t)

		body := `{"origin":""}`
		req := httptest.NewRequest(http.MethodPost, "/connector/grants/revoke", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("POST /connector/decide unknown id → 404", func(t *testing.T) {
		_, mux := newSvcPaired(t)

		body := `{"id":"no-such-id","approved":true,"password":""}`
		req := httptest.NewRequest(http.MethodPost, "/connector/decide", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404; body: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("POST /connector/decide real pending id → 200, goroutine unblocks", func(t *testing.T) {
		svc, mux := newSvcPaired(t)

		// Enqueue a request via Handle so we get a real pending id.
		enableDone := make(chan error, 1)
		go func() {
			_, err := svc.Handle(context.Background(), "https://decide.io", "enable", nil)
			enableDone <- err
		}()

		// Wait for the request to appear in the queue.
		deadline := time.Now().Add(2 * time.Second)
		var pendingID string
		for time.Now().Before(deadline) {
			p := svc.Pending()
			if len(p) > 0 {
				pendingID = p[0].ID
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if pendingID == "" {
			t.Fatal("no pending request within 2s")
		}

		body := `{"id":"` + pendingID + `","approved":true,"password":""}`
		req := httptest.NewRequest(http.MethodPost, "/connector/decide", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
		}

		// Goroutine should unblock now.
		select {
		case <-enableDone:
			// Good.
		case <-time.After(2 * time.Second):
			t.Error("Handle goroutine did not unblock within 2s after Decide")
		}
	})

	t.Run("POST /connector/decide malformed body → 400", func(t *testing.T) {
		_, mux := newSvcPaired(t)

		req := httptest.NewRequest(http.MethodPost, "/connector/decide", strings.NewReader("{bad json"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("POST /connector/unpair → 200, idempotent", func(t *testing.T) {
		_, mux := newSvcPaired(t)

		for i := 0; i < 2; i++ {
			req := httptest.NewRequest(http.MethodPost, "/connector/unpair", nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("attempt %d: status = %d, want 200; body: %s", i+1, rec.Code, rec.Body.String())
			}
			var resp map[string]bool
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("attempt %d: decode: %v", i+1, err)
			}
			if !resp["ok"] {
				t.Errorf("attempt %d: expected ok=true", i+1)
			}
		}
	})

	t.Run("same-origin guard: cross-origin Origin → 403", func(t *testing.T) {
		_, mux := newSvcPaired(t)

		paths := []struct {
			method string
			path   string
			body   string
		}{
			{http.MethodGet, "/connector/grants", ""},
			{http.MethodPost, "/connector/grants/revoke", `{"origin":"https://x.io"}`},
			{http.MethodPost, "/connector/decide", `{"id":"x","approved":false}`},
			{http.MethodPost, "/connector/unpair", ""},
		}
		for _, p := range paths {
			var bodyReader *strings.Reader
			if p.body != "" {
				bodyReader = strings.NewReader(p.body)
			} else {
				bodyReader = strings.NewReader("")
			}
			req := httptest.NewRequest(p.method, p.path, bodyReader)
			req.Header.Set("Origin", "https://evil.example")
			req.Host = "localhost:8080"
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s %s with evil Origin: status = %d, want 403", p.method, p.path, rec.Code)
			}
		}
	})

	t.Run("same-origin guard: no Origin header → allowed", func(t *testing.T) {
		_, mux := newSvcPaired(t)

		req := httptest.NewRequest(http.MethodGet, "/connector/grants", nil)
		// No Origin header set.
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200 when no Origin header", rec.Code)
		}
	})
}

// TestConnectorSameOriginDNSRebinding verifies the DNS-rebinding defence in
// sameOrigin: a request whose Host resolves to loopback but whose Host header
// is an external domain must be rejected even when Origin matches that domain.
func TestConnectorSameOriginDNSRebinding(t *testing.T) {
	_, mux := func() (*connector.Service, *http.ServeMux) {
		svc, _ := newTestService(t, "chrome-extension://rebindtest")
		m := http.NewServeMux()
		registerConnector(m, svc)
		return svc, m
	}()

	// A DNS-rebound host: Host: evil.com:8090 with matching Origin.
	// The same-origin exact-match would pass (Origin == "http://evil.com:8090"),
	// but the loopback guard must reject it because evil.com is not loopback.
	req := httptest.NewRequest(http.MethodGet, "/connector/grants", nil)
	req.Host = "evil.com:8090"
	req.Header.Set("Origin", "http://evil.com:8090")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("DNS-rebind: status = %d, want 403 (got body: %s)", rec.Code, rec.Body.String())
	}

	// Loopback host on any port must still pass.
	for _, tc := range []struct {
		host   string
		origin string
	}{
		{"127.0.0.1:9999", "http://127.0.0.1:9999"},
		{"localhost:8080", "http://localhost:8080"},
		{"[::1]:4242", "http://[::1]:4242"},
	} {
		req2 := httptest.NewRequest(http.MethodGet, "/connector/grants", nil)
		req2.Host = tc.host
		req2.Header.Set("Origin", tc.origin)
		rec2 := httptest.NewRecorder()
		mux.ServeHTTP(rec2, req2)
		if rec2.Code != http.StatusOK {
			t.Errorf("loopback host=%q origin=%q: status = %d, want 200",
				tc.host, tc.origin, rec2.Code)
		}
	}
}

// TestIsLoopbackHost unit-tests the isLoopbackHost helper directly.
func TestIsLoopbackHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.1:8080", true},
		{"localhost", true},
		{"localhost:9000", true},
		{"::1", true},
		{"[::1]", true},
		{"[::1]:4242", true},
		{"LOCALHOST", true},       // case-insensitive
		{"127.0.0.1:65535", true}, // high port
		{"evil.com", false},
		{"evil.com:8090", false},
		{"10.0.0.1", false},
		{"192.168.1.1:8080", false},
		{"", false},
	}
	for _, tc := range cases {
		got := isLoopbackHost(tc.host)
		if got != tc.want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestConnectorMiddleware(t *testing.T) {
	const extID = "chrome-extension://abc123"
	svc, token := newTestService(t, extID)

	paired := func() (string, bool) { return svc.PairedExtensionID() }
	mw := connectorMiddleware(svc, paired)

	tests := []struct {
		name       string
		method     string
		path       string
		origin     string
		tokenHdr   string
		wantStatus int
		// optional header assertions
		wantCORSOrigin string // non-empty → check Access-Control-Allow-Origin
		wantNextCalled bool   // middleware should have called okHandler
	}{
		{
			name:           "valid token and origin reaches next handler",
			method:         http.MethodGet,
			path:           "/connector/utxos",
			origin:         extID,
			tokenHdr:       token,
			wantStatus:     http.StatusOK,
			wantCORSOrigin: extID,
			wantNextCalled: true,
		},
		{
			name:       "missing token returns 401",
			method:     http.MethodGet,
			path:       "/connector/utxos",
			origin:     extID,
			tokenHdr:   "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "wrong token returns 401",
			method:     http.MethodGet,
			path:       "/connector/utxos",
			origin:     extID,
			tokenHdr:   "bad-token",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "wrong origin returns 401",
			method:     http.MethodGet,
			path:       "/connector/utxos",
			origin:     "chrome-extension://evil",
			tokenHdr:   token,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:           "OPTIONS preflight returns 204 with CORS headers",
			method:         http.MethodOptions,
			path:           "/connector/utxos",
			origin:         extID,
			tokenHdr:       "",
			wantStatus:     http.StatusNoContent,
			wantCORSOrigin: extID,
		},
		{
			name:           "/connector/pair bypasses token check (no token)",
			method:         http.MethodPost,
			path:           "/connector/pair",
			origin:         extID,
			tokenHdr:       "",
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			// The pair exemption must be an EXACT path match. A crafted path
			// that merely ends in /connector/pair must NOT bypass the token
			// check, or it would widen the unauthenticated surface.
			name:       "crafted suffix path does not bypass token check",
			method:     http.MethodPost,
			path:       "/evil/connector/pair",
			origin:     extID,
			tokenHdr:   "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "pair prefix path does not bypass token check",
			method:     http.MethodPost,
			path:       "/connector/pairXYZ",
			origin:     extID,
			tokenHdr:   "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:           "CORS Allow-Origin header equals paired extension id",
			method:         http.MethodGet,
			path:           "/connector/balance",
			origin:         extID,
			tokenHdr:       token,
			wantStatus:     http.StatusOK,
			wantCORSOrigin: extID,
			wantNextCalled: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.tokenHdr != "" {
				req.Header.Set("X-Bursa-Token", tc.tokenHdr)
			}

			var nextCalled bool
			rec := httptest.NewRecorder()
			mw(newOKHandler(&nextCalled)).ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if nextCalled != tc.wantNextCalled {
				t.Errorf("next handler called = %v, want %v", nextCalled, tc.wantNextCalled)
			}
			if tc.wantCORSOrigin != "" {
				got := rec.Header().Get("Access-Control-Allow-Origin")
				if got != tc.wantCORSOrigin {
					t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, tc.wantCORSOrigin)
				}
			}
		})
	}
}

func TestConnectorMiddlewareNormalizesRawPairedExtensionID(t *testing.T) {
	svc, token := newTestService(t, "abc123")
	paired := func() (string, bool) { return svc.PairedExtensionID() }
	mw := connectorMiddleware(svc, paired)

	var nextCalled bool
	req := httptest.NewRequest(http.MethodGet, "/connector/utxos", nil)
	req.Header.Set("Origin", "chrome-extension://abc123")
	req.Header.Set("X-Bursa-Token", token)
	rec := httptest.NewRecorder()

	mw(newOKHandler(&nextCalled)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if !nextCalled {
		t.Fatal("next handler was not called")
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "chrome-extension://abc123" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want chrome-extension://abc123", got)
	}
}

// TestHandlePendingPairings verifies POST /connector/pending-pairings.
func TestHandlePendingPairings(t *testing.T) {
	const extID = "chrome-extension://pending-pair-test"

	newSvc := func(t *testing.T) *connector.Service {
		t.Helper()
		return connector.NewService(t.TempDir(), &fakeConnectorBackend{}, nil)
	}

	strictReq := func(method string) *http.Request {
		req := httptest.NewRequest(method, "/connector/pending-pairings", nil)
		req.Host = "127.0.0.1:8090"
		req.Header.Set("Origin", "http://127.0.0.1:8090")
		return req
	}

	t.Run("strict same-origin no pending pairings returns empty array", func(t *testing.T) {
		svc := newSvc(t)
		mux := http.NewServeMux()
		registerConnector(mux, svc)

		req := strictReq(http.MethodPost)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var pairings []map[string]string
		if err := json.NewDecoder(rec.Body).Decode(&pairings); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(pairings) != 0 {
			t.Fatalf("want empty array, got %v", pairings)
		}
	})

	t.Run("strict same-origin with pending pairing returns extension_id + code", func(t *testing.T) {
		svc := newSvc(t)
		mux := http.NewServeMux()
		registerConnector(mux, svc)

		code := svc.BeginPair(extID)

		req := strictReq(http.MethodPost)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var pairings []map[string]string
		if err := json.NewDecoder(rec.Body).Decode(&pairings); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(pairings) != 1 {
			t.Fatalf("want 1 pairing, got %d", len(pairings))
		}
		if pairings[0]["extension_id"] != extID {
			t.Errorf("extension_id: want %q, got %q", extID, pairings[0]["extension_id"])
		}
		if pairings[0]["code"] != code {
			t.Errorf("code: want %q, got %q", code, pairings[0]["code"])
		}
	})

	t.Run("no-Origin POST is rejected", func(t *testing.T) {
		svc := newSvc(t)
		mux := http.NewServeMux()
		registerConnector(mux, svc)
		code := svc.BeginPair(extID)

		req := httptest.NewRequest(http.MethodPost, "/connector/pending-pairings", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
		if strings.Contains(rec.Body.String(), code) {
			t.Fatalf("response leaked pairing code %q: %s", code, rec.Body.String())
		}
	})

	t.Run("no-Origin GET does not expose pairing code", func(t *testing.T) {
		svc := newSvc(t)
		mux := http.NewServeMux()
		registerConnector(mux, svc)
		code := svc.BeginPair(extID)

		req := httptest.NewRequest(http.MethodGet, "/connector/pending-pairings", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code == http.StatusOK {
			t.Fatalf("GET status = 200, want non-200")
		}
		if strings.Contains(rec.Body.String(), code) {
			t.Fatalf("GET response leaked pairing code %q: %s", code, rec.Body.String())
		}
	})

	t.Run("cross-origin request is rejected with 403", func(t *testing.T) {
		svc := newSvc(t)
		mux := http.NewServeMux()
		registerConnector(mux, svc)

		req := httptest.NewRequest(http.MethodPost, "/connector/pending-pairings", nil)
		req.Host = "127.0.0.1:8090"
		req.Header.Set("Origin", "https://evil.example.com")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})
}
