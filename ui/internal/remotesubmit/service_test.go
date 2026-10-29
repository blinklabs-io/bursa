package remotesubmit

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/connector"
	"github.com/blinklabs-io/bursa/ui/internal/spend"
)

type fakeSubmitter struct {
	mu            sync.Mutex
	decode        spend.TxSummary
	err           error
	submits       int
	submitEntered chan struct{}
}

func (f *fakeSubmitter) DecodeTx(context.Context, string) (spend.TxSummary, error) {
	return f.decode, f.err
}

func (f *fakeSubmitter) SubmitTxCbor(ctx context.Context, _ string) (spend.TxResult, error) {
	if f.submitEntered != nil {
		close(f.submitEntered)
		<-ctx.Done()
		return spend.TxResult{}, ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.submits++
	return spend.TxResult{TxHash: "abc123"}, f.err
}

func (f *fakeSubmitter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.submits
}

type fakeApprover struct {
	err     error
	entered chan struct{}
	release chan struct{}
}

func (a *fakeApprover) ApproveSubmission(ctx context.Context, _ string, _ json.RawMessage, submit func(context.Context) (string, error)) (string, error) {
	if a.entered != nil {
		close(a.entered)
	}
	if a.release != nil {
		select {
		case <-a.release:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if a.err != nil {
		return "", a.err
	}
	return submit(ctx)
}

func newTestService(t *testing.T, approver Approver) (*Service, *fakeSubmitter) {
	t.Helper()
	submitter := &fakeSubmitter{decode: spend.TxSummary{IsComplete: true}}
	svc, err := New(t.TempDir()+"/state.json", "https://wallet.example:8443", submitter, approver)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc, submitter
}

func endpointPath(t *testing.T, svc *Service) string {
	t.Helper()
	u, err := url.Parse(svc.Status().Endpoint)
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}
	return u.Path
}

func submitRequest(path string, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/cbor")
	req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	return req
}

func TestDisabledAndUnauthorizedRequestsFailBeforeReadingOrSubmitting(t *testing.T) {
	svc, submitter := newTestService(t, &fakeApprover{})
	validToken := strings.Repeat("a", 64)

	for name, path := range map[string]string{
		"disabled":     "/" + validToken + "/api/submit/tx",
		"unknown path": "/api/submit/tx",
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			svc.ServeHTTP(rec, submitRequest(path, "tx"))
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", rec.Code)
			}
		})
	}

	if _, err := svc.Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	wrong := "/" + strings.Repeat("b", 64) + "/api/submit/tx"
	rec := httptest.NewRecorder()
	svc.ServeHTTP(rec, submitRequest(wrong, "tx"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unauthorized status = %d, want 404", rec.Code)
	}
	if submitter.count() != 0 {
		t.Fatal("unauthorized request reached submitter")
	}
}

func TestSubmissionRequiresTLSAndBoundedCBOR(t *testing.T) {
	svc, submitter := newTestService(t, &fakeApprover{})
	if _, err := svc.Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	path := endpointPath(t, svc)

	plain := submitRequest(path, "tx")
	plain.TLS = nil
	rec := httptest.NewRecorder()
	svc.ServeHTTP(rec, plain)
	if rec.Code != http.StatusUpgradeRequired {
		t.Fatalf("plaintext status = %d, want 426", rec.Code)
	}

	oversized := submitRequest(path, strings.Repeat("x", MaxTransactionBytes+1))
	rec = httptest.NewRecorder()
	svc.ServeHTTP(rec, oversized)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d, want 413", rec.Code)
	}
	if submitter.count() != 0 {
		t.Fatal("rejected request reached submitter")
	}
}

func TestIncompleteAndUnapprovedTransactionsNeverSubmit(t *testing.T) {
	svc, submitter := newTestService(t, &fakeApprover{err: connector.ErrUserDeclined})
	if _, err := svc.Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	path := endpointPath(t, svc)

	submitter.decode.IsComplete = false
	rec := httptest.NewRecorder()
	svc.ServeHTTP(rec, submitRequest(path, "incomplete"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("incomplete status = %d, want 400", rec.Code)
	}

	submitter.decode.IsComplete = true
	rec = httptest.NewRecorder()
	svc.ServeHTTP(rec, submitRequest(path, "complete"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("declined status = %d, want 403", rec.Code)
	}
	if submitter.count() != 0 {
		t.Fatal("unapproved transaction was submitted")
	}
}

func TestDuplicateTransactionIsRejected(t *testing.T) {
	svc, submitter := newTestService(t, &fakeApprover{})
	if _, err := svc.Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	path := endpointPath(t, svc)
	for i, want := range []int{http.StatusOK, http.StatusConflict} {
		rec := httptest.NewRecorder()
		svc.ServeHTTP(rec, submitRequest(path, "same-transaction"))
		if rec.Code != want {
			t.Fatalf("request %d status = %d, want %d", i+1, rec.Code, want)
		}
	}
	if submitter.count() != 1 {
		t.Fatalf("submit count = %d, want 1", submitter.count())
	}
}

func TestDisableRevokesRequestAwaitingApproval(t *testing.T) {
	approver := &fakeApprover{entered: make(chan struct{}), release: make(chan struct{})}
	svc, submitter := newTestService(t, approver)
	if _, err := svc.Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	path := endpointPath(t, svc)

	done := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		svc.ServeHTTP(rec, submitRequest(path, "pending-transaction"))
		done <- rec.Code
	}()
	<-approver.entered
	if _, err := svc.Disable(); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	close(approver.release)
	if status := <-done; status != http.StatusForbidden {
		t.Fatalf("revoked in-flight status = %d, want 403", status)
	}
	if submitter.count() != 0 {
		t.Fatal("revoked transaction was submitted")
	}
}

func TestDisableCancelsSubmissionThatAlreadyLeftApproval(t *testing.T) {
	svc, submitter := newTestService(t, &fakeApprover{})
	submitter.submitEntered = make(chan struct{})
	if _, err := svc.Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	path := endpointPath(t, svc)

	done := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		svc.ServeHTTP(rec, submitRequest(path, "approved-transaction"))
		done <- rec.Code
	}()
	<-submitter.submitEntered
	if _, err := svc.Disable(); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if status := <-done; status != http.StatusForbidden {
		t.Fatalf("revoked submission status = %d, want 403", status)
	}
	if submitter.count() != 0 {
		t.Fatal("revoked transaction completed submission")
	}
}

func TestEnableAndRotatePersistOnlyCurrentCapability(t *testing.T) {
	path := t.TempDir() + "/state.json"
	submitter := &fakeSubmitter{decode: spend.TxSummary{IsComplete: true}}
	svc, err := New(path, "https://wallet.example", submitter, &fakeApprover{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	first, err := svc.Enable()
	if err != nil {
		t.Fatalf("Enable: %v", err)
	}
	second, err := svc.Rotate()
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if first.Endpoint == second.Endpoint {
		t.Fatal("Rotate retained the old capability")
	}
	reloaded, err := New(path, "https://wallet.example", submitter, &fakeApprover{})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Status().Endpoint != second.Endpoint {
		t.Fatal("reloaded state did not preserve the current capability")
	}
	if _, err := reloaded.Disable(); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if reloaded.Status().Enabled {
		t.Fatal("Disable left service enabled")
	}
	if _, err := reloaded.Rotate(); !errors.Is(err, ErrDisabled) {
		t.Fatalf("Rotate after disable error = %v, want ErrDisabled", err)
	}
}
