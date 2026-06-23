package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServesIndexWithCSP(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Bursa Wallet") {
		t.Fatalf("index body unexpected: %s", rec.Body.String())
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != "default-src 'self'" {
		t.Fatalf("CSP = %q, want default-src 'self'", got)
	}
}

func TestSPAFallbackServesIndex(t *testing.T) {
	rec := httptest.NewRecorder()
	// An unknown, file-less path (a client route) must fall back to index.html, not 404.
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/portfolio", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Bursa Wallet") {
		t.Fatalf("SPA fallback failed: code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestNonGetMethodNotAllowed(t *testing.T) {
	// A non-GET request that fell through the API routes must not get HTML.
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/anything", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d, want 405", rec.Code)
	}
}

func TestServesEmbeddedFileDirectly(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/index.html", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /index.html = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != "default-src 'self'" {
		t.Fatalf("CSP = %q, want default-src 'self'", got)
	}
}
