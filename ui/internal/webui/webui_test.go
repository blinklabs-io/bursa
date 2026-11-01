package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const expectedContentSecurityPolicy = "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'"

func requireFrameProtection(t *testing.T, header http.Header) {
	t.Helper()
	if got := header.Get("Content-Security-Policy"); got != expectedContentSecurityPolicy {
		t.Errorf("CSP = %q, want %q", got, expectedContentSecurityPolicy)
	}
	if got := header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
}

func TestServesIndexWithCSP(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Bursa Wallet") {
		t.Fatalf("index body unexpected: %s", rec.Body.String())
	}
	requireFrameProtection(t, rec.Header())
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

func TestFrameProtectionHeaders(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{name: "root", method: http.MethodGet, path: "/"},
		{name: "direct index", method: http.MethodGet, path: "/index.html"},
		{name: "SPA fallback", method: http.MethodGet, path: "/portfolio"},
		{name: "head", method: http.MethodHead, path: "/"},
		{name: "method error", method: http.MethodPost, path: "/wallet/anything"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			Handler().ServeHTTP(rec, httptest.NewRequest(test.method, test.path, nil))

			requireFrameProtection(t, rec.Header())
		})
	}
}

func TestServesEmbeddedFileDirectly(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/index.html", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /index.html = %d, want 200", rec.Code)
	}
	requireFrameProtection(t, rec.Header())
}

// Bursa releases before NFT images were marked no-store served them as
// immutable for a year; every SPA entry response clears that cache.
func TestIndexClearsBrowserCache(t *testing.T) {
	for _, path := range []string{"/", "/index.html", "/portfolio"} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if got := rec.Header().Get("Clear-Site-Data"); got != `"cache"` {
				t.Fatalf("Clear-Site-Data = %q, want %q", got, `"cache"`)
			}
		})
	}
}
