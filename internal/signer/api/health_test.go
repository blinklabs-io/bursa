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
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func do(t *testing.T, h http.Handler, path string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code
}

func TestHealthHandler_LivenessAlwaysOK(t *testing.T) {
	// Liveness is static 200 even when the readiness dependency is failing.
	h := HealthHandler(func(context.Context) error { return errors.New("down") })
	if code := do(t, h, "/healthz"); code != http.StatusOK {
		t.Fatalf("/healthz: got %d, want 200", code)
	}
}

func TestHealthHandler_ReadyzUnavailableWhenStorePingFails(t *testing.T) {
	h := HealthHandler(func(context.Context) error { return errors.New("watermark store unreachable") })
	if code := do(t, h, "/readyz"); code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz with failing store: got %d, want 503", code)
	}
}

func TestHealthHandler_ReadyzOKWhenStoreHealthy(t *testing.T) {
	h := HealthHandler(func(context.Context) error { return nil })
	if code := do(t, h, "/readyz"); code != http.StatusOK {
		t.Fatalf("/readyz healthy: got %d, want 200", code)
	}
}

func TestHealthHandler_ReadyzOKWhenNoCheck(t *testing.T) {
	// A nil check means no dependency to verify (e.g. mem store): always ready.
	h := HealthHandler(nil)
	if code := do(t, h, "/readyz"); code != http.StatusOK {
		t.Fatalf("/readyz with nil check: got %d, want 200", code)
	}
}
