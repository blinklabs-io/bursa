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

package device

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var provisioningPaths = []string{
	"/provision/identity", "/provision/cold", "/provision/profile",
	"/provision/reward", "/provision/floor",
}

func serve(h http.Handler, path, body string) int {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))

	return w.Code
}

// The signing build serves no provisioning endpoint, so a process on the host
// cannot re-pin the reward account, move the floor or fill key objects.
func TestSigningHandlerServesNoProvisioning(t *testing.T) {
	t.Parallel()

	s, _ := newTestService(t)
	h := s.SigningHandler()

	for _, path := range provisioningPaths {
		if code := serve(h, path, "{}"); code != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404", path, code)
		}
	}

	for _, path := range []string{"/v1/inventory", "/v1/sign"} {
		if code := serve(h, path, "{}"); code == http.StatusNotFound {
			t.Errorf("%s: not served", path)
		}
	}
}

func TestProvisioningHandlerServesNoSigning(t *testing.T) {
	t.Parallel()

	s, _ := newTestService(t)
	h := s.ProvisioningHandler()

	for _, path := range []string{"/v1/inventory", "/v1/sign"} {
		if code := serve(h, path, "{}"); code != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404", path, code)
		}
	}

	for _, path := range provisioningPaths {
		if code := serve(h, path, "{}"); code == http.StatusNotFound {
			t.Errorf("%s: not served", path)
		}
	}
}
