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
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// jsonRequest builds a POST as the host clients send it: a JSON body and
// the device's own address in the Host header.
func jsonRequest(path string, body io.Reader) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, body)
	r.Host = Address
	r.Header.Set("Content-Type", "application/json")

	return r
}

// countingChip counts every call that reaches the chip.
type countingChip struct {
	Chip

	calls atomic.Int64
}

func (c *countingChip) Exists(id uint32) (bool, error) {
	c.calls.Add(1)
	return c.Chip.Exists(id)
}

func (c *countingChip) SignEd25519(id uint32, msg []byte) ([]byte, error) {
	c.calls.Add(1)
	return c.Chip.SignEd25519(id, msg)
}

func (c *countingChip) PublicKeyEd25519(id uint32) (ed25519.PublicKey, error) {
	c.calls.Add(1)
	return c.Chip.PublicKeyEd25519(id)
}

func (c *countingChip) GenerateEd25519(id uint32, t bool) error {
	c.calls.Add(1)
	return c.Chip.GenerateEd25519(id, t)
}

func (c *countingChip) ImportEd25519(id uint32, seed []byte, t bool) error {
	c.calls.Add(1)
	return c.Chip.ImportEd25519(id, seed, t)
}

func (c *countingChip) WriteBinary(id uint32, d []byte) error {
	c.calls.Add(1)
	return c.Chip.WriteBinary(id, d)
}

func (c *countingChip) ReadBinary(id uint32) ([]byte, error) {
	c.calls.Add(1)
	return c.Chip.ReadBinary(id)
}

func (c *countingChip) Delete(id uint32) error {
	c.calls.Add(1)
	return c.Chip.Delete(id)
}

// readCounter is a request body that counts reads.
type readCounter struct {
	io.Reader

	reads atomic.Int64
}

func (r *readCounter) Read(p []byte) (int, error) {
	r.reads.Add(1)
	return r.Reader.Read(p)
}

// A page in a browser on the host can send a cross-origin POST with a
// text/plain body, or reach the device under another name by DNS
// rebinding. Both are refused before the body is read or the chip touched.
func TestRoutesRefuseForeignRequests(t *testing.T) {
	t.Parallel()

	handlers := map[string]func(*Service) http.Handler{
		"combined":     (*Service).Handler,
		"signing":      (*Service).SigningHandler,
		"provisioning": (*Service).ProvisioningHandler,
		"wipe":         (*Service).WipeHandler,
	}

	paths := map[string][]string{
		"combined":     {"/v1/inventory", "/v1/sign", "/provision/host-key", "/provision/floor"},
		"signing":      {"/v1/inventory", "/v1/challenge", "/v1/sign", "/v1/signlog"},
		"provisioning": {"/provision/identity", "/provision/host-key", "/provision/reward", "/provision/floor"},
		"wipe":         {"/wipe/objects", "/wipe/device", "/wipe/profile", "/wipe/signlog"},
	}

	cases := []struct {
		name        string
		host        string
		contentType string
		want        int
	}{
		{"text plain", Address, "text/plain", http.StatusUnsupportedMediaType},
		{"form", Address, "application/x-www-form-urlencoded", http.StatusUnsupportedMediaType},
		{"no content type", Address, "", http.StatusUnsupportedMediaType},
		{"lookalike type", Address, "application/jsonp", http.StatusUnsupportedMediaType},
		{"rebound host", "attacker.example", "application/json", http.StatusForbidden},
		{"rebound host with port", "attacker.example:80", "application/json", http.StatusForbidden},
		{"other port", Address + ":8080", "application/json", http.StatusForbidden},
		{"loopback", "127.0.0.1", "application/json", http.StatusForbidden},
		{"empty host", "", "application/json", http.StatusForbidden},
	}

	for name, mk := range handlers {
		for _, path := range paths[name] {
			for _, tc := range cases {
				t.Run(name+path+"/"+tc.name, func(t *testing.T) {
					t.Parallel()

					s, chip := newTestService(t)
					cc := &countingChip{Chip: chip}
					s.chip = cc

					body := &readCounter{Reader: strings.NewReader("{}")}
					r := jsonRequest(path, body)
					r.Host = tc.host
					r.Header.Del("Content-Type")

					if tc.contentType != "" {
						r.Header.Set("Content-Type", tc.contentType)
					}

					w := httptest.NewRecorder()
					mk(s).ServeHTTP(w, r)

					if w.Code != tc.want {
						t.Errorf("status %d, want %d: %s", w.Code, tc.want, w.Body.String())
					}

					if n := cc.calls.Load(); n != 0 {
						t.Errorf("%d chip calls before the request was refused", n)
					}

					if n := body.reads.Load(); n != 0 {
						t.Errorf("body read %d times before the request was refused", n)
					}
				})
			}
		}
	}
}

// The firmware serves plain HTTP at its address, with or without the
// default port, and clients may add a charset parameter.
func TestRoutesAcceptDeviceHostAndJSONParameters(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ host, contentType string }{
		{Address, "application/json"},
		{Address + ":80", "application/json"},
		{Address, "application/json; charset=utf-8"},
		{Address, "Application/JSON"},
	} {
		s, _ := newTestService(t)
		r := jsonRequest("/v1/inventory", strings.NewReader("{}"))
		r.Host = tc.host
		r.Header.Set("Content-Type", tc.contentType)

		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)

		// the empty nonce is refused by the handler itself: the request got
		// past the origin checks
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid nonce") {
			t.Errorf("%q %q: status %d: %s", tc.host, tc.contentType, w.Code, w.Body.String())
		}
	}
}

// Guard fronts the legacy firmware routes, which are not JSON handlers.
func TestGuardRefusesForeignRequests(t *testing.T) {
	t.Parallel()

	var reached atomic.Int64

	h := Guard(Address, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) }))

	do := func(method, host, contentType string) int {
		r := httptest.NewRequest(method, "/reset", strings.NewReader("00"))
		r.Host = host

		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}

		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		return w.Code
	}

	if c := do(http.MethodPost, Address, "text/plain"); c != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain POST: %d", c)
	}

	if c := do(http.MethodPost, "evil.example", "application/json"); c != http.StatusForbidden {
		t.Errorf("foreign host POST: %d", c)
	}

	if c := do(http.MethodGet, "evil.example", ""); c != http.StatusForbidden {
		t.Errorf("foreign host GET: %d", c)
	}

	if n := reached.Load(); n != 0 {
		t.Fatalf("%d refused requests reached the handler", n)
	}

	if c := do(http.MethodPost, Address+":80", "application/json; charset=utf-8"); c != http.StatusOK {
		t.Errorf("valid POST: %d", c)
	}

	if c := do(http.MethodGet, Address, ""); c != http.StatusOK {
		t.Errorf("GET at the device address: %d", c)
	}

	if n := reached.Load(); n != 2 {
		t.Fatalf("%d requests reached the handler, want 2", n)
	}
}
