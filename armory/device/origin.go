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
	"mime"
	"net"
	"net/http"
	"strings"
)

// Address is the device's address on the USB network, the only Host its
// routes answer to.
const Address = "10.0.0.1"

// Guard refuses requests a browser page on the host could send: any request
// whose Host is not host (with or without port 80), which is how DNS
// rebinding reaches the device, and any POST whose Content-Type is not
// application/json, which a cross-origin form or text/plain fetch cannot set
// without a preflight the device does not answer.
func Guard(host string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowed(w, r, host) {
			return
		}

		next.ServeHTTP(w, r)
	})
}

// allowed writes the refusal and returns false when r is not a request the
// host's own clients send.
func allowed(w http.ResponseWriter, r *http.Request, host string) bool {
	if !hostIs(r.Host, host) {
		http.Error(w, "unexpected host", http.StatusForbidden)
		return false
	}

	if r.Method == http.MethodPost && !isJSON(r.Header.Get("Content-Type")) {
		http.Error(
			w,
			"content type must be application/json",
			http.StatusUnsupportedMediaType,
		)
		return false
	}

	return true
}

func hostIs(got, want string) bool {
	if h, port, err := net.SplitHostPort(got); err == nil && port == "80" {
		got = h
	}

	return strings.EqualFold(got, want)
}

func isJSON(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)

	return err == nil && mt == "application/json"
}
