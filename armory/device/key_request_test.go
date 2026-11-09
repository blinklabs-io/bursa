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
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// coldResult is a cold key response as a host reads it.
type coldResult struct {
	ColdKeyID uint32 `json:"cold_key_id"`
	PublicKey string `json:"public_key"`
	PoolID    string `json:"pool_id"`
}

// setDeviceHeaders makes r a request the device's host clients send: to the
// device's address, with a JSON body.
func setDeviceHeaders(r *http.Request) {
	r.Host = "10.0.0.1"
	r.Header.Set("Content-Type", "application/json")
}

func postCold(
	t *testing.T,
	s *Service,
	path string,
	req any,
) (int, coldResult, string) {
	t.Helper()

	code, body := post(t, s, path, req)

	var res coldResult
	if code == http.StatusOK {
		if err := json.Unmarshal(body, &res); err != nil {
			t.Fatalf("response %s: %v", body, err)
		}
	}

	return code, res, string(body)
}

// recordingBody is a request body that remembers every buffer it was read
// into.
type recordingBody struct {
	r    io.Reader
	bufs [][]byte
}

func (b *recordingBody) Read(p []byte) (int, error) {
	b.bufs = append(b.bufs, p)
	return b.r.Read(p)
}

func (b *recordingBody) Close() error { return nil }

// The request body buffer holds the cborHex of the key; it is zeroed once the
// request is decoded, whatever the outcome.
func TestProvisioningZeroesRequestBody(t *testing.T) {
	t.Parallel()

	seedHex := hex.EncodeToString(coldSeed)

	for name, tc := range map[string]struct {
		path, body string
	}{
		"cold import": {"/provision/cold", `{"cold_key_id":551878673,"signing_key":"` + coldKeyHex(coldSeed) + `"}`},
		"cold refused": {"/provision/cold",
			`{"cold_key_id":1,"signing_key":"` + coldKeyHex(coldSeed) + `"}`},
		"cold unknown field": {"/provision/cold",
			`{"cold_key_id":551878673,"signing_keys":"` + coldKeyHex(coldSeed) + `"}`},
		"profile owner": {"/provision/profile",
			`{"name":"a@preview","slot":1,"cold_key_id":551878672,"owner_signing_key":"` + coldKeyHex(coldSeed) + `"}`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s, _, _ := newLoggedService(t)
			body := &recordingBody{r: strings.NewReader(tc.body)}

			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			req.Body = body
			setDeviceHeaders(req)
			s.Handler().ServeHTTP(httptest.NewRecorder(), req)

			if len(body.bufs) == 0 {
				t.Fatal("body was never read")
			}

			for i, b := range body.bufs {
				if strings.Contains(string(b), seedHex) ||
					bytes.Contains(b, coldSeed) {
					t.Fatalf(
						"read buffer %d still holds the key after the request",
						i,
					)
				}
			}
		})
	}
}

// secretBytes returns the key field of req as the slice the handler decoded,
// failing when the field is not byte-backed: a Go string cannot be zeroed.
func secretBytes(t *testing.T, req any, field string) []byte {
	t.Helper()

	f := reflect.ValueOf(req).FieldByName(field)
	if f.Kind() != reflect.Slice || f.Type().Elem().Kind() != reflect.Uint8 {
		t.Fatalf(
			"%s is a %s, not a byte slice: its copy of the key cannot be zeroed",
			field,
			f.Kind(),
		)
	}

	return f.Bytes()
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}

	return true
}

// The decoded key fields are cleared after the import, so no copy of the key
// outlives the request.
func TestProvisioningZeroesDecodedKeys(t *testing.T) {
	t.Parallel()

	t.Run("cold", func(t *testing.T) {
		t.Parallel()

		s, _, _ := newLoggedService(t)

		var captured []byte

		mux := http.NewServeMux()
		mux.HandleFunc(
			"POST /c",
			handle(s, func(req ColdRequest) (ColdResponse, error) {
				captured = secretBytes(t, req, "SigningKey")
				if len(captured) == 0 || allZero(captured) {
					t.Error("key field empty before the import")
				}

				return s.provisionCold(req)
			}),
		)

		req := httptest.NewRequest(http.MethodPost, "/c", strings.NewReader(
			`{"cold_key_id":551878673,"signing_key":"`+coldKeyHex(
				coldSeed,
			)+`"}`,
		))
		setDeviceHeaders(req)

		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("%d %s", w.Code, w.Body)
		}

		if !allZero(captured) {
			t.Fatal("decoded signing key not zeroed after the import")
		}
	})

	t.Run("owner", func(t *testing.T) {
		t.Parallel()

		s, _, _ := newLoggedService(t)

		var captured []byte

		mux := http.NewServeMux()
		mux.HandleFunc(
			"POST /p",
			handle(s, func(req ProvisionRequest) (ProvisionResponse, error) {
				captured = secretBytes(t, req, "OwnerSigningKey")
				if len(captured) == 0 || allZero(captured) {
					t.Error("key field empty before the import")
				}

				return s.provisionProfile(req)
			}),
		)

		req := httptest.NewRequest(http.MethodPost, "/p", strings.NewReader(
			`{"name":"a@preview","slot":1,"cold_key_id":`+"551878672"+`,"reward_account":"`+testReward+`","owner_signing_key":"`+coldKeyHex(
				coldSeed,
			)+`"}`,
		))
		setDeviceHeaders(req)

		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("%d %s", w.Code, w.Body)
		}

		if !allZero(captured) {
			t.Fatal("decoded owner key not zeroed after the import")
		}
	})
}

// A key decoded over an earlier one, as from a repeated or case-variant field
// name, zeroes the earlier copy.
func TestSecretHexZeroesReplacedKey(t *testing.T) {
	t.Parallel()

	var h secretHex
	if err := h.UnmarshalJSON([]byte(`"` + coldKeyHex(coldSeed) + `"`)); err != nil {
		t.Fatal(err)
	}

	first := h

	for _, next := range []string{`"5820` + strings.Repeat("00", 32) + `"`, `null`} {
		if err := h.UnmarshalJSON([]byte(next)); err != nil {
			t.Fatal(err)
		}

		if !allZero(first) {
			t.Fatalf("earlier key not zeroed when %s replaced it", next)
		}

		first = h
	}

	if h != nil {
		t.Fatalf("null left %x, want no key", []byte(h))
	}
}

// escapeHex returns s as a JSON string body with every hex digit at an even
// index sent as a \u escape, alternating the case of the escape's digits.
func escapeHex(s string) string {
	var b strings.Builder

	for i, c := range s {
		switch {
		case i%4 == 0:
			fmt.Fprintf(&b, `\u%04x`, c)
		case i%4 == 2:
			fmt.Fprintf(&b, `\u%04X`, c)
		default:
			b.WriteRune(c)
		}
	}

	return b.String()
}

// The key fields are JSON strings, so a hex digit sent as an escape decodes as
// the digit itself.
func TestSecretHexDecodesEscapes(t *testing.T) {
	t.Parallel()

	key := coldKeyHex(coldSeed)

	var h secretHex
	if err := h.UnmarshalJSON([]byte(`"` + escapeHex(key) + `"`)); err != nil {
		t.Fatal(err)
	}

	if got := hex.EncodeToString(h); got != key {
		t.Fatalf("decoded %s, want %s", got, key)
	}

	s, _, _ := newLoggedService(t)

	raw := []byte(
		`{"cold_key_id":551878673,"signing_key":"` + escapeHex(key) + `"}`,
	)
	wire := encryptAdminTestRequest(t, s, RouteProvisionCold, raw)
	req := httptest.NewRequest(
		http.MethodPost,
		"/provision/cold",
		bytes.NewReader(wire),
	)
	setDeviceHeaders(req)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	var res coldResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); w.Code != http.StatusOK ||
		err != nil ||
		res.PublicKey == "" {
		t.Fatalf("escaped key: %d %s", w.Code, w.Body)
	}

	if _, plain, body := postCold(t, s, "/provision/cold", map[string]any{"cold_key_id": freeColdID, "signing_key": key}); plain != res {
		t.Fatalf("plain key %s, want the escaped import %+v", body, res)
	}
}

// An escape that is not a hex digit, or is cut short, is a malformed key.
func TestSecretHexRefusesNonHexEscapes(t *testing.T) {
	t.Parallel()

	for _, in := range []string{
		`"\n5820"`,
		`"é5820"`,
		`"g"`,
		`"😀5820"`,
		`"5820\u003"`,
		`"5820\u"`,
		`"5820\"`,
		`"\/5820"`,
	} {
		var h secretHex
		if err := h.UnmarshalJSON([]byte(in)); !errors.Is(
			err,
			errMalformedKey,
		) {
			t.Errorf("%s: got %v, want %v", in, err, errMalformedKey)
		}

		if h != nil {
			t.Errorf("%s: left %x, want no key", in, []byte(h))
		}
	}
}
