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
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// coldResult is a cold key response as a host reads it.
type coldResult struct {
	ColdKeyID uint32 `json:"cold_key_id"`
	PublicKey string `json:"public_key"`
	PoolID    string `json:"pool_id"`
	Origin    string `json:"origin"`
}

// originObject is the binary object recording how the cold key id was made:
// the cold key object's ID plus 0x30, which lies above the identity key, host
// key list and signing log head and below the owner keys.
func originObject(id uint32) uint32 { return id + 0x30 }

// setDeviceHeaders makes r a request the device's host clients send: to the
// device's address, with a JSON body.
func setDeviceHeaders(r *http.Request) {
	r.Host = "10.0.0.1"
	r.Header.Set("Content-Type", "application/json")
}

func postCold(t *testing.T, s *Service, path string, req any) (int, coldResult, string) {
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

func TestProvisionColdGenerate(t *testing.T) {
	t.Parallel()

	s, chip, logs := newLoggedService(t)

	code, res, body := postCold(t, s, "/provision/cold", map[string]any{
		"cold_key_id": freeColdID, "generate": true,
	})
	if code != http.StatusOK {
		t.Fatalf("got %d %s, want 200", code, body)
	}

	pub, err := chip.PublicKeyEd25519(freeColdID)
	if err != nil {
		t.Fatalf("no key generated: %v", err)
	}

	if res.ColdKeyID != freeColdID || res.PublicKey != hex.EncodeToString(pub) || res.PoolID != hashHex(pub) {
		t.Fatalf("response %s does not match the generated key %x", body, pub)
	}

	if res.Origin != "generated" {
		t.Fatalf("origin = %q, want generated", res.Origin)
	}

	if !strings.Contains(logs(), "generated cold key") {
		t.Fatalf("log does not record the generation: %q", logs())
	}
}

func TestProvisionColdGenerateNeverOverwrites(t *testing.T) {
	t.Parallel()

	for name, prepare := range map[string]func(*fakeChip){
		"preinstalled key": func(*fakeChip) {},
		"earlier import":   func(c *fakeChip) { _ = c.ImportEd25519(freeColdID, coldSeed, false) },
		"earlier binary":   func(c *fakeChip) { c.bins[freeColdID] = []byte("x") },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s, chip, _ := newLoggedService(t)
			prepare(chip)

			id := testColdID
			if name != "preinstalled key" {
				id = freeColdID
			}

			before, _ := chip.PublicKeyEd25519(id)
			binBefore := bytes.Clone(chip.bins[id])

			code, _, body := postCold(t, s, "/provision/cold", map[string]any{"cold_key_id": id, "generate": true})
			if code == http.StatusOK || !strings.Contains(body, "already exists") {
				t.Fatalf("got %d %q, want a refusal naming the existing object", code, body)
			}

			if after, _ := chip.PublicKeyEd25519(id); !bytes.Equal(before, after) {
				t.Fatal("existing cold key was replaced")
			}

			if !bytes.Equal(binBefore, chip.bins[id]) {
				t.Fatal("existing object was rewritten")
			}
		})
	}
}

func TestProvisionColdGenerateRefusals(t *testing.T) {
	t.Parallel()

	for name, req := range map[string]map[string]any{
		"key and generate":       {"cold_key_id": freeColdID, "generate": true, "signing_key": coldKeyHex(coldSeed)},
		"empty key and generate": {"cold_key_id": freeColdID, "generate": true, "signing_key": ""},
		"below range":            {"cold_key_id": coldKeyFirst - 1, "generate": true},
		"above range":            {"cold_key_id": coldKeyLast + 1, "generate": true},
		"misspelled generate":    {"cold_key_id": freeColdID, "generated": true},
		"explicit false":         {"cold_key_id": freeColdID, "generate": false},
		"no key, no generate":    {"cold_key_id": freeColdID},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s, chip, _ := newLoggedService(t)

			if code, _, body := postCold(t, s, "/provision/cold", req); code == http.StatusOK {
				t.Fatalf("accepted: %s", body)
			}

			for _, id := range []uint32{freeColdID, originObject(freeColdID)} {
				if ok, _ := chip.Exists(id); ok {
					t.Fatalf("refused request created object %#08x", id)
				}
			}
		})
	}
}

func TestProvisionColdGenerateDeviceFailures(t *testing.T) {
	t.Parallel()

	for name, set := range map[string]func(*fakeChip){
		"exists": func(c *fakeChip) { c.failExists = true },
		"record": func(c *fakeChip) { c.failWrite = true },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s, chip, _ := newLoggedService(t)
			set(chip)

			code, _, body := postCold(t, s, "/provision/cold", map[string]any{"cold_key_id": freeColdID, "generate": true})
			if code == http.StatusOK || !strings.Contains(body, "device error") {
				t.Fatalf("got %d %q, want a device error", code, body)
			}

			// a generated key whose origin could not be recorded is removed, so no
			// key exists that the device cannot describe
			chip.failExists = false
			if ok, _ := chip.Exists(freeColdID); ok {
				t.Fatal("generated key left behind without an origin record")
			}
		})
	}
}

func TestProvisionColdImportReportsOrigin(t *testing.T) {
	t.Parallel()

	s, _, _ := newLoggedService(t)
	req := map[string]any{"cold_key_id": freeColdID, "signing_key": coldKeyHex(coldSeed)}

	code, res, body := postCold(t, s, "/provision/cold", req)
	if code != http.StatusOK || res.Origin != "imported" {
		t.Fatalf("got %d %s, want origin imported", code, body)
	}

	// a retry confirms the import and reports the same origin
	if code, again, body := postCold(t, s, "/provision/cold", req); code != http.StatusOK || again != res {
		t.Fatalf("retry: %d %s, want %+v", code, body, res)
	}
}

// The origin is device state: a service started on a chip that already holds
// the keys reports it, and a key with no record is reported as unknown rather
// than guessed.
func TestColdKeyOriginSurvivesRestart(t *testing.T) {
	t.Parallel()

	s, chip, _ := newLoggedService(t)

	_, gen, _ := postCold(t, s, "/provision/cold", map[string]any{"cold_key_id": freeColdID, "generate": true})
	imp := coldKeyFirst + 2
	postCold(t, s, "/provision/cold", map[string]any{"cold_key_id": imp, "signing_key": coldKeyHex(coldSeed)})

	restarted := New(&sync.Mutex{}, t.Logf)
	if err := restarted.SetChip(chip); err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		id   uint32
		want string
	}{
		"generated":     {freeColdID, "generated"},
		"imported":      {imp, "imported"},
		"no record":     {testColdID, "unknown"},
		"generated key": {gen.ColdKeyID, "generated"},
	} {
		code, res, body := postCold(t, restarted, "/provision/cold/info", map[string]any{"cold_key_id": tc.id})
		if code != http.StatusOK || res.Origin != tc.want || res.ColdKeyID != tc.id {
			t.Errorf("%s: got %d %s, want origin %s", name, code, body, tc.want)
		}

		pub, _ := chip.PublicKeyEd25519(tc.id)
		if res.PublicKey != hex.EncodeToString(pub) || res.PoolID != hashHex(pub) {
			t.Errorf("%s: %s does not describe key %x", name, body, pub)
		}
	}

	for name, id := range map[string]uint32{"absent": coldKeyFirst + 5, "outside range": coldKeyLast + 1} {
		if code, _, body := postCold(t, restarted, "/provision/cold/info", map[string]any{"cold_key_id": id}); code == http.StatusOK {
			t.Errorf("%s: info answered %s", name, body)
		}
	}
}

// A wiped cold key takes its origin record with it, so a later key in the same
// object cannot inherit it.
func TestWipeRemovesColdOrigin(t *testing.T) {
	t.Parallel()

	s, chip, _ := newLoggedService(t)
	identity := identityHex(t, s)

	postCold(t, s, "/provision/cold", map[string]any{"cold_key_id": freeColdID, "generate": true})

	if ok, _ := chip.Exists(originObject(freeColdID)); !ok {
		t.Fatal("no origin record written")
	}

	_, body := wipePost(t, s, "/wipe/objects", struct{}{})
	if !strings.Contains(string(body), "0x20e50041") {
		t.Fatalf("object list %s omits the origin record", body)
	}

	if code, body := wipePost(t, s, "/wipe/device", WipeDeviceRequest{IdentityPublicKey: identity}); code != http.StatusOK {
		t.Fatalf("wipe: %d %s", code, body)
	}

	for _, id := range []uint32{freeColdID, originObject(freeColdID)} {
		if ok, _ := chip.Exists(id); ok {
			t.Errorf("object %#08x survived a device wipe", id)
		}
	}
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
				if strings.Contains(string(b), seedHex) || bytes.Contains(b, coldSeed) {
					t.Fatalf("read buffer %d still holds the key after the request", i)
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
		t.Fatalf("%s is a %s, not a byte slice: its copy of the key cannot be zeroed", field, f.Kind())
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
		mux.HandleFunc("POST /c", handle(s, func(req ColdRequest) (ColdResponse, error) {
			captured = secretBytes(t, req, "SigningKey")
			if len(captured) == 0 || allZero(captured) {
				t.Error("key field empty before the import")
			}

			return s.provisionCold(req)
		}))

		req := httptest.NewRequest(http.MethodPost, "/c", strings.NewReader(
			`{"cold_key_id":551878673,"signing_key":"`+coldKeyHex(coldSeed)+`"}`))
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
		mux.HandleFunc("POST /p", handle(s, func(req ProvisionRequest) (ProvisionResponse, error) {
			captured = secretBytes(t, req, "OwnerSigningKey")
			if len(captured) == 0 || allZero(captured) {
				t.Error("key field empty before the import")
			}

			return s.provisionProfile(req)
		}))

		req := httptest.NewRequest(http.MethodPost, "/p", strings.NewReader(
			`{"name":"a@preview","slot":1,"cold_key_id":`+"551878672"+`,"reward_account":"`+testReward+`","owner_signing_key":"`+coldKeyHex(coldSeed)+`"}`))
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

// A generation whose answer was lost still created the key, which was absent
// when the request began: it is recorded as generated, not stranded without
// an origin.
func TestProvisionColdGenerateLostReply(t *testing.T) {
	t.Parallel()

	s, chip, _ := newLoggedService(t)
	chip.lostGenerateReply = true

	code, res, body := postCold(t, s, "/provision/cold", map[string]any{"cold_key_id": freeColdID, "generate": true})
	if code != http.StatusOK || res.Origin != "generated" {
		t.Fatalf("got %d %s, want the generated key recorded", code, body)
	}

	pub, err := chip.PublicKeyEd25519(freeColdID)
	if err != nil || res.PublicKey != hex.EncodeToString(pub) {
		t.Fatalf("response %s does not describe the stored key: %v", body, err)
	}
}

// A generation whose answer was lost, followed by a failed exist check, may
// have created the key: it is deleted, so a retry is not refused by a key the
// device cannot account for.
func TestProvisionColdGenerateLostReplyUnverified(t *testing.T) {
	t.Parallel()

	s, chip, _ := newLoggedService(t)
	chip.lostGenerateReply = true
	chip.failExistsAfterGenerate = true

	code, _, body := postCold(t, s, "/provision/cold", map[string]any{"cold_key_id": freeColdID, "generate": true})
	if code == http.StatusOK || !strings.Contains(body, "device error") {
		t.Fatalf("got %d %q, want a device error", code, body)
	}

	chip.failExists = false
	chip.failExistsAfterGenerate = false
	chip.lostGenerateReply = false

	if ok, _ := chip.Exists(freeColdID); ok {
		t.Fatal("generated key left behind without an origin record")
	}

	code, res, body := postCold(t, s, "/provision/cold", map[string]any{"cold_key_id": freeColdID, "generate": true})
	if code != http.StatusOK || res.Origin != "generated" {
		t.Fatalf("retry: %d %s, want a generated key", code, body)
	}
}

// A key that matches the seed supplied was imported, whatever an earlier
// record says.
func TestProvisionColdImportCorrectsStaleOrigin(t *testing.T) {
	t.Parallel()

	s, chip, _ := newLoggedService(t)
	req := map[string]any{"cold_key_id": freeColdID, "signing_key": coldKeyHex(coldSeed)}

	if code, _, body := postCold(t, s, "/provision/cold", req); code != http.StatusOK {
		t.Fatalf("import: %d %s", code, body)
	}

	chip.bins[originObject(freeColdID)] = []byte("generated")

	if code, res, body := postCold(t, s, "/provision/cold", req); code != http.StatusOK || res.Origin != "imported" {
		t.Fatalf("retry: %d %s, want origin imported", code, body)
	}

	if got := string(chip.bins[originObject(freeColdID)]); got != "imported" {
		t.Fatalf("origin record %q, want imported", got)
	}
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

// An origin record that reads back different from what was written fails the
// provision and removes the key the request created, so a retry records it.
func TestProvisionColdTornOriginRecord(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		req    map[string]any
		origin string
	}{
		"generate": {map[string]any{"cold_key_id": freeColdID, "generate": true}, "generated"},
		"import":   {map[string]any{"cold_key_id": freeColdID, "signing_key": coldKeyHex(coldSeed)}, "imported"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s, chip, _ := newLoggedService(t)
			chip.tornWrite = true

			code, _, body := postCold(t, s, "/provision/cold", tc.req)
			if code == http.StatusOK || !strings.Contains(body, "device error") {
				t.Fatalf("got %d %q, want a device error", code, body)
			}

			if ok, _ := chip.Exists(freeColdID); ok {
				t.Fatal("key left behind with a torn origin record")
			}

			chip.tornWrite = false

			if code, res, body := postCold(t, s, "/provision/cold", tc.req); code != http.StatusOK || res.Origin != tc.origin {
				t.Fatalf("retry: %d %s, want origin %s", code, body, tc.origin)
			}
		})
	}
}
