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
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
)

const freeColdID uint32 = 0x20e50011

var coldSeed = bytes.Repeat([]byte{0x42}, 32)

func coldKeyHex(seed []byte) string { return "5820" + hex.EncodeToString(seed) }

// newLoggedService is newTestService with the service log captured.
func newLoggedService(t *testing.T) (*Service, *fakeChip, func() string) {
	t.Helper()

	var (
		mu  sync.Mutex
		buf strings.Builder
	)

	chip := newFakeChip()
	s := New(&sync.Mutex{}, func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(&buf, format+"\n", args...)
	})

	if err := s.SetChip(chip); err != nil {
		t.Fatal(err)
	}

	return s, chip, func() string {
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
}

func TestProvisionCold(t *testing.T) {
	t.Parallel()

	s, chip, logs := newLoggedService(t)

	code, body := post(t, s, "/provision/cold", map[string]any{
		"cold_key_id": freeColdID, "signing_key": coldKeyHex(coldSeed),
	})

	if code != http.StatusOK {
		t.Fatalf("got %d %s, want 200", code, body)
	}

	var resp struct {
		ColdKeyID uint32 `json:"cold_key_id"`
		PublicKey string `json:"public_key"`
		PoolID    string `json:"pool_id"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}

	pub := ed25519.NewKeyFromSeed(coldSeed).Public().(ed25519.PublicKey)

	if resp.ColdKeyID != freeColdID || resp.PublicKey != hex.EncodeToString(pub) || resp.PoolID != hashHex(pub) {
		t.Fatalf("response %s does not match the imported key", body)
	}

	got, err := chip.PublicKeyEd25519(freeColdID)
	if err != nil || !bytes.Equal(got, pub) {
		t.Fatalf("chip key = %x, %v; want %x", got, err, pub)
	}

	if l := logs(); strings.Contains(l, hex.EncodeToString(coldSeed)) {
		t.Fatalf("service log contains the seed: %s", l)
	}
}

func TestProvisionColdRefusals(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		id   uint32
		key  string
		want string
	}{
		{"below range", coldKeyFirst - 1, coldKeyHex(coldSeed), "outside the cold key range"},
		{"above range", coldKeyLast + 1, coldKeyHex(coldSeed), "outside the cold key range"},
		{"occupied", testColdID, coldKeyHex(coldSeed), "already exists"},
		{"not hex", freeColdID, "zz", "malformed signing key"},
		{"no cbor prefix", freeColdID, hex.EncodeToString(coldSeed), "malformed signing key"},
		{"short seed", freeColdID, "5820" + hex.EncodeToString(coldSeed[:31]), "malformed signing key"},
		{"extended key", freeColdID, "5840" + strings.Repeat("11", 64), "malformed signing key"},
		{"empty", freeColdID, "", "malformed signing key"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, chip, logs := newLoggedService(t)
			before, _ := chip.PublicKeyEd25519(testColdID)

			code, body := post(t, s, "/provision/cold", map[string]any{
				"cold_key_id": tc.id, "signing_key": tc.key,
			})

			if code == http.StatusOK || !strings.Contains(string(body), tc.want) {
				t.Fatalf("got %d %q, want a refusal containing %q", code, body, tc.want)
			}

			if after, _ := chip.PublicKeyEd25519(testColdID); !bytes.Equal(before, after) {
				t.Fatal("existing cold key changed")
			}

			if tc.id == freeColdID {
				if ok, _ := chip.Exists(freeColdID); ok {
					t.Fatal("refused request still created an object")
				}
			}

			if strings.Contains(logs(), hex.EncodeToString(coldSeed)) {
				t.Fatal("service log contains the seed")
			}
		})
	}
}

func TestProvisionColdChipErrors(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		set  func(*fakeChip)
	}{
		{"exists", func(c *fakeChip) { c.failExists = true }},
		{"import", func(c *fakeChip) { c.failImport = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, chip, logs := newLoggedService(t)
			tc.set(chip)

			code, body := post(t, s, "/provision/cold", map[string]any{
				"cold_key_id": freeColdID, "signing_key": coldKeyHex(coldSeed),
			})

			if code == http.StatusOK || !strings.Contains(string(body), "device error") {
				t.Fatalf("got %d %q, want a device error", code, body)
			}

			if strings.Contains(string(body)+logs(), hex.EncodeToString(coldSeed)) {
				t.Fatal("seed leaked into the response or log")
			}
		})
	}
}

func TestProvisionColdNeverOverwrites(t *testing.T) {
	t.Parallel()

	s, chip, _ := newLoggedService(t)

	req := map[string]any{"cold_key_id": freeColdID, "signing_key": coldKeyHex(coldSeed)}

	if code, body := post(t, s, "/provision/cold", req); code != http.StatusOK {
		t.Fatalf("first import: %d %s", code, body)
	}

	first, _ := chip.PublicKeyEd25519(freeColdID)
	req["signing_key"] = coldKeyHex(bytes.Repeat([]byte{0x43}, 32))

	if code, _ := post(t, s, "/provision/cold", req); code == http.StatusOK {
		t.Fatal("second import over an existing key was accepted")
	}

	if second, _ := chip.PublicKeyEd25519(freeColdID); !bytes.Equal(first, second) {
		t.Fatal("key was overwritten")
	}
}
