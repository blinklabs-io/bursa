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

package confidentialspace

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLauncherTokenSource(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "launcher.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("Unix sockets unavailable: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(
			func(rw http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/token" || r.Method != http.MethodPost ||
					r.Header.Get("Content-Type") != "application/json" {
					t.Errorf(
						"request = %s %s %q",
						r.Method,
						r.URL.Path,
						r.Header.Get("Content-Type"),
					)
				}
				var got struct {
					Audience  string   `json:"audience"`
					Nonces    []string `json:"nonces"`
					TokenType string   `json:"token_type"`
				}
				if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
					t.Error(err)
				}
				if got.Audience != "https://signer.example" ||
					len(got.Nonces) != 1 ||
					got.Nonces[0] != "12345678" ||
					got.TokenType != "OIDC" {
					t.Errorf("request body = %+v", got)
				}
				_, _ = rw.Write([]byte("signed.jwt.token\n"))
			},
		),
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	source, err := NewLauncherTokenSource(path)
	if err != nil {
		t.Fatal(err)
	}
	token, err := source.Token(
		t.Context(),
		"https://signer.example",
		[]string{"12345678"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if string(token) != "signed.jwt.token" {
		t.Fatalf("token = %q", token)
	}
}

func TestLauncherTokenSourceFailsClosed(t *testing.T) {
	t.Parallel()
	if _, err := NewLauncherTokenSource("relative.sock"); err == nil {
		t.Fatal("relative launcher socket accepted")
	}
	source, err := NewLauncherTokenSource(
		filepath.Join(t.TempDir(), "missing.sock"),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		audience string
		nonces   []string
	}{
		{"missing audience", "", []string{"12345678"}},
		{"long audience", strings.Repeat("a", 513), []string{"12345678"}},
		{"missing nonce", "a", nil},
		{"short nonce", "a", []string{"short"}},
		{"long nonce", "a", []string{strings.Repeat("n", 89)}},
		{"too many nonces", "a", []string{"12345678", "12345678", "12345678", "12345678", "12345678", "12345678", "12345678"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := source.Token(t.Context(), tc.audience, tc.nonces); err == nil {
				t.Fatal("invalid token request accepted")
			}
		})
	}
}

func TestFileEnvelopeStore(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state", "pool.wrapped")
	store, err := NewFileEnvelopeStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrEnvelopeNotFound) {
		t.Fatalf("initial load error = %v", err)
	}
	if err := store.Create([]byte("wrapped")); err != nil {
		t.Fatal(err)
	}
	if err := store.Create([]byte("replacement")); !errors.Is(
		err,
		ErrEnvelopeExists,
	) {
		t.Fatalf("replacement error = %v", err)
	}
	got, err := store.Load()
	if err != nil || string(got) != "wrapped" {
		t.Fatalf("load = %q, %v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("permissive wrapped key loaded")
	}
}
