// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package survey

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func relayServer(t *testing.T, handler http.HandlerFunc) func(context.Context, uint64) ([]byte, error) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return newRelayFetcher(srv.Client(), srv.URL)
}

func TestRelayFetcherReadsTheQuicknetBeacon(t *testing.T) {
	t.Parallel()
	var path string
	fetch := relayServer(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		fmt.Fprintf(w, `{"round":100,"randomness":"79fe","signature":%q}`, quicknetRound100Sig)
	})
	got, err := fetch(context.Background(), 100)
	noErr(t, err)
	equal(t, "/"+QuicknetChainHash+"/public/100", path)
	equal(t, quicknetRound100Sig, hex.EncodeToString(got))
}

func TestRelayFetcherRejectsBadResponses(t *testing.T) {
	t.Parallel()
	for name, handler := range map[string]http.HandlerFunc{
		"not found":     func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) },
		"server error":  func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "boom", 500) },
		"not json":      func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) },
		"wrong round":   func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"round":7,"signature":"aa"}`)) },
		"signature hex": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"round":100,"signature":"zz"}`)) },
		"no signature":  func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"round":100}`)) },
		"oversized body": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"round":100,"signature":"` + strings.Repeat("a", 1<<16) + `"}`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := relayServer(t, handler)(context.Background(), 100); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
