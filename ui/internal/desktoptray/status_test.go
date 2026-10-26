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

//go:build webview

package desktoptray

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSplitLaunchURL(t *testing.T) {
	base, tok := SplitLaunchURL("http://127.0.0.1:8090/#session=abc_-123")
	if base != "http://127.0.0.1:8090/" || tok != "abc_-123" {
		t.Fatalf("got base %q token %q", base, tok)
	}
	base, tok = SplitLaunchURL("http://127.0.0.1:8090")
	if base != "http://127.0.0.1:8090" || tok != "" {
		t.Fatalf("no fragment: got base %q token %q", base, tok)
	}
}

func TestFetchNodeStatusAuthenticatesAgainstFragmentFreeBase(t *testing.T) {
	const token = "tray-token"
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.URL.Path != "/status" || r.Header.Get(sessionHeader) != token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"state":"syncing","caughtUp":false}`))
	}))
	defer srv.Close()

	base, tok := SplitLaunchURL(srv.URL + "#session=" + token)
	st, err := fetchNodeStatus(context.Background(), srv.Client(), base, tok)
	if err != nil {
		t.Fatalf("fetchNodeStatus: %v (path %q)", err, gotPath)
	}
	if st.State != "syncing" || st.CaughtUp {
		t.Fatalf("unexpected status %+v", st)
	}

	if _, err := fetchNodeStatus(context.Background(), srv.Client(), base, ""); err == nil {
		t.Fatal("poll without session token must fail")
	}
}
