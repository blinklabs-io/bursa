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

package updatecheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckRejectsUnsafeReleaseURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v1.2.3","html_url":"https://example.com/update"}`))
	}))
	defer server.Close()

	_, _, err := checkAt(context.Background(), server.Client(), "v1.0.0", server.URL)
	if err == nil {
		t.Fatal("Check accepted an untrusted release URL")
	}
}

func TestCheckReportsNewRelease(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v1.2.4","html_url":"https://github.com/blinklabs-io/bursa/releases/tag/v1.2.4"}`))
	}))
	defer server.Close()

	release, update, err := checkAt(context.Background(), server.Client(), "v1.2.3", server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !update || release.TagName != "v1.2.4" {
		t.Fatalf("release = %#v, update = %v; want v1.2.4 and true", release, update)
	}
}

func TestVersionCompare(t *testing.T) {
	cases := []struct {
		current, latest string
		want            bool
	}{
		{"v1.2.3", "v1.2.4", true},
		{"v1.2.3", "v1.2.3", false},
		{"v1.2.3", "v1.2.2", false},
		{"v1.2.3-rc.1", "v1.2.3", true},
	}
	for _, tc := range cases {
		current, err := parseVersion(tc.current)
		if err != nil {
			t.Fatal(err)
		}
		latest, err := parseVersion(tc.latest)
		if err != nil {
			t.Fatal(err)
		}
		if got := latest.compare(current) > 0; got != tc.want {
			t.Errorf("%s -> %s = %v, want %v", tc.current, tc.latest, got, tc.want)
		}
	}
}

func TestCheckDevelopmentBuildDoesNotReportUpdate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v1.2.4","html_url":"https://github.com/blinklabs-io/bursa/releases/tag/v1.2.4"}`))
	}))
	defer server.Close()

	_, update, err := checkAt(context.Background(), server.Client(), "", server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if update {
		t.Fatal("development build should not report an update")
	}
}
