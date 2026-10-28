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

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blinklabs-io/bursa/internal/config"
)

func TestNewMetricsHTTPServerRequiresLoopback(t *testing.T) {
	for _, address := range []string{"", "0.0.0.0", "::", "192.0.2.1"} {
		t.Run(address, func(t *testing.T) {
			server, err := newMetricsHTTPServer(config.MetricsConfig{
				ListenAddress: address,
				ListenPort:    8081,
			})
			if err == nil {
				t.Fatalf("newMetricsHTTPServer(%q) returned server %v without an error", address, server)
			}
		})
	}
}

func TestNewMetricsHTTPServerServesLoopbackMetrics(t *testing.T) {
	server, err := newMetricsHTTPServer(config.MetricsConfig{
		ListenAddress: "127.0.0.1",
		ListenPort:    8081,
	})
	if err != nil {
		t.Fatalf("newMetricsHTTPServer: %v", err)
	}
	if server == nil {
		t.Fatal("newMetricsHTTPServer returned nil server for a non-zero port")
	}
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /metrics status = %d, want %d", response.Code, http.StatusOK)
	}
}

func TestNewMetricsHTTPServerFormatsIPv6(t *testing.T) {
	for _, address := range []string{"::1", "[::1]"} {
		t.Run(address, func(t *testing.T) {
			server, err := newMetricsHTTPServer(config.MetricsConfig{
				ListenAddress: address,
				ListenPort:    8081,
			})
			if err != nil {
				t.Fatalf("newMetricsHTTPServer: %v", err)
			}
			if server == nil {
				t.Fatal("newMetricsHTTPServer returned nil server for a non-zero port")
			}
			if server.Addr != "[::1]:8081" {
				t.Fatalf("metrics address = %q, want %q", server.Addr, "[::1]:8081")
			}
		})
	}
}

func TestNewMetricsHTTPServerDisabled(t *testing.T) {
	server, err := newMetricsHTTPServer(config.MetricsConfig{ListenAddress: "0.0.0.0"})
	if err != nil {
		t.Fatalf("disabled metrics listener: %v", err)
	}
	if server != nil {
		t.Fatalf("disabled metrics listener returned server %v", server)
	}
}
