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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer"
)

func TestNewSignerHTTPServerReadTimeout(t *testing.T) {
	srv := newSignerHTTPServer("127.0.0.1:0", http.NotFoundHandler())
	if srv.ReadHeaderTimeout <= 0 {
		t.Fatal("signer server must bound header reads")
	}
	if srv.ReadTimeout != signerReadTimeout {
		t.Fatalf("ReadTimeout = %s, want %s", srv.ReadTimeout, signerReadTimeout)
	}
}

func TestSignerMuxDoesNotExposeMetrics(t *testing.T) {
	mux := newSignerMux(http.NotFoundHandler(), http.NotFoundHandler())
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("GET /metrics status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestIsLocalListenAddress(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want bool
	}{
		{name: "localhost", addr: "localhost", want: true},
		{name: "localhost with spaces", addr: " localhost ", want: true},
		{name: "localhost uppercase", addr: "LOCALHOST", want: true},
		{name: "localhost with port", addr: "localhost:8080", want: true},
		{name: "ipv4 loopback", addr: "127.0.0.1", want: true},
		{name: "ipv6 loopback", addr: "::1", want: true},
		{name: "bracketed ipv6 loopback", addr: "[::1]", want: true},
		{name: "bracketed ipv6 loopback with spaces", addr: " [::1] ", want: true},
		{name: "bracketed ipv6 loopback with port", addr: "[::1]:8080", want: true},
		{name: "empty wildcard", addr: "", want: false},
		{name: "ipv4 wildcard", addr: "0.0.0.0", want: false},
		{name: "ipv6 wildcard", addr: "::", want: false},
		{name: "malformed bracket missing close", addr: "[::1", want: false},
		{name: "malformed bracket missing open", addr: "]:1", want: false},
		{name: "malformed bracket only", addr: "[", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := signer.IsLoopbackListenAddress(tt.addr); got != tt.want {
				t.Fatalf("IsLoopbackListenAddress(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

// A metrics scrape that outlives the shutdown deadline must not skip the
// signer drain or turn into a failed shutdown.
func TestShutdownSignerServersDrainsSignerWhenMetricsShutdownFails(t *testing.T) {
	signerLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	metricsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	signerServer := &http.Server{Handler: http.NotFoundHandler()}
	metricsConnTracked := make(chan struct{}, 1)
	metricsServer := &http.Server{
		Handler: http.NotFoundHandler(),
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				metricsConnTracked <- struct{}{}
			}
		},
	}
	t.Cleanup(func() {
		_ = signerServer.Close()
		_ = metricsServer.Close()
	})
	signerDone := make(chan error, 1)
	go func() { signerDone <- signerServer.Serve(signerLn) }()
	go func() { _ = metricsServer.Serve(metricsLn) }()

	// A connection that has sent nothing stays in StateNew, which Shutdown
	// does not treat as idle, so the metrics drain cannot finish.
	stalled, err := net.Dial("tcp", metricsLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stalled.Close() })
	<-metricsConnTracked

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	if err := shutdownSignerServers(ctx, logger, signerServer, metricsServer); err != nil {
		t.Fatalf("shutdownSignerServers: %v", err)
	}
	if err := <-signerDone; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("signer Serve returned %v, want %v", err, http.ErrServerClosed)
	}
	if !strings.Contains(logs.String(), "metrics shutdown failed") {
		t.Fatalf("metrics shutdown failure was not logged: %q", logs.String())
	}
}
