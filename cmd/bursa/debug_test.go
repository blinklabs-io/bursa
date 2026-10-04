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
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/internal/config"
)

func TestStartDebugListenerRefusesNonLoopback(t *testing.T) {
	t.Parallel()
	for _, addr := range []string{"", "0.0.0.0", "::", "10.1.2.3"} {
		srv, err := startDebugListener(
			config.DebugConfig{ListenAddress: addr, ListenPort: 6060},
		)
		if err == nil {
			_ = srv.Close()
			t.Errorf("address %q: expected error", addr)
		}
	}
}

func TestStartDebugListenerDisabledAtPortZero(t *testing.T) {
	t.Parallel()
	srv, err := startDebugListener(
		config.DebugConfig{ListenAddress: "0.0.0.0", ListenPort: 0},
	)
	if err != nil || srv != nil {
		t.Fatalf("got (%v, %v), want (nil, nil)", srv, err)
	}
}

func TestStartDebugListenerServesPprofOnLoopback(t *testing.T) {
	t.Parallel()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()

	srv, err := startDebugListener(
		config.DebugConfig{ListenAddress: "127.0.0.1", ListenPort: uint(port)},
	)
	if err != nil {
		t.Fatalf("startDebugListener: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(
		"http://127.0.0.1:" + strconv.Itoa(port) + "/debug/pprof/",
	)
	if err != nil {
		t.Fatalf("GET pprof index: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
}
