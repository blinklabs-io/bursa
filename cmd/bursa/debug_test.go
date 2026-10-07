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
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/internal/config"
)

func TestStartDebugListenerRefusesNonLoopback(t *testing.T) {
	t.Parallel()
	for _, addr := range []string{"", "0.0.0.0", "::", "10.1.2.3", "example.com"} {
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

// startDebugListenerOnFreePort starts the listener on host at a port picked
// from the kernel. The probe releases the port before the listener binds it,
// so a bind lost to another process is retried on a fresh port.
func startDebugListenerOnFreePort(t *testing.T, host string) (*http.Server, int) {
	t.Helper()
	for range 5 {
		probe, err := net.Listen("tcp", net.JoinHostPort(strings.Trim(host, "[]"), "0"))
		if err != nil {
			t.Fatalf("probe listen: %v", err)
		}
		port := probe.Addr().(*net.TCPAddr).Port
		_ = probe.Close()
		srv, err := startDebugListener(
			config.DebugConfig{ListenAddress: host, ListenPort: uint(port)},
		)
		if errors.Is(err, syscall.EADDRINUSE) {
			continue
		}
		if err != nil {
			t.Fatalf("startDebugListener(%q): %v", host, err)
		}
		t.Cleanup(func() { _ = srv.Close() })
		return srv, port
	}
	t.Fatal("no free port after 5 attempts")
	return nil, 0
}

func TestStartDebugListenerServesPprofOnLoopback(t *testing.T) {
	t.Parallel()
	for _, host := range []string{"127.0.0.1", "[::1]", "::1"} {
		if strings.Contains(host, ":") {
			ln, err := net.Listen("tcp", "[::1]:0")
			if err != nil {
				t.Logf("skipping %q: no IPv6 loopback: %v", host, err)
				continue
			}
			_ = ln.Close()
		}
		_, port := startDebugListenerOnFreePort(t, host)
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(
			"http://" + net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(port)) +
				"/debug/pprof/",
		)
		if err != nil {
			t.Fatalf("%s: GET pprof index: %v", host, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d, want 200", host, resp.StatusCode)
		}
	}
}
