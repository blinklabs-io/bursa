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
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

type fakePinger struct{ err error }

func (f fakePinger) Ping(context.Context) error { return f.err }

type fakeReady struct{ err error }

func (f fakeReady) Ready() error { return f.err }

func TestKesAgentHealthMux(t *testing.T) {
	metrics := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	down := errors.New("down")
	cases := []struct {
		name  string
		store *fakePinger
		agent error
		want  int
	}{
		{"no store", nil, nil, http.StatusOK},
		{"store answers", &fakePinger{}, nil, http.StatusOK},
		{"store down", &fakePinger{err: down}, nil, http.StatusServiceUnavailable},
		{"key not loaded", &fakePinger{}, down, http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var store interface{ Ping(context.Context) error }
			if tc.store != nil {
				store = *tc.store
			}
			srv := httptest.NewServer(
				kesAgentHealthMux(metrics, store, fakeReady{err: tc.agent}),
			)
			defer srv.Close()
			for path, want := range map[string]int{
				"/healthz": http.StatusOK,
				"/readyz":  tc.want,
				"/metrics": http.StatusTeapot,
			} {
				resp, err := http.Get(srv.URL + path)
				if err != nil {
					t.Fatalf("GET %s: %v", path, err)
				}
				_ = resp.Body.Close()
				if resp.StatusCode != want {
					t.Errorf("GET %s: status %d, want %d", path, resp.StatusCode, want)
				}
			}
		})
	}
}

func writeReadyConfig(t *testing.T, port int) string {
	t.Helper()
	return writeReadyConfigAt(t, "127.0.0.1", port)
}

func writeReadyConfigAt(t *testing.T, address string, port int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bursa.yaml")
	body := fmt.Sprintf("metrics:\n  address: %q\n  port: %d\n", address, port)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckKesAgentReady(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusOK)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/readyz" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(int(status.Load()))
		}),
	)
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	defer srv.Close()
	cfg := writeReadyConfig(t, ln.Addr().(*net.TCPAddr).Port)

	if err := checkKesAgentReady(cfg); err != nil {
		t.Fatalf("ready agent: %v", err)
	}
	status.Store(http.StatusServiceUnavailable)
	if err := checkKesAgentReady(cfg); err == nil ||
		!strings.Contains(err.Error(), "503") {
		t.Fatalf("unready agent: want a 503 error, got %v", err)
	}
}

// TestCheckKesAgentReadyWildcardBind: an agent whose metrics listener binds
// every interface is queried on loopback.
func TestCheckKesAgentReadyWildcardBind(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	defer srv.Close()
	cfg := writeReadyConfigAt(t, "0.0.0.0", ln.Addr().(*net.TCPAddr).Port)
	if err := checkKesAgentReady(cfg); err != nil {
		t.Fatalf("ready agent bound to 0.0.0.0: %v", err)
	}
}

func TestCheckKesAgentReadyMetricsDisabled(t *testing.T) {
	err := checkKesAgentReady(writeReadyConfig(t, 0))
	if err == nil || !strings.Contains(err.Error(), "metrics.port") {
		t.Fatalf("metrics disabled: want an error naming metrics.port, got %v", err)
	}
}

// TestKesAgentRejectsUnknownSubcommand: a misspelled subcommand fails
// instead of starting the daemon.
func TestKesAgentRejectsUnknownSubcommand(t *testing.T) {
	if err := kesAgentCommand().ValidateArgs([]string{"reday"}); err == nil {
		t.Fatal("kes-agent reday: want an error, got nil")
	}
}

// readyzProxyHelperEnv carries the readiness URL to the child process in
// TestKesAgentReadyzBypassesProxy.
const readyzProxyHelperEnv = "BURSA_TEST_READYZ_PROXY_URL"

// TestKesAgentReadyzProxyHelper runs only as the child process of
// TestKesAgentReadyzBypassesProxy.
func TestKesAgentReadyzProxyHelper(t *testing.T) {
	url := os.Getenv(readyzProxyHelperEnv)
	if url == "" {
		t.Skip("helper process only")
	}
	if err := getKesAgentReadyz(url); err != nil {
		t.Fatal(err)
	}
}

// TestKesAgentReadyzBypassesProxy probes a readiness listener on a
// non-loopback address with HTTP_PROXY set. Go reads the proxy variables once
// per process, so the probe runs in a child process that starts with them.
func TestKesAgentReadyzBypassesProxy(t *testing.T) {
	ip := nonLoopbackIPv4(t)
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Skipf("listen on %s: %v", ip, err)
	}
	agent := &httptest.Server{
		Listener: ln,
		Config: &http.Server{Handler: http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
		)},
	}
	agent.Start()
	defer agent.Close()
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			proxied.Add(1)
			w.WriteHeader(http.StatusBadGateway)
		},
	))
	defer proxy.Close()

	cmd := exec.Command(os.Args[0], "-test.run=^TestKesAgentReadyzProxyHelper$")
	cmd.Env = append(os.Environ(),
		readyzProxyHelperEnv+"="+agent.URL+"/readyz",
		"HTTP_PROXY="+proxy.URL, "http_proxy="+proxy.URL,
		"NO_PROXY=", "no_proxy=",
	)
	out, err := cmd.CombinedOutput()
	if n := proxied.Load(); n != 0 {
		t.Errorf("readiness probe went through the proxy %d time(s)", n)
	}
	if err != nil {
		t.Fatalf("readiness probe failed: %v\n%s", err, out)
	}
}

func nonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("list interface addresses: %v", err)
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if ok && !n.IP.IsLoopback() && n.IP.To4() != nil &&
			!n.IP.IsLinkLocalUnicast() {
			return n.IP.String()
		}
	}
	t.Skip("no non-loopback IPv4 address")
	return ""
}
