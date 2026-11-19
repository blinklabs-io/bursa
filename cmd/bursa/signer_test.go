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
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/internal/signer"
)

type countingReadinessPinger struct {
	calls atomic.Int32
	err   error
}

func (p *countingReadinessPinger) Ping(context.Context) error {
	p.calls.Add(1)
	return p.err
}

type controlledReadinessPinger struct {
	calls         atomic.Int32
	active        atomic.Int32
	maxActive     atomic.Int32
	called        chan struct{}
	results       chan error
	ignoreContext bool
}

func newControlledReadinessPinger(ignoreContext bool) *controlledReadinessPinger {
	return &controlledReadinessPinger{
		called:        make(chan struct{}, 8),
		results:       make(chan error, 8),
		ignoreContext: ignoreContext,
	}
}

func (p *controlledReadinessPinger) Ping(ctx context.Context) error {
	p.calls.Add(1)
	active := p.active.Add(1)
	defer p.active.Add(-1)
	for {
		maxActive := p.maxActive.Load()
		if active <= maxActive || p.maxActive.CompareAndSwap(maxActive, active) {
			break
		}
	}
	p.called <- struct{}{}
	if p.ignoreContext {
		return <-p.results
	}
	select {
	case err := <-p.results:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

type readinessTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *readinessTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *readinessTestClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func waitReadinessCall(t *testing.T, p *controlledReadinessPinger) {
	t.Helper()
	select {
	case <-p.called:
	case <-time.After(time.Second):
		t.Fatal("readiness probe did not run")
	}
}

func waitReadinessResult(
	t *testing.T,
	check func(context.Context) error,
	want error,
) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		got := check(t.Context())
		if (want == nil && got == nil) || errors.Is(got, want) {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("readiness result = %v, want %v", got, want)
		default:
			runtime.Gosched()
		}
	}
}

func readinessStatus(h http.Handler) int {
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	return response.Code
}

func TestSignerServiceMuxReadinessRequestsDoNotPingWatermark(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pinger := &countingReadinessPinger{}
	handler := newSignerServiceMux(ctx, http.NotFoundHandler(), pinger)
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for readinessStatus(handler) != http.StatusOK {
		select {
		case <-deadline.C:
			t.Fatal("background readiness probe did not report healthy")
		default:
			runtime.Gosched()
		}
	}

	for range 20 {
		if got := readinessStatus(handler); got != http.StatusOK {
			t.Fatalf("GET /readyz status = %d, want %d", got, http.StatusOK)
		}
	}
	if got := pinger.calls.Load(); got != 1 {
		t.Fatalf(
			"watermark probes after readiness requests = %d, want 1 background probe",
			got,
		)
	}
}

func TestSignerServiceMuxPendingProbeIsUnavailable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pinger := newControlledReadinessPinger(false)
	handler := newSignerServiceMux(ctx, http.NotFoundHandler(), pinger)
	waitReadinessCall(t, pinger)
	if got := readinessStatus(handler); got != http.StatusServiceUnavailable {
		t.Fatalf(
			"GET /readyz during first probe = %d, want %d",
			got,
			http.StatusServiceUnavailable,
		)
	}
}

func TestSignerReadinessRefreshesBothDirections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	clock := &readinessTestClock{now: time.Unix(1, 0)}
	state := newSignerReadinessState(clock.Now)
	pinger := newControlledReadinessPinger(false)
	ticks := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		state.run(ctx, pinger, ticks)
		close(done)
	}()

	waitReadinessCall(t, pinger)
	pinger.results <- nil
	waitReadinessResult(t, state.check, nil)

	failed := errors.New("watermark unavailable")
	ticks <- clock.Now()
	waitReadinessCall(t, pinger)
	pinger.results <- failed
	waitReadinessResult(t, state.check, failed)

	ticks <- clock.Now()
	waitReadinessCall(t, pinger)
	pinger.results <- nil
	waitReadinessResult(t, state.check, nil)
	if got := pinger.maxActive.Load(); got != 1 {
		t.Fatalf("concurrent readiness probes = %d, want 1", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("readiness monitor did not stop after cancellation")
	}
}

func TestSignerReadinessWedgedProbeBecomesStale(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	clock := &readinessTestClock{now: time.Unix(1, 0)}
	state := newSignerReadinessState(clock.Now)
	pinger := newControlledReadinessPinger(true)
	ticks := make(chan time.Time, 3)
	done := make(chan struct{})
	go func() {
		state.run(ctx, pinger, ticks)
		close(done)
	}()

	waitReadinessCall(t, pinger)
	pinger.results <- nil
	waitReadinessResult(t, state.check, nil)
	ticks <- clock.Now()
	waitReadinessCall(t, pinger)
	clock.Advance(signerReadinessTimeout)
	if got := state.check(t.Context()); !errors.Is(
		got,
		errSignerReadinessStale,
	) {
		t.Fatalf("readiness result after wedged probe = %v, want stale", got)
	}
	for range 3 {
		ticks <- clock.Now()
	}
	runtime.Gosched()
	if got := pinger.calls.Load(); got != 2 {
		t.Fatalf("probes while one is wedged = %d, want 2 total", got)
	}
	if got := pinger.maxActive.Load(); got != 1 {
		t.Fatalf("concurrent readiness probes = %d, want 1", got)
	}

	cancel()
	pinger.results <- nil
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("readiness monitor did not stop after wedged probe returned")
	}
}

func TestSignerReadinessRejectsLateSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	clock := &readinessTestClock{now: time.Unix(1, 0)}
	state := newSignerReadinessState(clock.Now)
	pinger := newControlledReadinessPinger(true)
	ticks := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		state.run(ctx, pinger, ticks)
		close(done)
	}()

	waitReadinessCall(t, pinger)
	clock.Advance(signerReadinessTimeout)
	pinger.results <- nil
	waitReadinessResult(t, state.check, errSignerReadinessStale)

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("readiness monitor did not stop after cancellation")
	}
}

func TestNewSignerHTTPServerReadTimeout(t *testing.T) {
	srv := newSignerHTTPServer("127.0.0.1:0", http.NotFoundHandler())
	if srv.ReadHeaderTimeout <= 0 {
		t.Fatal("signer server must bound header reads")
	}
	if srv.ReadTimeout != signerReadTimeout {
		t.Fatalf(
			"ReadTimeout = %s, want %s",
			srv.ReadTimeout,
			signerReadTimeout,
		)
	}
}

func TestSignerMuxDoesNotExposeMetrics(t *testing.T) {
	mux := newSignerMux(http.NotFoundHandler(), http.NotFoundHandler())
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf(
			"GET /metrics status = %d, want %d",
			response.Code,
			http.StatusNotFound,
		)
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
		{
			name: "bracketed ipv6 loopback with spaces",
			addr: " [::1] ",
			want: true,
		},
		{
			name: "bracketed ipv6 loopback with port",
			addr: "[::1]:8080",
			want: true,
		},
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
				t.Fatalf(
					"IsLoopbackListenAddress(%q) = %v, want %v",
					tt.addr,
					got,
					tt.want,
				)
			}
		})
	}
}

// A metrics scrape that outlives the shutdown deadline must not skip the
// signer drain or turn into a failed shutdown.
func TestShutdownSignerServersDrainsSignerWhenMetricsShutdownFails(
	t *testing.T,
) {
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
