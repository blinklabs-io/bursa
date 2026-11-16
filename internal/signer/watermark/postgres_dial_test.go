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

package watermark

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// closedLoopbackAddr returns a loopback address with nothing listening.
func closedLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// A refused first dial through the real constructor is retried until ctx ends
// rather than returned at once.
func TestNewPostgresWatermark_RefusedRetriesUntilContextEnds(t *testing.T) {
	t.Parallel()
	addr := closedLoopbackAddr(t)
	dsn := "postgres://u:s3cretpw@" + addr + "/db?sslmode=disable"
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := NewPostgresWatermark(ctx, dsn)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("want error with nothing listening")
	}
	if elapsed < time.Second {
		t.Fatalf("returned after %v: refused dial was not retried", elapsed)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("want connection refused, got %v", err)
	}
}

// silentServer accepts connections and holds them open without answering,
// so a connect attempt waits until its context ends. It returns the address
// and a channel that receives one value per accepted connection.
func silentServer(t *testing.T) (string, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	accepts := make(chan struct{}, 100)
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			accepts <- struct{}{}
		}
	}()
	return ln.Addr().String(), accepts
}

// A connect that hits connect_timeout is retried while the caller context
// still has time.
func TestNewPostgresWatermark_ConnectTimeoutRetries(t *testing.T) {
	t.Parallel()
	addr, accepts := silentServer(t)
	dsn := "postgres://u:pw@" + addr + "/db?sslmode=disable&connect_timeout=1"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := NewPostgresWatermark(ctx, dsn)
	if err == nil {
		t.Fatal("want error from a server that never answers")
	}
	if got := len(accepts); got < 2 {
		t.Fatalf("want connect_timeout retried, got %d attempts: %v", got, err)
	}
}

// When the caller context itself expires, the timeout is not retried.
func TestNewPostgresWatermark_CallerDeadlineNotRetried(t *testing.T) {
	t.Parallel()
	addr, accepts := silentServer(t)
	dsn := "postgres://u:pw@" + addr + "/db?sslmode=disable"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	_, err := NewPostgresWatermark(ctx, dsn)
	if err == nil {
		t.Fatal("want error from a server that never answers")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("returned after %v, want shortly after the caller deadline", elapsed)
	}
	if got := len(accepts); got != 1 {
		t.Fatalf("want 1 attempt, got %d: %v", got, err)
	}
}

// A server that rejects the login must fail on the first attempt.
func TestNewPostgresWatermark_AuthErrorFailsFast(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	accepts := make(chan struct{}, 100)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts <- struct{}{}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf) // startup message
				// ErrorResponse: severity, SQLSTATE 28P01, message.
				body := "SFATAL\x00C28P01\x00Mpassword authentication failed\x00\x00"
				msg := []byte{'E', 0, 0, 0, 0}
				n := uint32(4 + len(body))
				msg[1], msg[2], msg[3], msg[4] = byte(n>>24), byte(n>>16), byte(n>>8), byte(n)
				msg = append(msg, body...)
				_, _ = c.Write(msg)
			}(c)
		}
	}()
	dsn := "postgres://u:pw@" + ln.Addr().String() + "/db?sslmode=disable"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	_, err = NewPostgresWatermark(ctx, dsn)
	if err == nil {
		t.Fatal("want auth error")
	}
	if !strings.Contains(err.Error(), "28P01") &&
		!strings.Contains(err.Error(), "password authentication failed") {
		t.Fatalf("want auth error, got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("auth error took %v: it was retried", time.Since(start))
	}
	if got := len(accepts); got != 1 {
		t.Fatalf("want 1 connection attempt, got %d", got)
	}
}
