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
