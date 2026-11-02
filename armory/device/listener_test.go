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

package device

import (
	"errors"
	"net"
	"testing"
	"time"
)

// acceptAsync runs one Accept and delivers its error. An accepted connection
// stays open, holding its slot, until the test ends.
func acceptAsync(t *testing.T, l net.Listener) <-chan error {
	t.Helper()

	conns := make(chan net.Conn, 1)
	done := make(chan error, 1)

	t.Cleanup(func() {
		select {
		case c := <-conns:
			_ = c.Close()
		default:
		}
	})

	go func() {
		c, err := l.Accept()
		if err == nil {
			conns <- c
		}
		done <- err
	}()

	return done
}

func dialLoopback(t *testing.T, l net.Listener) {
	t.Helper()

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = c.Close() })
}

// A listener limited to one connection accepts a second only after the first
// closes, releases the slot once however often a connection is closed, and
// unblocks a waiting Accept when it is closed itself.
func TestConnLimitListener(t *testing.T) {
	t.Parallel()

	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	l := ConnLimitListener(inner, 1)
	t.Cleanup(func() { _ = l.Close() })

	dialLoopback(t, l)

	first, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}

	dialLoopback(t, l)
	dialLoopback(t, l)

	second := acceptAsync(t, l)

	select {
	case err := <-second:
		t.Fatalf("second connection accepted while the first is open (err %v)", err)
	case <-time.After(200 * time.Millisecond):
	}

	_ = first.Close()
	_ = first.Close()

	select {
	case err := <-second:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second connection not accepted after the first closed")
	}

	// the double close released one slot, not two
	third := acceptAsync(t, l)

	select {
	case err := <-third:
		t.Fatalf("third connection accepted while the second is open (err %v)", err)
	case <-time.After(200 * time.Millisecond):
	}

	_ = l.Close()

	select {
	case err := <-third:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("accept after close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiting accept not released by close")
	}
}
