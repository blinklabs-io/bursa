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

package kesagent

import (
	"net"
	"testing"
	"time"
)

func TestConnSetCloseAllClosesTrackedConns(t *testing.T) {
	s := newConnSet()
	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	s.add(server)

	s.closeAll()

	// server was closed by closeAll; a read on the client side must now
	// observe EOF/closed-pipe rather than blocking.
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := client.Read(buf); err == nil {
		t.Fatal("expected the client side to observe the server conn closed")
	}
}

// TestConnSetAddAfterCloseAllClosesImmediately guards against the shutdown
// race this connSet exists to close: a connection accepted concurrently with
// shutdown (after closeAll's pass has already run, but before the accept
// loop could register it) must not be tracked and left open -- add must
// close it immediately so its handler goroutine unblocks right away instead
// of hanging in a blocking read forever.
func TestConnSetAddAfterCloseAllClosesImmediately(t *testing.T) {
	s := newConnSet()
	s.closeAll() // simulate shutdown having already completed a pass

	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	s.add(server)

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := client.Read(buf); err == nil {
		t.Fatal("expected a connection added after closeAll to be closed immediately")
	}
}

func TestConnSetRemoveThenCloseAllSkipsRemoved(t *testing.T) {
	s := newConnSet()
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	t.Cleanup(func() { _ = client.Close() })
	s.add(server)
	s.remove(server)

	s.closeAll()

	// server was never closed by closeAll (it was removed first), so a read
	// with a short deadline should time out rather than observe a close.
	_ = client.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 1)
	_, err := client.Read(buf)
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("expected a read timeout (conn not closed), got %v", err)
	}
}
