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
	"sync"
)

// connSet tracks live accepted connections so an accept loop can close them
// on shutdown. Closing only the listener (as net.Listener.Close does) does
// not unblock a handler already parked in a blocking read on a connection
// that was accepted before shutdown; that leaves ServeService/ServeControl's
// wg.Wait() unable to complete. connSet lets the accept loop reach into
// those already-accepted connections and close them too.
type connSet struct {
	mu sync.Mutex
	m  map[net.Conn]struct{}
}

func newConnSet() *connSet {
	return &connSet{m: make(map[net.Conn]struct{})}
}

func (s *connSet) add(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[c] = struct{}{}
}

func (s *connSet) remove(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, c)
}

// closeAll closes every tracked connection. Safe to call concurrently with
// add/remove; a connection removed just before closeAll iterates it is
// simply skipped.
func (s *connSet) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.m {
		_ = c.Close()
	}
}
