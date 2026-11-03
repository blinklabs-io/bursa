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
	"net"
	"sync"
)

// ConnLimitListener returns a listener that holds at most n accepted
// connections open at once. Accept waits for a connection to close before
// taking another; closing the listener releases a waiting Accept.
func ConnLimitListener(l net.Listener, n int) net.Listener {
	return &connLimitListener{
		Listener: l,
		slots:    make(chan struct{}, n),
		done:     make(chan struct{}),
	}
}

type connLimitListener struct {
	net.Listener

	slots     chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func (l *connLimitListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}

	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}

	return &limitedConn{Conn: c, release: func() { <-l.slots }}, nil
}

func (l *connLimitListener) Close() error {
	err := net.ErrClosed

	l.closeOnce.Do(func() {
		close(l.done)
		err = l.Listener.Close()
	})

	return err
}

// limitedConn gives its listener slot back on its first Close.
type limitedConn struct {
	net.Conn

	release func()
	once    sync.Once
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)

	return err
}
