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
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// blackholeProxy forwards TCP to a backend. blackholeOpen makes every
// connection open at that moment read and discard bytes in both directions,
// with no FIN or RST, as when a host is lost. Connections accepted afterwards
// reach the live backend.
type blackholeProxy struct {
	ln      net.Listener
	backend string
	wg      sync.WaitGroup
	mu      sync.Mutex
	conns   []net.Conn
	cuts    []*atomic.Bool
	closed  bool
}

func newBlackholeProxy(t *testing.T, backend string) *blackholeProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &blackholeProxy{ln: ln, backend: backend}
	p.wg.Add(1)
	go p.accept()
	t.Cleanup(p.close)
	return p
}

func (p *blackholeProxy) accept() {
	defer p.wg.Done()
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		b, err := net.Dial("tcp", p.backend)
		if err != nil {
			_ = c.Close()
			continue
		}
		cut := new(atomic.Bool)
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			_ = c.Close()
			_ = b.Close()
			return
		}
		p.conns = append(p.conns, c, b)
		p.cuts = append(p.cuts, cut)
		p.mu.Unlock()
		p.wg.Add(2)
		go p.pipe(b, c, cut)
		go p.pipe(c, b, cut)
	}
}

func (p *blackholeProxy) pipe(dst, src net.Conn, cut *atomic.Bool) {
	defer p.wg.Done()
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 && !cut.Load() {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// blackholeOpen silences every connection currently open.
func (p *blackholeProxy) blackholeOpen() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.cuts {
		c.Store(true)
	}
}

func (p *blackholeProxy) close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	_ = p.ln.Close()
	for _, c := range p.conns {
		_ = c.Close()
	}
	p.mu.Unlock()
	p.wg.Wait()
}

// A pooled connection that goes silent without a reset must not cost the
// guard write: pgxpool pings a connection idle for over a second on acquire,
// and an unbounded ping spends the caller's whole context, leaving none to
// dial a fresh connection.
func TestPostgres_DeadIdleConnectionDoesNotConsumeWriteContext(t *testing.T) {
	t.Parallel()
	cfg, err := pgconn.ParseConfig(testPGDSN(t))
	if err != nil {
		t.Fatalf("parse %s: %v", pgDSNEnv, err)
	}
	if strings.HasPrefix(cfg.Host, "/") {
		t.Skipf("%s uses a Unix socket; the proxy relays TCP", pgDSNEnv)
	}
	proxy := newBlackholeProxy(t, net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port)))
	// The proxy is a plain TCP relay, so the test backend must accept
	// connections without TLS.
	dsn := (&url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(cfg.User, cfg.Password),
		Host:     proxy.ln.Addr().String(),
		Path:     "/" + cfg.Database,
		RawQuery: "sslmode=disable",
	}).String()
	wm := newTestPG(t, dsn)
	// Cleanups run last-in first-out: cut the proxy before the pool closes so
	// closing the silent connection does not wait out pgx's close timeout.
	t.Cleanup(proxy.close)

	// The pool now holds one idle connection. pgxpool pings it on acquire
	// once it has been idle for over one second.
	time.Sleep(1200 * time.Millisecond)
	proxy.blackholeOpen()

	const guardBudget = 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), guardBudget)
	defer cancel()
	start := time.Now()
	if err := wm.CheckAndCommit(ctx, randKey(t), "tx", []byte("A")); err != nil {
		t.Fatalf(
			"write after %s through a silent idle connection: %v",
			time.Since(start), err,
		)
	}
	if got := time.Since(start); got >= guardBudget/2 {
		t.Fatalf("write took %s; a dead connection must fail its ping fast", got)
	}
}
