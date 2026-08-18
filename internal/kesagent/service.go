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
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/blinklabs-io/bursa/internal/kesagent/securemem"
)

// ListenUnix creates a Unix-domain listener at path with the given file mode,
// removing any stale socket first.
func ListenUnix(path string, mode os.FileMode) (net.Listener, error) {
	if path == "" {
		return nil, errors.New("kesagent: socket path is empty")
	}
	// Remove a stale socket if present (only if it is a socket).
	if fi, err := os.Stat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("kesagent: refusing to remove non-socket %q", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("kesagent: remove stale socket %q: %w", path, err)
		}
	}
	// net.Listen creates the socket under the process umask, so its requested
	// mode only lands one Chmod later — a window in which the socket can be
	// world-writable (under umask 0/0002) and a connection made during it
	// survives the tightening (Unix checks permission at connect time). Behind
	// this socket is the KES block-production signing key, so close the window
	// rather than trusting the deployment umask: bind inside a fresh 0700
	// staging directory (which no other user can traverse), chmod the socket to
	// its final mode there, and only expose it at its advertised path via an
	// atomic rename. This avoids the process-global, listen-racy syscall.Umask
	// approach and stays pure-Go / cross-platform.
	stagingDir, err := os.MkdirTemp(filepath.Dir(path), ".kes-sock-")
	if err != nil {
		return nil, fmt.Errorf("kesagent: create socket staging dir for %q: %w", path, err)
	}
	defer func() { _ = os.RemoveAll(stagingDir) }()
	stagingPath := filepath.Join(stagingDir, "s")
	ln, err := net.Listen("unix", stagingPath)
	if err != nil {
		return nil, fmt.Errorf("kesagent: listen %q: %w", path, err)
	}
	if err := os.Chmod(stagingPath, mode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("kesagent: chmod socket %q: %w", path, err)
	}
	if err := os.Rename(stagingPath, path); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("kesagent: publish socket %q: %w", path, err)
	}
	return ln, nil
}

// ServeService accepts connections on ln and serves them according to the
// agent's configured mode. It returns when ctx is cancelled or ln is closed.
func (a *Agent) ServeService(ctx context.Context, ln net.Listener) error {
	conns := newConnSet()
	// srvCtx is cancelled on every return path (not just external ctx
	// cancellation), so the watchdog goroutine below always exits — otherwise it
	// stays parked in the receive forever when ServeService returns via a closed
	// listener or an Accept error, and permanently so under context.Background()
	// (whose Done() is a nil channel).
	srvCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-srvCtx.Done()
		_ = ln.Close()
		// Unblock any handler already parked in a read on a connection
		// accepted before shutdown (in particular handleSign, which has no
		// other way to observe ctx cancellation while blocked in readFrame),
		// so wg.Wait() below can complete.
		conns.closeAll()
	}()
	var wg sync.WaitGroup
	// Close every tracked connection before waiting on every return path, not
	// just the ctx-cancellation goroutine above: a listener closed externally
	// (or any non-context Accept error) must also unblock handlers already
	// parked in a blocking read, or wg.Wait() below hangs forever.
	defer func() {
		conns.closeAll()
		wg.Wait()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("kesagent: service accept: %w", err)
			}
		}
		if !conns.add(conn) {
			// Shutting down, or the concurrent-connection ceiling was hit:
			// close and drop this connection rather than serving it.
			_ = conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conns.remove(conn)
			a.handleServiceConn(ctx, conn)
		}()
	}
}

func (a *Agent) handleServiceConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	// Send the handshake Hello frame.
	if err := writeFrame(conn, Hello{Protocol: ProtocolID, Mode: a.cfg.Mode}); err != nil {
		a.logger.Debug("service hello write failed", "error", err)
		return
	}
	switch a.cfg.Mode {
	case ModeServeKey:
		a.handleServeKey(ctx, conn)
	case ModeSign:
		a.handleSign(ctx, conn)
	}
}

func (a *Agent) handleServeKey(ctx context.Context, conn net.Conn) {
	id, ch, current := a.subscribe()
	defer a.unsubscribe(id)
	a.metrics.addConns(1)
	defer a.metrics.addConns(-1)

	// Detect client disconnect: reads on a serve-key client should only ever
	// return EOF/error, which we use to cancel this connection.
	connClosed := make(chan struct{})
	go func() {
		defer close(connClosed)
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
	}()

	if current != nil {
		err := writeFrame(conn, *current)
		// Wipe the plaintext signing-key copy as soon as it has been written
		// (or failed to): it is a swappable-heap clone the securemem locking
		// and forward-erasure elsewhere exist to avoid leaving behind.
		securemem.Wipe(current.KESSignKey)
		if err != nil {
			a.logger.Debug("service key push write failed", "error", err)
			return
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-connClosed:
			return
		case kp := <-ch:
			err := writeFrame(conn, kp)
			securemem.Wipe(kp.KESSignKey) // erase this subscriber's copy
			if err != nil {
				a.logger.Debug("service key push write failed", "error", err)
				return
			}
		}
	}
}

func (a *Agent) handleSign(ctx context.Context, conn net.Conn) {
	for {
		if ctx.Err() != nil {
			return
		}
		var req SignRequest
		if err := readFrame(conn, &req); err != nil {
			if !errors.Is(err, io.EOF) {
				a.logger.Debug("service sign read failed", "error", err)
			}
			return
		}
		resp := SignResponse{Type: "sign_response", Period: req.Period}
		sig, err := a.Sign(req.Period, req.Message)
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.Signature = sig
		}
		if err := writeFrame(conn, resp); err != nil {
			a.logger.Debug("service sign response write failed", "error", err)
			return
		}
	}
}
