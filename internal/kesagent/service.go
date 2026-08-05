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
	"sync"
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
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("kesagent: listen %q: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("kesagent: chmod socket %q: %w", path, err)
	}
	return ln, nil
}

// ServeService accepts connections on ln and serves them according to the
// agent's configured mode. It returns when ctx is cancelled or ln is closed.
func (a *Agent) ServeService(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				wg.Wait()
				return nil
			default:
				return fmt.Errorf("kesagent: service accept: %w", err)
			}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
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
		if err := writeFrame(conn, *current); err != nil {
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
			if err := writeFrame(conn, kp); err != nil {
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
