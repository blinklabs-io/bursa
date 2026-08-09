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
	"sync"
)

// Control command names.
const (
	CmdGenStagedKey = "gen-staged-key"
	CmdInstallKey   = "install-key"
	CmdDropKey      = "drop-key"
	CmdInfo         = "info"
)

// ServeControl accepts connections on ln and processes control commands until
// ctx is cancelled or ln is closed.
func (a *Agent) ServeControl(ctx context.Context, ln net.Listener) error {
	conns := newConnSet()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
		// Unblock any handler already parked in a read on a connection
		// accepted before shutdown, so wg.Wait() below can complete.
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
				return fmt.Errorf("kesagent: control accept: %w", err)
			}
		}
		conns.add(conn)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conns.remove(conn)
			a.handleControlConn(conn)
		}()
	}
}

func (a *Agent) handleControlConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	// Send the handshake Hello frame (matches the service socket; see the
	// package doc comment in protocol.go).
	if err := writeFrame(conn, Hello{Protocol: ProtocolID, Mode: a.cfg.Mode}); err != nil {
		a.logger.Debug("control hello write failed", "error", err)
		return
	}
	for {
		var cmd Command
		if err := readFrame(conn, &cmd); err != nil {
			if !errors.Is(err, io.EOF) {
				a.logger.Debug("control read failed", "error", err)
			}
			return
		}
		reply := a.dispatch(cmd)
		if err := writeFrame(conn, reply); err != nil {
			a.logger.Debug("control write failed", "error", err)
			return
		}
	}
}

// dispatch executes a single control command and returns its reply.
func (a *Agent) dispatch(cmd Command) Reply {
	switch cmd.Command {
	case CmdGenStagedKey:
		vkey, err := a.GenStagedKey()
		if err != nil {
			return Reply{Ok: false, Error: err.Error()}
		}
		return Reply{Ok: true, KESVKey: vkey, Info: a.Info()}
	case CmdInstallKey:
		info, err := a.InstallKey(cmd.OpCert)
		if err != nil {
			return Reply{Ok: false, Error: err.Error()}
		}
		return Reply{Ok: true, Info: info}
	case CmdDropKey:
		if err := a.DropKey(cmd.Target); err != nil {
			return Reply{Ok: false, Error: err.Error()}
		}
		return Reply{Ok: true, Info: a.Info()}
	case CmdInfo:
		return Reply{Ok: true, Info: a.Info()}
	default:
		return Reply{Ok: false, Error: fmt.Sprintf("unknown command %q", cmd.Command)}
	}
}
