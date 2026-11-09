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
	// srvCtx is cancelled on every return path so the watchdog goroutine always
	// exits; otherwise it stays parked forever when ServeControl returns via a
	// closed listener or an Accept error (permanently so under
	// context.Background(), whose Done() is a nil channel).
	srvCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-srvCtx.Done()
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
	// Cancel srvCtx first, so a handler blocked in a shared key store call
	// returns now instead of at its own timeout.
	defer func() {
		cancel()
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
			a.handleControlConn(srvCtx, conn)
		}()
	}
}

func (a *Agent) handleControlConn(ctx context.Context, conn net.Conn) {
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
		reply := a.dispatch(ctx, cmd)
		if err := writeFrame(conn, reply); err != nil {
			a.logger.Debug("control write failed", "error", err)
			return
		}
	}
}

// dispatch executes a single control command and returns its reply. Key
// commands act on cmd.Profile, which may be omitted when the agent has one
// profile. ctx bounds any shared key store calls the command makes.
func (a *Agent) dispatch(ctx context.Context, cmd Command) Reply {
	switch cmd.Command {
	case CmdInfo:
		if cmd.Profile == "" && len(a.profiles) > 1 {
			return Reply{Ok: true, Profiles: a.ProfilesInfo()}
		}
	case CmdGenStagedKey, CmdInstallKey, CmdDropKey:
	default:
		return Reply{
			Ok:    false,
			Error: fmt.Sprintf("unknown command %q", cmd.Command),
		}
	}
	p, err := a.profileByName(cmd.Profile)
	if err != nil {
		return Reply{Ok: false, Error: err.Error()}
	}
	switch cmd.Command {
	case CmdGenStagedKey:
		vkey, err := p.genStagedKey(ctx)
		if err != nil {
			return Reply{Ok: false, Error: err.Error()}
		}
		return Reply{Ok: true, KESVKey: vkey, Info: a.profileInfo(p)}
	case CmdInstallKey:
		if _, err := p.installKey(ctx, cmd.OpCert); err != nil {
			return Reply{Ok: false, Error: err.Error()}
		}
		return Reply{Ok: true, Info: a.profileInfo(p)}
	case CmdDropKey:
		if err := p.DropKey(cmd.Target); err != nil {
			return Reply{Ok: false, Error: err.Error()}
		}
		return Reply{Ok: true, Info: a.profileInfo(p)}
	default: // CmdInfo
		return Reply{Ok: true, Info: a.profileInfo(p)}
	}
}
