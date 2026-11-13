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
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/gouroboros/kes"
)

// serveControlAt runs a's control socket at a short path and returns it.
func serveControlAt(t *testing.T, a *Agent) string {
	t.Helper()
	sock := shortSocketPath(t, "ctrl.sock")
	ln, err := ListenUnix(sock, 0o600)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = a.ServeControl(ctx, ln) }()
	return sock
}

func TestControlRequestStagesAndInstallsAKey(t *testing.T) {
	cold := newColdKey(t)
	a := testAgent(t, ModeSign, cold, kes.CardanoKesDepth, atPeriod(5))
	sock := serveControlAt(t, a)
	ctx := context.Background()

	gen, err := ControlRequest(ctx, sock, Command{Command: CmdGenStagedKey})
	if err != nil {
		t.Fatalf("gen-staged-key: %v", err)
	}
	if !gen.Ok || len(gen.KESVKey) != kes.PublicKeySize {
		t.Fatalf("gen-staged-key reply: %+v", gen)
	}

	// Each request is its own connection, as each CLI run is.
	inst, err := ControlRequest(ctx, sock, Command{
		Command: CmdInstallKey,
		OpCert:  makeOpCert(t, gen.KESVKey, 1, 3, cold),
	})
	if err != nil {
		t.Fatalf("install-key: %v", err)
	}
	if !inst.Ok || inst.Info == nil || !inst.Info.HasActiveKey {
		t.Fatalf("install-key reply: %+v", inst)
	}

	info, err := ControlRequest(ctx, sock, Command{Command: CmdInfo})
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	if !info.Ok || info.Info == nil || info.Info.ActivePeriod != 5 {
		t.Fatalf("info reply: %+v", info)
	}
}

func TestControlRequestReturnsAnAgentRefusal(t *testing.T) {
	cold := newColdKey(t)
	a := testAgent(t, ModeSign, cold, kes.CardanoKesDepth, atPeriod(5))
	sock := serveControlAt(t, a)

	// No key is staged, so the agent refuses the install. A refusal is a
	// reply, not a transport error.
	reply, err := ControlRequest(context.Background(), sock, Command{
		Command: CmdInstallKey,
		OpCert:  []byte{0x80},
	})
	if err != nil {
		t.Fatalf("install-key: %v", err)
	}
	if reply.Ok || reply.Error == "" {
		t.Fatalf("expected a refusal, got %+v", reply)
	}
}

func TestControlRequestRefusesAnotherProtocol(t *testing.T) {
	sock := shortSocketPath(t, "other.sock")
	ln, err := ListenUnix(sock, 0o600)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = writeFrame(conn, Hello{Protocol: "something-else/1"})
		time.Sleep(time.Second)
	}()

	_, err = ControlRequest(context.Background(), sock, Command{Command: CmdInfo})
	if err == nil || !strings.Contains(err.Error(), "something-else/1") {
		t.Fatalf("expected a protocol mismatch, got %v", err)
	}
}

func TestControlRequestReportsAMissingSocket(t *testing.T) {
	sock := shortSocketPath(t, "absent.sock")
	_, err := ControlRequest(context.Background(), sock, Command{Command: CmdInfo})
	if err == nil || !strings.Contains(err.Error(), sock) {
		t.Fatalf("expected a dial error naming the socket, got %v", err)
	}
}

func TestControlRequestStopsWhenTheContextIsCancelled(t *testing.T) {
	sock := shortSocketPath(t, "silent.sock")
	ln, err := ListenUnix(sock, 0o600)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// A hello, then no reply to the command.
		_ = writeFrame(conn, Hello{Protocol: ProtocolID})
		<-release
	}()

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	_, err = ControlRequest(ctx, sock, Command{Command: CmdInfo})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the request returned %v after the cancel", elapsed)
	}
}
