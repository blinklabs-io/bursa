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
	"net"
	"testing"
	"time"

	"github.com/blinklabs-io/gouroboros/kes"
)

func startControl(t *testing.T, a *Agent) net.Conn {
	t.Helper()
	sock := shortSocketPath(t, "ctrl.sock")
	ln, err := ListenUnix(sock, 0o600)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = a.ServeControl(ctx, ln) }()
	conn := dial(t, sock)
	var hello Hello
	if err := readFrame(conn, &hello); err != nil {
		t.Fatalf("read control hello: %v", err)
	}
	if hello.Protocol != ProtocolID {
		t.Fatalf("bad control hello: %+v", hello)
	}
	return conn
}

func request(t *testing.T, conn net.Conn, cmd Command) Reply {
	t.Helper()
	if err := writeFrame(conn, cmd); err != nil {
		t.Fatalf("write command %q: %v", cmd.Command, err)
	}
	var reply Reply
	if err := readFrame(conn, &reply); err != nil {
		t.Fatalf("read reply for %q: %v", cmd.Command, err)
	}
	return reply
}

func TestControlGenInstallInfoDrop(t *testing.T) {
	cold := newColdKey(t)
	a := testAgent(t, ModeServeKey, cold, kes.CardanoKesDepth, atPeriod(5))
	conn := startControl(t, a)

	// gen-staged-key
	genReply := request(t, conn, Command{Command: CmdGenStagedKey})
	if !genReply.Ok || len(genReply.KESVKey) != kes.PublicKeySize {
		t.Fatalf("gen-staged-key reply: %+v", genReply)
	}
	vkey := genReply.KESVKey

	// install-key with a valid opcert
	opcert := makeOpCert(t, vkey, 1, 3, cold)
	instReply := request(t, conn, Command{Command: CmdInstallKey, OpCert: opcert})
	if !instReply.Ok {
		t.Fatalf("install failed: %s", instReply.Error)
	}
	if instReply.Info == nil || !instReply.Info.HasActiveKey || instReply.Info.ActivePeriod != 5 {
		t.Fatalf("install info: %+v", instReply.Info)
	}

	// info
	infoReply := request(t, conn, Command{Command: CmdInfo})
	if !infoReply.Ok || infoReply.Info.Version != "test" {
		t.Fatalf("info reply: %+v", infoReply)
	}

	// drop-key
	dropReply := request(t, conn, Command{Command: CmdDropKey, Target: "active"})
	if !dropReply.Ok || dropReply.Info.HasActiveKey {
		t.Fatalf("drop reply: %+v", dropReply)
	}
}

func TestControlInstallOpCertMismatchRejected(t *testing.T) {
	cold := newColdKey(t)
	other := newColdKey(t)
	a := testAgent(t, ModeServeKey, cold, kes.CardanoKesDepth, atPeriod(5))
	conn := startControl(t, a)

	genReply := request(t, conn, Command{Command: CmdGenStagedKey})
	vkey := genReply.KESVKey

	// Opcert signed by the wrong cold key.
	reply := request(t, conn, Command{
		Command: CmdInstallKey,
		OpCert:  makeOpCert(t, vkey, 1, 3, other),
	})
	if reply.Ok || reply.Error == "" {
		t.Fatalf("expected rejection for mismatched opcert, got %+v", reply)
	}
}

func TestControlUnknownCommand(t *testing.T) {
	cold := newColdKey(t)
	a := testAgent(t, ModeSign, cold, kes.CardanoKesDepth, atPeriod(1))
	conn := startControl(t, a)
	reply := request(t, conn, Command{Command: "bogus"})
	if reply.Ok || reply.Error == "" {
		t.Fatalf("expected error for unknown command, got %+v", reply)
	}
}

// TestServeControlShutdownWithIdleConnection guards against a shutdown hang:
// an idle client that never sends another command must not prevent
// ServeControl from returning once ctx is cancelled.
func TestServeControlShutdownWithIdleConnection(t *testing.T) {
	cold := newColdKey(t)
	a := testAgent(t, ModeSign, cold, kes.CardanoKesDepth, atPeriod(1))
	sock := shortSocketPath(t, "ctrl-shutdown.sock")
	ln, err := ListenUnix(sock, 0o600)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- a.ServeControl(ctx, ln) }()

	conn := dial(t, sock) // stays open and idle; never sends a command
	var hello Hello
	if err := readFrame(conn, &hello); err != nil {
		t.Fatalf("read control hello: %v", err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeControl returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeControl did not return within 2s of an idle connection outliving shutdown")
	}
}
