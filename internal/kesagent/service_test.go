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
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blinklabs-io/gouroboros/kes"
)

// shortSocketPath returns a short socket path (Unix socket paths are limited to
// ~104 bytes, and t.TempDir() names can be long).
func shortSocketPath(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "kes")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, name)
}

// statMode returns the file mode bits of path.
func statMode(path string) (os.FileMode, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return fi.Mode(), nil
}

func dial(t *testing.T, path string) net.Conn {
	t.Helper()
	var conn net.Conn
	var err error
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.Dial("unix", path)
		if err == nil {
			t.Cleanup(func() { _ = conn.Close() })
			return conn
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("dial %q: %v", path, err)
	return nil
}

func TestServiceServeKeyMode(t *testing.T) {
	cold := newColdKey(t)
	a := testAgent(t, ModeServeKey, cold, kes.CardanoKesDepth, atPeriod(5))
	vkey, _ := a.GenStagedKey()
	if _, err := a.InstallKey(makeOpCert(t, vkey, 1, 3, cold)); err != nil {
		t.Fatalf("InstallKey: %v", err)
	}

	sock := shortSocketPath(t, "svc.sock")
	ln, err := ListenUnix(sock, 0o600)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = a.ServeService(ctx, ln) }()

	// Verify the socket file permission is 0600.
	if fi, err := statMode(sock); err != nil {
		t.Fatalf("stat socket: %v", err)
	} else if fi&0o777 != 0o600 {
		t.Fatalf("socket mode = %o, want 600", fi&0o777)
	}

	conn := dial(t, sock)
	// Bound every read below so a handler that fails to send a frame fails the
	// test fast instead of blocking until the go-test timeout.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	var hello Hello
	if err := readFrame(conn, &hello); err != nil {
		t.Fatalf("read hello: %v", err)
	}
	if hello.Protocol != ProtocolID || hello.Mode != ModeServeKey {
		t.Fatalf("bad hello: %+v", hello)
	}

	var kp KeyPush
	if err := readFrame(conn, &kp); err != nil {
		t.Fatalf("read initial key push: %v", err)
	}
	if kp.Period != 5 {
		t.Fatalf("initial push period = %d, want 5", kp.Period)
	}
	if !bytes.Equal(kp.KESVKey, vkey) {
		t.Fatal("pushed kes vkey mismatch")
	}
	if len(kp.KESSignKey) == 0 || len(kp.OpCert) == 0 {
		t.Fatal("push missing key or opcert bytes")
	}

	// Evolve the key and expect a re-push at the higher period.
	a.now = func() time.Time { return atPeriod(6) }
	a.Tick()

	var kp2 KeyPush
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err := readFrame(conn, &kp2); err != nil {
		t.Fatalf("read re-push: %v", err)
	}
	if kp2.Period != 6 {
		t.Fatalf("re-push period = %d, want 6", kp2.Period)
	}
}

func TestServiceSignMode(t *testing.T) {
	cold := newColdKey(t)
	a := testAgent(t, ModeSign, cold, kes.CardanoKesDepth, atPeriod(5))
	vkey, _ := a.GenStagedKey()
	if _, err := a.InstallKey(makeOpCert(t, vkey, 1, 3, cold)); err != nil {
		t.Fatalf("InstallKey: %v", err)
	}

	sock := shortSocketPath(t, "sign.sock")
	ln, err := ListenUnix(sock, 0o600)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = a.ServeService(ctx, ln) }()

	conn := dial(t, sock)
	// Bound every read below so a handler that fails to send a frame fails the
	// test fast instead of blocking until the go-test timeout.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var hello Hello
	if err := readFrame(conn, &hello); err != nil {
		t.Fatalf("read hello: %v", err)
	}
	if hello.Mode != ModeSign {
		t.Fatalf("bad hello mode: %s", hello.Mode)
	}

	msg := []byte("header")
	if err := writeFrame(conn, SignRequest{Type: "sign_request", Period: 5, Message: msg}); err != nil {
		t.Fatalf("write sign request: %v", err)
	}
	var resp SignResponse
	if err := readFrame(conn, &resp); err != nil {
		t.Fatalf("read sign response: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("unexpected sign error: %s", resp.Error)
	}
	if !kes.VerifySignedKES(vkey, 5-3, msg, resp.Signature) {
		t.Fatal("signature from sign-mode socket failed to verify")
	}

	// A past period must be rejected with an error in the response.
	if err := writeFrame(conn, SignRequest{Type: "sign_request", Period: 4, Message: msg}); err != nil {
		t.Fatalf("write past-period request: %v", err)
	}
	var resp2 SignResponse
	if err := readFrame(conn, &resp2); err != nil {
		t.Fatalf("read past-period response: %v", err)
	}
	if resp2.Error == "" {
		t.Fatal("expected error for past-period sign request")
	}
}

// TestServeServiceShutdownWithIdleConnection guards against a shutdown hang
// symmetric to TestServeControlShutdownWithIdleConnection: handleSign has no
// way to observe ctx cancellation while blocked in readFrame on an idle
// client, so ServeService must force-close tracked connections on shutdown
// rather than relying on the client to disconnect.
func TestServeServiceShutdownWithIdleConnection(t *testing.T) {
	cold := newColdKey(t)
	a := testAgent(t, ModeSign, cold, kes.CardanoKesDepth, atPeriod(1))
	sock := shortSocketPath(t, "sign-shutdown.sock")
	ln, err := ListenUnix(sock, 0o600)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- a.ServeService(ctx, ln) }()

	conn := dial(t, sock) // stays open and idle; never sends a sign request
	var hello Hello
	if err := readFrame(conn, &hello); err != nil {
		t.Fatalf("read service hello: %v", err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeService returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeService did not return within 2s of an idle connection outliving shutdown")
	}
}

// TestServeServiceListenerCloseUnblocksIdleHandler guards against the other
// half of the same hang: a listener closed directly (without ctx being
// cancelled) takes the non-context Accept-error return path, which must
// still close tracked connections before the deferred wg.Wait(), or an idle
// client's handler blocked in readFrame would keep ServeService from
// returning forever.
func TestServeServiceListenerCloseUnblocksIdleHandler(t *testing.T) {
	cold := newColdKey(t)
	a := testAgent(t, ModeSign, cold, kes.CardanoKesDepth, atPeriod(1))
	sock := shortSocketPath(t, "sign-lnclose.sock")
	ln, err := ListenUnix(sock, 0o600)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	// Note: ctx is intentionally never cancelled; only the listener is
	// closed, so the ctx-cancellation goroutine's conns.closeAll() never
	// runs and the fix under test is the accept-error return path's own
	// cleanup.
	ctx := context.Background()

	done := make(chan error, 1)
	go func() { done <- a.ServeService(ctx, ln) }()

	conn := dial(t, sock) // stays open and idle; never sends a sign request
	var hello Hello
	if err := readFrame(conn, &hello); err != nil {
		t.Fatalf("read service hello: %v", err)
	}

	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	select {
	case <-done:
		// Any return (with or without an Accept error) is fine; what matters
		// is that it doesn't hang on the idle handler.
	case <-time.After(2 * time.Second):
		t.Fatal("ServeService did not return within 2s of a direct listener close with an idle connection")
	}
}
