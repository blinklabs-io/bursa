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

//go:build pkcs11

package backend

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/pkcs11"
)

func newTestPKCS11Backend(nativeSign func(pkcs11.ObjectHandle, []byte) ([]byte, error)) *PKCS11Backend {
	b := &PKCS11Backend{
		requests:   make(chan pkcs11SignRequest, maxQueuedPKCS11Signs),
		closeDone:  make(chan struct{}),
		nativeSign: nativeSign,
	}
	b.workerWG.Add(1)
	go b.signWorker()
	return b
}

func TestPKCS11Sign_ContextCancellationDoesNotConcurrentSessionUse(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var active atomic.Int32
	var maxActive atomic.Int32
	b := newTestPKCS11Backend(func(pkcs11.ObjectHandle, []byte) ([]byte, error) {
		current := active.Add(1)
		for {
			old := maxActive.Load()
			if current <= old || maxActive.CompareAndSwap(old, current) {
				break
			}
		}
		defer active.Add(-1)
		select {
		case <-started:
		default:
			close(started)
		}
		<-release
		return make([]byte, ed25519.SignatureSize), nil
	})

	key := &pkcs11Key{sign: b.signWithSession}
	ctx, cancel := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() {
		_, err := key.Sign(ctx, []byte("first"))
		firstDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("native signing did not start")
	}
	cancel()
	select {
	case err := <-firstDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context cancellation, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("sign did not honor canceled context while native call was active")
	}

	secondCtx, secondCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer secondCancel()
	if _, err := key.Sign(secondCtx, []byte("second")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected bounded queue wait, got %v", err)
	}
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("expected one native operation, got peak concurrency %d", got)
	}

	close(release)
	if err := b.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestPKCS11Sign_CanceledQueuedRequestIsNotSentToToken(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	var calls atomic.Int32
	b := newTestPKCS11Backend(func(pkcs11.ObjectHandle, []byte) ([]byte, error) {
		calls.Add(1)
		close(started)
		<-release
		return make([]byte, ed25519.SignatureSize), nil
	})
	key := &pkcs11Key{sign: b.signWithSession}

	firstDone := make(chan struct{})
	go func() {
		_, _ = key.Sign(context.Background(), []byte("first"))
		close(firstDone)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("native signing did not start")
	}

	ctx, cancel := context.WithCancel(context.Background())
	queuedDone := make(chan error, 1)
	go func() {
		_, err := key.Sign(ctx, []byte("queued"))
		queuedDone <- err
	}()
	deadline := time.After(time.Second)
	for len(b.requests) != 1 {
		select {
		case <-deadline:
			t.Fatal("queued sign was not enqueued")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	select {
	case err := <-queuedDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected queued cancellation, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued sign did not honor cancellation")
	}
	close(release)
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first sign did not finish")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected canceled queued request to be skipped, got %d token calls", got)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// The production caller — handleSign, via Coordinator.SignTx — passes the HTTP
// request's context straight through, and the signer server sets no handler
// timeout, so a caller-supplied bound cannot be relied on. A wedged token must
// not be able to hold a signing call open indefinitely on that path.
func TestPKCS11Sign_BoundsAnUnboundedCallerContext(t *testing.T) {
	restore := defaultPKCS11SignTimeoutForTest(50 * time.Millisecond)
	defer restore()

	wedged := make(chan struct{})
	defer close(wedged)
	b := newTestPKCS11Backend(func(pkcs11.ObjectHandle, []byte) ([]byte, error) {
		<-wedged
		return make([]byte, ed25519.SignatureSize), nil
	})
	key := &pkcs11Key{sign: b.signWithSession}

	done := make(chan error, 1)
	go func() {
		// context.Background() has no deadline: the bound has to come from the
		// backend itself.
		_, err := key.Sign(context.Background(), []byte("msg"))
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Sign = %v, want the backend's own deadline", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Sign did not return: an unbounded caller context left it waiting on the token")
	}
}

// defaultPKCS11SignTimeoutForTest shortens the backend's self-imposed signing
// bound and returns a function restoring it.
func defaultPKCS11SignTimeoutForTest(d time.Duration) func() {
	prev := defaultPKCS11SignTimeout
	defaultPKCS11SignTimeout = d
	return func() { defaultPKCS11SignTimeout = prev }
}
