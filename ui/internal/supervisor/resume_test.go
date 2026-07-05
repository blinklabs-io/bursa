// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package supervisor

import (
	"context"
	"errors"
	"testing"

	"github.com/blinklabs-io/dingo"
)

// countingNodeFactory records how many times New is called, so tests can
// assert a node was never constructed (e.g. because Start bailed out on an
// already-canceled ctx before reaching the node factory).
type countingNodeFactory struct{ calls int }

func (f *countingNodeFactory) New(_ dingo.Config) (NodeRunner, error) {
	f.calls++
	return fakeNodeRunner{}, nil
}

// TestStartReturnsContextErrorIfAlreadyCanceled covers the guard added for the
// boot.Boot node-lifecycle leak fix (PR #561 review): a caller that races a
// cancellation against Start (boot.Boot does this on a superseded/timed-out
// mobile start) must get a prompt context error and must NOT have a node
// constructed or launched — the whole point is that no node work happens for a
// start the caller has already abandoned.
func TestStartReturnsContextErrorIfAlreadyCanceled(t *testing.T) {
	factory := &countingNodeFactory{}
	s := New(Config{Network: "preview", DataDir: t.TempDir()})
	s.bootstrapper = &fakeBootstrapper{}
	s.nodeFactory = factory

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := s.Start(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Start with already-canceled ctx = %v, want context.Canceled", err)
	}
	if factory.calls != 0 {
		t.Fatalf("Start constructed a node with an already-canceled context (New called %d times)", factory.calls)
	}
	if got := s.Status().State; got != StateStopped {
		t.Fatalf("state after canceled Start = %q, want stopped", got)
	}

	// The guard must not consume the start reservation: a fresh, uncancelled
	// Start must still succeed afterward.
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start after a canceled attempt = %v, want nil", err)
	}
	t.Cleanup(s.Stop)
	if factory.calls != 1 {
		t.Fatalf("Start after a canceled attempt: New called %d times, want 1", factory.calls)
	}
}

// TestStartWhileRunningReturnsErrAlreadyStarted verifies the start guard: a
// second Start must not overwrite the active node's cancel function and orphan
// its goroutines.
func TestStartWhileRunningReturnsErrAlreadyStarted(t *testing.T) {
	s := New(Config{Network: "preview", DataDir: t.TempDir()})
	s.nodeFactory = fakeNodeFactory{}

	// Start the supervisor so the cancel guard is set.
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("first Start = %v, want nil", err)
	}
	t.Cleanup(s.Stop)

	// Verify the cancel guard is occupied.
	s.mu.Lock()
	guard := s.cancel
	s.mu.Unlock()
	if guard == nil {
		t.Fatal("expected cancel guard to be set after Start")
	}

	// A direct Start while running must return ErrAlreadyStarted — not nil
	// (which would silently accept a double-start bug) and not some other error.
	err := s.Start(context.Background())
	if err == nil {
		t.Fatal("Start while running returned nil; expected ErrAlreadyStarted")
	}
	if !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("Start while running = %v, want ErrAlreadyStarted", err)
	}

}
