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
package boot

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestBootValidatesConfig covers the cheap, no-node validation paths so a
// misconfiguration is reported synchronously by Boot (before any node is
// launched) rather than failing later.
func TestBootValidatesConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantSub string
	}{
		{
			name:    "missing network",
			cfg:     Config{DataDir: t.TempDir()},
			wantSub: "network is required",
		},
		{
			name:    "missing data dir",
			cfg:     Config{Network: "preview"},
			wantSub: "data dir is required",
		},
		{
			name:    "invalid network",
			cfg:     Config{Network: "bogus", DataDir: t.TempDir()},
			wantSub: "invalid network",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			app, err := Boot(context.Background(), tc.cfg)
			if app != nil {
				_ = app.Stop()
				t.Fatalf("expected nil App on error, got %v", app)
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// TestBootReturnsContextErrorWhenAlreadyCanceled covers the node-lifecycle
// leak fix for ui/mobile's cleanupLateStart (PR #561 review): a start
// superseded (or timed out) before Boot is even invoked must abort promptly
// with a context error and must never spin up — or hand back — a live App.
// This is what makes cleanupLateStart's unconditional wait for Boot's result
// safe: Boot is bounded and ctx-aware, so the wait cannot leak the watcher
// goroutine and cannot leave a node/socket running behind a caller that has
// already moved on.
func TestBootReturnsContextErrorWhenAlreadyCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	app, err := Boot(ctx, Config{
		Network: "preview",
		DataDir: t.TempDir(),
		Addr:    "127.0.0.1:0",
	})
	elapsed := time.Since(start)

	if app != nil {
		_ = app.Stop()
		t.Fatalf("expected nil App when ctx is already canceled, got %v", app)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Boot with an already-canceled ctx = %v, want context.Canceled", err)
	}
	// The guard must fire before any node/network work, so this must return
	// almost instantly — a regression back to "ignore ctx" would still return
	// (fast, since nothing in Boot's synchronous path blocks) but with a live
	// App instead of this error, which the case above already catches; the
	// bound here guards against a future step becoming a genuine, unbounded
	// wait that ignores ctx.
	if elapsed > 2*time.Second {
		t.Fatalf("Boot with an already-canceled ctx took %s; want a prompt abort", elapsed)
	}
}
