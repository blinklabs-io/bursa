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

// Package mobile is the gomobile binding for the Bursa full-node wallet. It is
// compiled to a native library (an Android AAR via `gomobile bind
// -target=android`, an Apple xcframework via `-target=ios`) and consumed by the
// Android/iOS shells in ../../mobile. Each shell boots the wallet in-process and
// points a system WebView at the loopback URL the wallet serves the embedded SPA
// on.
//
// gomobile constraint: only a fixed set of types cross the language boundary —
// bool, int/int64, float, string, []byte, error, and exported structs/methods.
// NO maps, slices-of-structs, channels, or other Go types may appear in any
// EXPORTED signature here. App keeps all its fields unexported (so the struct
// crosses as an opaque handle) and every exported method uses only the supported
// scalar/error types.
package mobile

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/blinklabs-io/bursa/ui/internal/boot"
)

const defaultStartTimeout = 2 * time.Minute

var (
	errStartTimeout = errors.New("mobile: start timed out")
	bootWallet      = boot.Boot
)

// App is an opaque handle to a booted in-process wallet. It is returned by New
// and driven by the Android/iOS shells: Start boots the stack, Port reports the
// loopback port the WebView should load, and Stop tears it down. All fields are
// unexported so gomobile treats it as an opaque reference type.
type App struct {
	mu          sync.Mutex
	app         runtimeApp
	starting    bool
	startCancel context.CancelFunc
	// startDone is created before each boot goroutine launches and is closed
	// only after that boot has either completed normally or its canceled result
	// has been collected and stopped. Stop publishes this channel as draining
	// before it cancels, so an immediate retry waits even if the canceled
	// StartWithTimeout goroutine has not observed ctx.Done yet.
	startDone chan struct{}
	startID   uint64
	// draining is the done-channel of an in-flight (or already-finished)
	// cleanupLateStart watching a superseded/canceled start. StartWithTimeout
	// waits on it before rebinding boot's fixed node ports (5555/5556), so a
	// rapid Stop-then-retry can't race a still-unwinding canceled boot for those
	// ports. The channel is registered before boot launch (startDone) and
	// published when the start is canceled, not after the canceled start notices
	// cancellation. Reading an already-closed channel never blocks, so once
	// cleanup finishes this becomes a no-op wait; it is never reset to nil.
	draining <-chan struct{}
}

type runtimeApp interface {
	Stop() error
	Port() int
	OnNetworkChanged() error
	OnResume() error
}

// New constructs an unstarted App handle. Call Start to boot the wallet.
func New() *App { return &App{} }

// Start boots the wallet stack in-process and begins serving the embedded SPA +
// API on an OS-assigned loopback port (127.0.0.1:0). It returns once the node
// goroutine is launched and the control surface is accepting connections; node
// sync progress is reported via the /status API the WebView polls. After Start
// returns nil, call Port to learn the loopback port to load in the WebView.
//
// dataDir is the per-app writable directory (Android filesDir, iOS Documents);
// network is "preview" | "preprod" | "mainnet"; lean seeds the first-run
// lean-node (history-expiry) profile (mobile passes true for a small on-disk
// footprint). Calling Start on an already-started App returns an error.
func (a *App) Start(dataDir, network string, lean bool) error {
	return a.StartWithTimeout(dataDir, network, lean, defaultStartTimeout.Milliseconds())
}

// StartWithTimeout is Start with a caller-supplied boot timeout in milliseconds.
// A non-positive timeout uses the default. The boot work runs outside a.mu so
// Port, Stop, and lifecycle kicks are not blocked while startup waits on I/O.
func (a *App) StartWithTimeout(dataDir, network string, lean bool, timeoutMs int64) error {
	timeout := startTimeout(timeoutMs)

	var (
		ctx       context.Context
		cancel    context.CancelFunc
		startDone chan struct{}
		startID   uint64
		waited    <-chan struct{}
	)
	for {
		a.mu.Lock()
		// Wait for a previous canceled/timed-out start's cleanup to finish
		// releasing the fixed node ports before attempting to rebind them here.
		// This check shares the admission lock with Stop/cancelStart so a retry
		// cannot slip between a canceled start being cleared and its drain being
		// published.
		if a.draining != nil && a.draining != waited {
			draining := a.draining
			a.mu.Unlock()
			<-draining
			waited = draining
			continue
		}
		if a.app != nil {
			a.mu.Unlock()
			return errors.New("mobile: already started")
		}
		if a.starting {
			a.mu.Unlock()
			return errors.New("mobile: start already in progress")
		}
		ctx, cancel = context.WithCancel(context.Background())
		startDone = make(chan struct{})
		a.starting = true
		a.startCancel = cancel
		a.startDone = startDone
		a.startID++
		startID = a.startID
		a.mu.Unlock()
		break
	}

	// Mithril fast-sync keeps the first sync (and the on-disk footprint, paired
	// with the lean profile) practical on a mobile device.
	result := make(chan startResult, 1)
	go func() {
		app, err := bootWallet(ctx, boot.Config{
			Network:        network,
			DataDir:        dataDir,
			Addr:           "127.0.0.1:0", // OS-assigned loopback port for the WebView
			MithrilEnabled: true,
			LeanDefault:    lean,
		})
		var runtime runtimeApp
		if app != nil {
			runtime = app
		}
		result <- startResult{app: runtime, err: err}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case res := <-result:
		return a.finishStart(startID, cancel, startDone, res)
	case <-timer.C:
		cancel()
		a.cancelStart(startID, startDone)
		cleanupStartResult(result, startDone)
		return fmt.Errorf("%w after %s", errStartTimeout, timeout)
	case <-ctx.Done():
		a.cancelStart(startID, startDone)
		cleanupStartResult(result, startDone)
		return ctx.Err()
	}
}

type startResult struct {
	app runtimeApp
	err error
}

func startTimeout(timeoutMs int64) time.Duration {
	if timeoutMs <= 0 {
		return defaultStartTimeout
	}
	return time.Duration(timeoutMs) * time.Millisecond
}

func (a *App) finishStart(startID uint64, cancel context.CancelFunc, done chan struct{}, res startResult) error {
	defer close(done)

	a.mu.Lock()
	if a.startID != startID || !a.starting {
		a.mu.Unlock()
		cancel()
		if res.app != nil {
			_ = res.app.Stop()
		}
		if res.err != nil {
			return res.err
		}
		return context.Canceled
	}
	a.starting = false
	a.startCancel = nil
	a.startDone = nil
	if res.err != nil {
		a.mu.Unlock()
		cancel()
		return res.err
	}
	a.app = res.app
	a.mu.Unlock()
	return nil
}

func (a *App) cancelStart(startID uint64, done <-chan struct{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.startID != startID || !a.starting {
		return
	}
	a.starting = false
	a.startCancel = nil
	a.startDone = nil
	a.startID++
	a.draining = done
}

// cleanupLateStart waits for a superseded/canceled start's boot result and, if
// bootWallet went on to return a live *boot.App despite the supersede, stops it
// so the abandoned start doesn't leak a running node or its sockets.
//
// The wait is unconditional — it does NOT select on ctx.Done(). Callers invoke
// this only after cancel() has already fired, so ctx.Done() is already closed
// by the time this runs: a `case <-ctx.Done(): return` would fire immediately
// and abandon the watch right when a live, fully-booted App could still be in
// flight — the exact node/socket leak this function exists to prevent (see
// boot.Boot returning a live App promptly after cancellation, e.g. via the
// timeout path).
//
// The unconditional wait is safe because bootWallet (boot.Boot) is itself
// ctx-aware: it checks ctx.Err() before doing any work and again right after
// the node/control surface are launched, tearing down and returning an error
// instead of a live App whenever it observes cancellation. Every step in
// between is local, bounded work (no network/readiness waits), so bootWallet's
// return is guaranteed to happen in bounded time — which is what makes this
// goroutine guaranteed to terminate rather than leak.
//
// It returns a channel that is closed once the goroutine has finished (Stop
// called, if applicable). Tests use the channel to deterministically observe
// completion instead of polling.
func cleanupLateStart(result <-chan startResult) <-chan struct{} {
	done := make(chan struct{})
	cleanupStartResult(result, done)
	return done
}

func cleanupStartResult(result <-chan startResult, done chan struct{}) {
	go func() {
		defer close(done)
		res := <-result
		if res.app != nil {
			_ = res.app.Stop()
		}
	}()
}

// Port returns the OS-assigned loopback TCP port the control surface is serving
// on, for the WebView to load (http://127.0.0.1:<port>/). It returns 0 before a
// successful Start.
func (a *App) Port() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.app == nil {
		return 0
	}
	return a.app.Port()
}

// OnNetworkChanged re-dials the embedded node's peers after the host network
// changes (WiFi↔cellular, loss→regain). It is called from the Android
// ConnectivityManager.NetworkCallback and must be safe to call from any thread.
// It is a safe no-op before Start.
func (a *App) OnNetworkChanged() error {
	a.mu.Lock()
	app := a.app
	a.mu.Unlock()
	if app == nil {
		return nil
	}
	return app.OnNetworkChanged()
}

// OnResume re-dials the embedded node's peers after the app returns from the
// background. It is called from the Android Activity.onResume and must be safe
// to call from any thread. Peers go stale during suspension so a re-dial cycle
// re-establishes them without data loss. It is a safe no-op before Start.
func (a *App) OnResume() error {
	a.mu.Lock()
	app := a.app
	a.mu.Unlock()
	if app == nil {
		return nil
	}
	return app.OnResume()
}

// Stop tears the wallet down cleanly: it drains the control surface and winds
// down the in-process node. It is safe to call more than once; calling it before
// Start is a no-op.
func (a *App) Stop() error {
	a.mu.Lock()
	if a.starting {
		cancel := a.startCancel
		done := a.startDone
		a.starting = false
		a.startCancel = nil
		a.startDone = nil
		a.startID++
		if done != nil {
			a.draining = done
		}
		a.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		return nil
	}
	if a.app == nil {
		a.mu.Unlock()
		return nil
	}
	app := a.app
	a.app = nil
	a.mu.Unlock()
	return app.Stop()
}
