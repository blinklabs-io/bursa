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
	"sync"

	"github.com/blinklabs-io/bursa/ui/internal/boot"
)

// App is an opaque handle to a booted in-process wallet. It is returned by New
// and driven by the Android/iOS shells: Start boots the stack, Port reports the
// loopback port the WebView should load, and Stop tears it down. All fields are
// unexported so gomobile treats it as an opaque reference type.
type App struct {
	mu  sync.Mutex
	app *boot.App
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
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.app != nil {
		return errors.New("mobile: already started")
	}
	// Mithril fast-sync keeps the first sync (and the on-disk footprint, paired
	// with the lean profile) practical on a mobile device.
	app, err := boot.Boot(context.Background(), boot.Config{
		Network:        network,
		DataDir:        dataDir,
		Addr:           "127.0.0.1:0", // OS-assigned loopback port for the WebView
		MithrilEnabled: true,
		LeanDefault:    lean,
	})
	if err != nil {
		return err
	}
	a.app = app
	return nil
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
	defer a.mu.Unlock()
	if a.app == nil {
		return nil
	}
	return a.app.OnNetworkChanged()
}

// Stop tears the wallet down cleanly: it drains the control surface and winds
// down the in-process node. It is safe to call more than once; calling it before
// Start is a no-op.
func (a *App) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.app == nil {
		return nil
	}
	err := a.app.Stop()
	a.app = nil
	return err
}
