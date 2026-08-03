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

//go:build webview

// This is Variant A from the design: a self-contained desktop app that opens an
// embedded webview window onto the loopback control surface. Build it with
// `-tags webview` (requires CGO + a system webview: webkit2gtk on Linux). The
// default build omits all of this and stays a pure-Go headless service.
package main

import (
	"context"
	"log/slog"
	"runtime"
	"time"

	"github.com/blinklabs-io/bursa/ui/internal/desktopnotify"
	"github.com/blinklabs-io/bursa/ui/internal/desktoptray"
	"github.com/blinklabs-io/bursa/ui/internal/openexternal"
	webview "github.com/webview/webview_go"
)

// The webview GUI event loop must own the main OS thread; pin the main goroutine
// to it before main() runs.
func init() { runtime.LockOSThread() }

// awaitUI (webview build) opens a native window onto the loopback UI and runs the
// GUI loop until the window closes. A shutdown signal or a failed control surface
// terminates the window, which unblocks the loop.
func awaitUI(ctx context.Context, url string, logger *slog.Logger, srvErr <-chan error) error {
	// Don't paint a connection error before the control surface is listening.
	if err := waitReachable(ctx, url, 15*time.Second, srvErr); err != nil {
		return err
	}

	w := webview.New(false)
	w.SetTitle("Bursa")
	w.SetSize(1120, 760, webview.HintNone)

	// The embedded webview has no tab-strip: a plain `target="_blank"` anchor
	// click would navigate this window itself, turning the wallet into a
	// general-purpose browser. The frontend (ExplorerLink.tsx) always
	// preventDefault()s its own anchor navigation and, when this bridge is
	// present, calls it instead so external links open in the OS's real
	// browser. Bind before Navigate so the function exists for the first
	// page load, not just subsequent ones.
	if err := w.Bind("bursaOpenExternal", func(rawurl string) {
		openexternal.Open(logger, rawurl)
	}); err != nil {
		logger.Warn("failed to bind bursaOpenExternal", "error", err)
	}

	// Wallet-activity notifications: the frontend (notifications.ts) calls this
	// bridge, when present, to raise a real OS-native notification for incoming
	// funds / stake rewards; the plain browser build has no bridge and falls back
	// to the browser Notification API. Bound before Navigate for the same reason
	// as bursaOpenExternal.
	if err := w.Bind("bursaNotify", func(title, body string) {
		desktopnotify.Notify(logger, title, body)
	}); err != nil {
		logger.Warn("failed to bind bursaNotify", "error", err)
	}

	uiErr := make(chan error, 1)
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)

		var err error
		select {
		case <-done:
			return
		case <-ctx.Done():
		case err = <-srvErr:
			err = controlSurfaceError(err)
		}
		uiErr <- err
		w.Terminate() // safe from another goroutine; unblocks w.Run()
	}()
	defer func() {
		close(done)
		<-stopped
		w.Destroy()
	}()

	// Minimize/close-to-tray (single-process "Option B"): a system-tray item
	// that shares this one webview run loop rather than a second controller
	// process. Closing or minimizing the window hides it — the embedded node
	// keeps running — and the tray's Open re-shows it. The tray's Quit performs
	// a real shutdown by terminating the run loop, which unblocks w.Run() below
	// so main() can Stop the boot stack (node + control surface).
	//
	// New must run on this (main) goroutine before w.Run(): it installs the
	// native close-interception hook, which touches the window. w.Window() is
	// valid immediately after webview.New (the native window already exists).
	tray := desktoptray.New(desktoptray.Config{
		Window:    w.Window(),
		Dispatch:  w.Dispatch,
		Terminate: w.Terminate,
		StatusURL: url,
		Logger:    logger,
	})
	tray.Launch()
	defer tray.Stop()

	logger.Info("opening webview window", "url", url)
	w.Navigate(url)
	w.Run()

	select {
	case err := <-uiErr:
		return err
	default:
		return nil
	}
}
