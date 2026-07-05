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
	"net/url"
	"os/exec"
	"runtime"
	"time"

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
		openExternal(logger, rawurl)
	}); err != nil {
		logger.Warn("failed to bind bursaOpenExternal", "error", err)
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

// openExternal opens rawurl in the OS's default browser, never in the
// embedded webview. It is the Go side of the `bursaOpenExternal` JS bridge
// bound above: the frontend calls this instead of letting an anchor's own
// `target="_blank"` navigate the wallet window.
//
// rawurl is validated before use — it must parse as an absolute http(s) URL —
// so a compromised or buggy frontend can't smuggle a `file://` path or an
// arbitrary shell-meaningful string into an external command. Anything else
// is logged and dropped rather than opened.
func openExternal(logger *slog.Logger, rawurl string) {
	u, err := url.Parse(rawurl)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		logger.Warn("refusing to open external URL", "url", rawurl)
		return
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", u.String())
	case "darwin":
		cmd = exec.Command("open", u.String())
	case "windows":
		// rundll32's url.dll opener takes the URL as its sole argument; it
		// does not go through a shell, so no extra quoting is needed.
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u.String())
	default:
		logger.Warn("no external-browser opener for this OS", "os", runtime.GOOS, "url", u.String())
		return
	}

	// Fire-and-forget: the wallet doesn't wait on or manage the browser
	// process's lifetime, it only launches it.
	if err := cmd.Start(); err != nil {
		logger.Warn("failed to open external URL", "url", u.String(), "error", err)
		return
	}
	go func() { _ = cmd.Wait() }()
}
