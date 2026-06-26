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
	"fmt"
	"log/slog"
	"net/http"
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
	waitReachable(ctx, url, 15*time.Second)

	w := webview.New(false)
	defer w.Destroy()
	w.SetTitle("Bursa")
	w.SetSize(1120, 760, webview.HintNone)

	var uiErr error
	go func() {
		select {
		case <-ctx.Done():
		case err := <-srvErr:
			uiErr = fmt.Errorf("control surface: %w", err)
		}
		w.Terminate() // safe from another goroutine; unblocks w.Run()
	}()

	logger.Info("opening webview window", "url", url)
	w.Navigate(url)
	w.Run()
	return uiErr
}

// waitReachable polls url until it answers or the timeout elapses.
func waitReachable(ctx context.Context, url string, timeout time.Duration) {
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return
		}
		resp, err := client.Get(url) //nolint:noctx // loopback readiness probe
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}
