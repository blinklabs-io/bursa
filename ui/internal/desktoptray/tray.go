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

package desktoptray

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"fyne.io/systray"
)

// menuAction enumerates the tray menu actions the click loop routes through the
// Controller. It lives with the webview-tagged tray glue (its only consumer)
// rather than in the tag-free controller so the pure-Go build has no dead code.
type menuAction int

const (
	actionOpen menuAction = iota // "Open" / "Show" — reveal the window.
	actionQuit                   // "Quit" — real shutdown (terminate the loop).
)

// route maps a tray menu action to its Controller handler. It is the seam the
// systray click loop calls and that the tray unit test drives directly.
func (c *Controller) route(a menuAction) {
	switch a {
	case actionOpen:
		c.Show()
	case actionQuit:
		c.Quit()
	}
}

// Config wires a Tray to a running webview window. Every field except Logger and
// StatusURL is required.
type Config struct {
	// Window is webview.WebView.Window(): a GtkWindow* (Linux), NSWindow*
	// (macOS) or HWND (Windows).
	Window unsafe.Pointer
	// Dispatch is webview.WebView.Dispatch: it runs a closure on the webview UI
	// thread. The tray click loop and the status poller run on their own
	// goroutines, so all native window work is marshalled through this.
	Dispatch func(func())
	// Terminate is webview.WebView.Terminate: the Quit path that ends the run
	// loop so the desktop shell can stop the boot stack (node + control surface).
	Terminate func()
	// StatusURL is the loopback control-surface base URL (e.g. http://127.0.0.1:8090).
	// When set, the tray shows a live node-status line polled from StatusURL+"/status".
	// Empty disables the poller (the line then reads a static label).
	StatusURL string
	// Logger receives tray diagnostics; defaults to slog.Default when nil.
	Logger *slog.Logger
}

// Tray is a system-tray item bound to the desktop window. It coexists with the
// webview run loop in a single process: see Launch for the per-OS threading
// contract.
type Tray struct {
	ctrl      *Controller
	dispatch  func(func())
	statusURL string
	logger    *slog.Logger

	start func() // systray backend start (RunWithExternalLoop)
	stop  func() // systray backend stop

	done     chan struct{}
	stopOnce sync.Once
}

// New builds the tray and its window controller and registers the systray
// callbacks. It installs the native close-interception hook immediately (via the
// Controller) so a close hides the window from the moment the window exists. It
// does not yet bring the tray up — call Launch.
//
// New must be called on the webview's main/UI thread (the goroutine that owns
// the window), before webview.Run, because installing the close hook touches the
// native window (setting the NSWindow delegate / connecting the GTK signal /
// subclassing the HWND proc).
func New(cfg Config) *Tray {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	t := &Tray{
		dispatch:  cfg.Dispatch,
		statusURL: cfg.StatusURL,
		logger:    logger,
		done:      make(chan struct{}),
	}
	win := newWindowController(cfg.Window)
	t.ctrl = NewController(win, cfg.Dispatch, cfg.Terminate)

	// RunWithExternalLoop registers the callbacks and hands back start/stop so
	// the tray can share the webview's loop instead of running its own — the
	// crux of the single-process ("Option B") design.
	t.start, t.stop = systray.RunWithExternalLoop(t.onReady, t.onExit)
	return t
}

// Launch starts the tray backend using the correct threading model for the
// current OS. It is the one place the single-process coexistence is arranged:
//
//   - macOS: the NSStatusItem must be created on the NSApp main thread, and
//     Launch already runs on it — the desktop shell calls it on the main
//     goroutine (runtime.LockOSThread) before webview.Run brings up [NSApp run].
//     systray's start (RunWithExternalLoop's nativeStart) is non-blocking: it
//     registers the status item into the shared NSApp and returns, deferring
//     interactivity to the loop webview.Run starts moments later. So start is
//     called directly here. It must NOT be marshalled through webview.Dispatch:
//     that posts onto the NSApp main queue, which is not being serviced until
//     webview.Run starts the loop, so a Dispatch made here (before Run) is not a
//     reliable way to bring the tray up.
//     NOTE: this coexistence path cannot be exercised off real macOS hardware;
//     it is implemented per the design and needs on-device validation.
//   - Linux: systray talks to the desktop over DBus (StatusNotifierItem /
//     AppIndicator). start connects the session bus and exports the item; the
//     DBus library services incoming calls on its own goroutines, so start runs
//     off the UI thread and never contends with the webview's GTK loop.
//   - Windows: systray runs a hidden-window message pump; start spawns that pump
//     on its own goroutine, independent of the webview's HWND.
func (t *Tray) Launch() {
	if runtime.GOOS == "darwin" {
		// Synchronous, on the AppKit main thread Launch already owns. start is
		// non-blocking (see the doc comment above).
		t.start()
		return
	}
	go t.start()
}

// Stop tears the tray down: it stops the click loop / status poller and closes
// the systray backend. Idempotent.
func (t *Tray) Stop() {
	t.stopOnce.Do(func() {
		close(t.done)
		if t.stop != nil {
			t.stop()
		}
	})
}

// onReady builds the tray menu once the systray backend is up. systray runs it
// on its own goroutine, and the systray.* mutators are goroutine-safe.
func (t *Tray) onReady() {
	if len(iconPNG) > 0 {
		systray.SetIcon(iconPNG)
	}
	systray.SetTitle("")
	systray.SetTooltip("Bursa Wallet")

	mOpen := systray.AddMenuItem("Open Bursa Wallet", "Show the wallet window")
	systray.AddSeparator()
	mStatus := systray.AddMenuItem("Node: starting…", "Embedded node status")
	mStatus.Disable()
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Quit", "Quit Bursa Wallet and stop the node")

	// Click loop: route tray clicks through the Controller, which owns the
	// show-vs-quit policy. Terminates when the tray is stopped.
	go func() {
		for {
			select {
			case <-mOpen.ClickedCh:
				t.ctrl.route(actionOpen)
			case <-mQuit.ClickedCh:
				t.ctrl.route(actionQuit)
			case <-t.done:
				return
			}
		}
	}()

	go t.pollStatus(mStatus)
}

// onExit runs in the systray event loop as it tears down; nothing extra to
// release here (Stop already closed the click loop / poller).
func (t *Tray) onExit() {}

// nodeStatus is the subset of GET /status the tray renders.
type nodeStatus struct {
	State    string `json:"state"`
	CaughtUp bool   `json:"caughtUp"`
}

// pollStatus keeps the disabled status menu item in step with the embedded
// node. It is best-effort: a failed poll leaves the last label in place. It
// exits when the tray is stopped.
func (t *Tray) pollStatus(item *systray.MenuItem) {
	if t.statusURL == "" {
		item.SetTitle("Node: running")
		return
	}
	client := &http.Client{Timeout: 2 * time.Second}
	// Poll immediately, then on a ticker.
	t.refreshStatus(client, item)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			t.refreshStatus(client, item)
		}
	}
}

func (t *Tray) refreshStatus(client *http.Client, item *systray.MenuItem) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.statusURL+"/status", nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		item.SetTitle("Node: unreachable")
		return
	}
	defer func() { _ = resp.Body.Close() }()
	var st nodeStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return
	}
	item.SetTitle("Node: " + statusLabel(st))
}

// statusLabel renders a node status snapshot into a short tray line.
func statusLabel(st nodeStatus) string {
	if st.CaughtUp {
		return "synced"
	}
	if st.State == "" {
		return "starting…"
	}
	return st.State
}

// --- native close-interception callback registry -------------------------
//
// The per-OS cgo files intercept the window's close/minimize and call back into
// Go through an //export'd C function; that function fires the handler stored
// here. Only one window exists, so a single package-level slot suffices.

var (
	closeMu      sync.Mutex
	closeHandler func()
)

func setCloseHandler(fn func()) {
	closeMu.Lock()
	closeHandler = fn
	closeMu.Unlock()
}

func fireCloseHandler() {
	closeMu.Lock()
	fn := closeHandler
	closeMu.Unlock()
	if fn != nil {
		fn()
	}
}
