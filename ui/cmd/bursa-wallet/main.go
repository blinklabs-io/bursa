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
//
// Command bursa-wallet is the Bursa full-node wallet: a single binary that
// embeds and supervises Dingo and exposes a local control surface.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/blinklabs-io/bursa/ui/internal/boot"
)

// desktopAddr is the fixed loopback control-surface address the desktop binary
// serves on (a browser or the embedded webview navigates here). Mobile instead
// uses an OS-assigned port (boot.Config.Addr "127.0.0.1:0").
const desktopAddr = "127.0.0.1:8090"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "bursa-wallet:", err)
		os.Exit(1)
	}
}

func run() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	network := envOr("BURSA_NETWORK", "preview")
	dataDir := filepath.Join(home, ".bursa-wallet", network)

	// Log to a file under the data dir in addition to stderr, so the
	// Diagnostics screen can export the logs. A failure to open the file is
	// non-fatal: fall back to stderr-only and leave log export disabled.
	logFilePath, logCloser := openLogFile(dataDir)
	if logCloser != nil {
		defer func() { _ = logCloser.Close() }()
	}
	var logDst io.Writer = os.Stderr
	if logCloser != nil {
		logDst = io.MultiWriter(os.Stderr, logCloser)
	}
	logger := slog.New(slog.NewTextHandler(logDst, nil))

	// Mithril fast-sync is on by default; BURSA_SYNC=genesis opts out.
	mithrilEnabled := !strings.EqualFold(envOr("BURSA_SYNC", "mithril"), "genesis")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Boot the shared wallet stack (supervisor + node + chain + api + embedded
	// SPA) on the fixed desktop loopback port. This is the same wiring the mobile
	// binding (ui/mobile) drives — see internal/boot.
	app, err := boot.Boot(ctx, boot.Config{
		Network:        network,
		DataDir:        dataDir,
		Addr:           desktopAddr,
		Logger:         logger,
		MithrilEnabled: mithrilEnabled,
		// BURSA_LEAN seeds the first-run lean-node default; the persisted setting
		// (default off) is the source of truth thereafter.
		LeanDefault:      envBool("BURSA_LEAN", false),
		ConnectorEnabled: envBool("BURSA_CONNECTOR", false),
		LogFilePath:      logFilePath,
	})
	if err != nil {
		return err
	}
	defer func() { _ = app.Stop() }()

	// Block until it's time to shut down. The default (headless) build waits for a
	// signal and serves the UI over loopback for a browser; the `webview` build
	// opens a native window onto the same loopback UI and waits for it to close.
	uiErr := awaitUI(ctx, app.URL(), logger, app.Err())
	return uiErr
}

// openLogFile creates <dataDir>/logs/bursa-wallet.log (appending) and returns
// its path plus the open file for the logger to also write to. On any failure
// it returns ("", nil): logging then stays stderr-only and log export is
// disabled, rather than blocking startup.
func openLogFile(dataDir string) (string, *os.File) {
	logDir := filepath.Join(dataDir, "logs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "bursa-wallet: could not create log dir:", err)
		return "", nil
	}
	path := filepath.Join(logDir, "bursa-wallet.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bursa-wallet: could not open log file:", err)
		return "", nil
	}
	return path, f
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envBool reads a boolean env var, falling back to def when unset or unparsable.
// Accepts the usual strconv.ParseBool truthy/falsy values (1/0, t/f, true/false).
func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}
