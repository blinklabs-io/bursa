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

// Package openexternal opens a URL in the host OS's default handler on behalf
// of the desktop (webview) build. It lives in its own pure-Go package — no
// webview/CGO dependency — so its URL validation is unit-testable without a
// GUI. Only the webview build calls Open (via the bursaOpenExternal JS
// bridge); the headless build serves the UI in a real browser and never needs
// it.
package openexternal

import (
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Open opens rawurl in the OS's default handler, never in the embedded webview.
// It is the Go side of the `bursaOpenExternal` JS bridge: the frontend calls it
// for explorer links (http/https, opened in the default browser) and for the
// Diagnostics screen's "Open log folder" action (a `file://` URL of the log
// directory, opened in the OS file manager).
//
// The target is validated by ResolveTarget before use so a compromised or buggy
// frontend can't smuggle an arbitrary shell-meaningful string into an external
// command. Anything that does not validate is logged and dropped.
func Open(logger *slog.Logger, rawurl string) {
	target, isFile, ok := ResolveTarget(rawurl)
	if !ok {
		logger.Warn("refusing to open external URL", "url", rawurl)
		return
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		// xdg-open opens a URL in the default browser and a directory path in
		// the default file manager.
		cmd = exec.Command("xdg-open", target) //nolint:gosec // target is a validated http(s) URL or an existing directory
	case "darwin":
		cmd = exec.Command("open", target) //nolint:gosec // target is a validated http(s) URL or an existing directory
	case "windows":
		if isFile {
			// target is a validated, absolute, existing directory, so explorer
			// opens a folder view — never executes a file.
			cmd = exec.Command("explorer", target) //nolint:gosec // target is a validated existing directory
		} else {
			// rundll32's url.dll opener takes the URL as its sole argument; it
			// does not go through a shell, so no extra quoting is needed.
			cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", target) //nolint:gosec // target is a validated http(s) URL
		}
	default:
		logger.Warn("no external opener for this OS", "os", runtime.GOOS, "url", target)
		return
	}

	// Fire-and-forget: the wallet doesn't wait on or manage the opened
	// process's lifetime, it only launches it.
	if err := cmd.Start(); err != nil {
		logger.Warn("failed to open external URL", "url", target, "error", err)
		return
	}
	go func() { _ = cmd.Wait() }()
}

// ResolveTarget validates rawurl and returns the concrete argument to hand to
// the OS opener, whether that argument is a local file path (isFile), and
// whether the URL is allowed at all (ok). The accepted forms are:
//
//   - http/https with a hostname → opened in the default browser.
//   - file:// whose path is an existing directory → opened as a folder view.
//     It can never open — let alone execute — a file.
//
// Everything else returns ok=false.
func ResolveTarget(rawurl string) (target string, isFile bool, ok bool) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return "", false, false
	}
	switch {
	case (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "":
		return u.String(), false, true
	case u.Scheme == "file":
		p, ok := fileURLDir(u)
		if !ok {
			return "", false, false
		}
		return p, true, true
	default:
		return "", false, false
	}
}

// fileURLDir extracts, normalizes, and validates the local directory path from
// a file:// URL. It returns ok=false unless the URL resolves to an existing,
// absolute directory.
//
// url.Parse already percent-decodes u.Path, so spaces and other escaped
// characters are restored to the real filesystem name — there is no second
// unescape (that would double-decode). On Windows a drive path arrives as
// "/C:/Users/…"; the leading slash is stripped so os/filepath see a real
// "C:\Users\…" path.
func fileURLDir(u *url.URL) (string, bool) {
	// A file URL's authority is empty (file:///path) or "localhost"; anything
	// else names a remote host we won't dereference.
	if u.Host != "" && !strings.EqualFold(u.Host, "localhost") {
		return "", false
	}

	p := u.Path
	if runtime.GOOS == "windows" && len(p) >= 3 && p[0] == '/' && p[2] == ':' {
		p = p[1:]
	}
	p = filepath.Clean(p)

	// Belt-and-suspenders: only ever open an absolute path that is a real,
	// existing directory.
	if !filepath.IsAbs(p) {
		return "", false
	}
	info, err := os.Stat(p)
	if err != nil || !info.IsDir() {
		return "", false
	}
	return p, true
}
