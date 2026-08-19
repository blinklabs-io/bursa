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

// Package desktopnotify raises an OS-native desktop notification on behalf of
// the desktop (webview) build. It lives in its own pure-Go package — no
// webview/CGO dependency — so its input sanitization is unit-testable without a
// GUI. Only the webview build calls Notify (via the bursaNotify JS bridge); the
// headless build serves the UI in a real browser and uses the browser
// Notification API instead.
package desktopnotify

import (
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// notifyStartGrace bounds how long start waits to observe an immediate
// notifier exit before assuming success. cmd.Start() only confirms the OS
// could launch the process — a notifier binary that launches fine but
// immediately errors out (e.g. no display/session, D-Bus unavailable) would
// otherwise still be reported as delivered. Waiting this long for an early
// exit catches that case while still returning well before a notifier that
// stays running (to display a toast, or on Windows to hold the balloon tip
// open) has a chance to finish — start must never block on the full process
// lifetime.
const notifyStartGrace = 200 * time.Millisecond

// maxFieldLen caps a sanitized title/body. A real notification is a short line
// ("Received 12.5 ADA"); anything longer is truncated defensively so a
// malformed value can never balloon into an oversized OS command argument.
const maxFieldLen = 200

// maxRawScanLen bounds how many runes of the raw input Sanitize will examine,
// independent of maxFieldLen. Dropped characters (quotes/backslashes/control
// chars) never advance the maxFieldLen counter, so an input consisting
// entirely of such characters would otherwise be scanned in full no matter
// how long it is. This is set generously above maxFieldLen so it never
// affects legitimate input (including a run of leading whitespace ahead of
// real text) while still bounding the worst case scan cost.
const maxRawScanLen = 20 * maxFieldLen

// Notify shows an OS-native desktop notification with the given title and body.
// Both are sanitized (see Sanitize) before use so a compromised or buggy
// frontend cannot smuggle quotes, backslashes, or control characters that would
// break out of the notifier's argument/script string. It reports whether the
// notifier process was successfully started — the wallet does not wait on or
// manage its lifetime beyond that, but a failure to even start it must be
// reported to the caller (the bursaNotify bridge) rather than silently
// dropped, since the frontend uses this to decide whether the event may be
// marked as delivered.
func Notify(logger *slog.Logger, title, body string) bool {
	title = Sanitize(title)
	body = Sanitize(body)
	// Nothing meaningful to show — refuse rather than pop an empty notification.
	if title == "" && body == "" {
		return false
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		// notify-send takes summary and body as distinct argv entries — no shell,
		// so the sanitized text is passed verbatim with no quoting concerns. The
		// leading "--" stops option parsing so a title/body starting with "-"
		// (Sanitize does not forbid a leading dash) is never read as a flag.
		cmd = exec.Command("notify-send", "--", title, body) //nolint:gosec // title/body are sanitized (Sanitize) to a safe printable subset
	case "darwin":
		// osascript embeds the text inside an AppleScript string literal. Sanitize
		// has removed every double-quote and backslash, so wrapping in plain
		// double-quotes cannot terminate the literal early.
		script := fmt.Sprintf("display notification %q with title %q", body, title)
		cmd = exec.Command("osascript", "-e", script) //nolint:gosec // title/body are sanitized (Sanitize); no quotes/backslashes remain
	case "windows":
		// A standard balloon tip via System.Windows.Forms.NotifyIcon. The text is
		// embedded in single-quoted PowerShell strings; Sanitize has removed every
		// single-quote, so the literals cannot be broken out of.
		script := windowsToastScript(title, body)
		cmd = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script) //nolint:gosec // title/body are sanitized (Sanitize); no single-quotes remain
	default:
		logger.Warn("no desktop notifier for this OS", "os", runtime.GOOS)
		return false
	}

	return start(logger, cmd)
}

// start launches cmd and reports whether it was successfully started AND
// did not fail within notifyStartGrace. Split out from Notify so the
// start/failure outcome is unit-testable with an injected command,
// independent of the OS-specific notifier selection above.
func start(logger *slog.Logger, cmd *exec.Cmd) bool {
	if err := cmd.Start(); err != nil {
		logger.Warn("failed to raise desktop notification", "error", err)
		return false
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			logger.Warn("desktop notifier process exited with error", "error", err)
			return false
		}
		return true
	case <-time.After(notifyStartGrace):
		// Still running past the grace window: treat it as delivered rather
		// than block the caller on the notifier's full lifetime. Any failure
		// observed after this point is logged but can no longer change the
		// already-reported result.
		go func() {
			if err := <-done; err != nil {
				logger.Warn("desktop notifier process exited with error", "error", err)
			}
		}()
		return true
	}
}

// Sanitize reduces s to a safe, single-line printable subset for use as a
// notification field: it drops control characters (including newlines) and the
// shell/script-meaningful quoting characters (" ' ` \), collapses surrounding
// whitespace, and caps the length. The notification copy is plain ASCII-ish
// prose ("Received 12.5 ADA"), so this never loses meaningful content.
//
// The cap is enforced while writing, not by building the full sanitized string
// and truncating afterward: an oversized (e.g. attacker-controlled bursaNotify)
// input would otherwise still be fully processed and copied before the excess
// is discarded, so maxFieldLen would bound the output but not the work done to
// produce it. Stopping the write (and the scan) as soon as the cap is reached
// keeps the defensive limit effective. Runes are only ever written whole, so
// this can never bisect a multi-byte UTF-8 rune the way a byte-offset cut
// could.
//
// Leading whitespace is skipped (not counted against maxFieldLen) rather than
// written and trimmed off afterward: a run of leading whitespace long enough
// to exhaust maxFieldLen would otherwise consume the entire budget before any
// meaningful text is reached, discarding it. Dropped characters (quotes/
// backslashes/control chars) don't advance the maxFieldLen counter either, so
// a second, independent counter (maxRawScanLen) bounds the number of raw
// input runes examined regardless of how many are skipped or dropped —
// keeping the scan itself bounded even for a hostile input built entirely
// from such characters.
func Sanitize(s string) string {
	var b strings.Builder
	n := 0       // runes written to b, bounded by maxFieldLen
	scanned := 0 // raw input runes examined, bounded by maxRawScanLen
	leading := true
	for _, r := range s {
		if n >= maxFieldLen || scanned >= maxRawScanLen {
			break
		}
		scanned++
		switch {
		case r == '"' || r == '\'' || r == '`' || r == '\\':
			// drop quoting/escape characters
			continue
		case r == '\n' || r == '\r' || r == '\t':
			r = ' '
		case r < 0x20 || r == 0x7f:
			// drop other control characters
			continue
		}
		if leading && r == ' ' {
			// skip leading whitespace without spending the maxFieldLen budget
			continue
		}
		leading = false
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// windowsToastScript builds the PowerShell balloon-tip command. title and body
// must already be sanitized (no single-quotes) so they embed safely in the
// single-quoted string literals.
func windowsToastScript(title, body string) string {
	return "Add-Type -AssemblyName System.Windows.Forms;" +
		"$n=New-Object System.Windows.Forms.NotifyIcon;" +
		"$n.Icon=[System.Drawing.SystemIcons]::Information;" +
		"$n.BalloonTipTitle='" + title + "';" +
		"$n.BalloonTipText='" + body + "';" +
		"$n.Visible=$true;$n.ShowBalloonTip(5000);Start-Sleep -Seconds 6;$n.Dispose()"
}
