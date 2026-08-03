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
	"unicode/utf8"
)

// maxFieldLen caps a sanitized title/body. A real notification is a short line
// ("Received 12.5 ADA"); anything longer is truncated defensively so a
// malformed value can never balloon into an oversized OS command argument.
const maxFieldLen = 200

// Notify shows an OS-native desktop notification with the given title and body.
// Both are sanitized (see Sanitize) before use so a compromised or buggy
// frontend cannot smuggle quotes, backslashes, or control characters that would
// break out of the notifier's argument/script string. It is fire-and-forget:
// the wallet does not wait on or manage the notifier process's lifetime, and any
// failure is logged and dropped rather than surfaced.
func Notify(logger *slog.Logger, title, body string) {
	title = Sanitize(title)
	body = Sanitize(body)
	// Nothing meaningful to show — refuse rather than pop an empty notification.
	if title == "" && body == "" {
		return
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		// notify-send takes summary and body as distinct argv entries — no shell,
		// so the sanitized text is passed verbatim with no quoting concerns.
		cmd = exec.Command("notify-send", title, body) //nolint:gosec // title/body are sanitized (Sanitize) to a safe printable subset
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
		return
	}

	if err := cmd.Start(); err != nil {
		logger.Warn("failed to raise desktop notification", "error", err)
		return
	}
	go func() {
		if err := cmd.Wait(); err != nil {
			logger.Warn("desktop notifier process exited with error", "error", err)
		}
	}()
}

// Sanitize reduces s to a safe, single-line printable subset for use as a
// notification field: it drops control characters (including newlines) and the
// shell/script-meaningful quoting characters (" ' ` \), collapses surrounding
// whitespace, and caps the length. The notification copy is plain ASCII-ish
// prose ("Received 12.5 ADA"), so this never loses meaningful content.
func Sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '"' || r == '\'' || r == '`' || r == '\\':
			// drop quoting/escape characters
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f:
			// drop other control characters
		default:
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	// Truncate by rune count, not byte offset — a byte-offset cut can bisect a
	// multi-byte UTF-8 rune and leave an invalid string that renders as garbage
	// (or breaks the macOS/PowerShell notifier scripts, which expect valid text).
	if utf8.RuneCountInString(out) > maxFieldLen {
		runes := []rune(out)
		out = strings.TrimSpace(string(runes[:maxFieldLen]))
	}
	return out
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
