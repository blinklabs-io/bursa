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

package desktopnotify

import (
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"testing"
	"unicode/utf8"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestSanitizeStripsQuotingAndControlChars(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "Received 12.5 ADA", "Received 12.5 ADA"},
		{"double quotes", `Received "12.5" ADA`, "Received 12.5 ADA"},
		{"single quotes", "it's 5 ADA", "its 5 ADA"},
		{"backtick and backslash", "a`b\\c", "abc"},
		{"newlines to space then trimmed", "line1\nline2", "line1 line2"},
		{"leading/trailing space", "  hi  ", "hi"},
		{"tab collapses", "a\tb", "a b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Sanitize(tc.in); got != tc.want {
				t.Fatalf("Sanitize(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSanitizeCapsLength(t *testing.T) {
	in := strings.Repeat("a", maxFieldLen+50)
	got := Sanitize(in)
	if len(got) > maxFieldLen {
		t.Fatalf("Sanitize length = %d, want <= %d", len(got), maxFieldLen)
	}
}

func TestSanitizeLeadingWhitespaceDoesNotConsumeCap(t *testing.T) {
	// A run of leading whitespace long enough to exhaust maxFieldLen on its
	// own must not crowd out the meaningful text that follows it.
	in := strings.Repeat(" ", maxFieldLen) + "hello"
	if got := Sanitize(in); got != "hello" {
		t.Fatalf("Sanitize(huge leading whitespace + text) = %q, want %q", got, "hello")
	}
}

func TestSanitizeBoundsScanOfDroppedChars(t *testing.T) {
	// An input consisting entirely of dropped characters (quotes here) must
	// not be scanned past maxRawScanLen. Trailing legitimate text placed
	// beyond that bound acts as a witness: if the scan were unbounded it
	// would appear in the output, but since it's well beyond maxRawScanLen
	// it must not.
	huge := strings.Repeat(`"`, maxRawScanLen*10) + "trailing"
	if got := Sanitize(huge); got != "" {
		t.Fatalf("Sanitize(huge all-dropped-char input) = %q, want empty (scan must be bounded, not reach trailing text)", got)
	}
}

func TestSanitizeCapsLengthByRuneNotByte(t *testing.T) {
	// Position a 3-byte rune (a CJK character) straddling the maxFieldLen
	// boundary. A byte-offset truncation (out[:maxFieldLen]) would bisect it and
	// produce invalid UTF-8; a rune-count truncation must not.
	in := strings.Repeat("a", maxFieldLen-1) + "中中中"
	got := Sanitize(in)
	if !utf8.ValidString(got) {
		t.Fatalf("Sanitize(%q) = %q, not valid UTF-8", in, got)
	}
	if n := utf8.RuneCountInString(got); n > maxFieldLen {
		t.Fatalf("Sanitize rune count = %d, want <= %d", n, maxFieldLen)
	}
}

func TestSanitizeRemovesAllInjectionChars(t *testing.T) {
	got := Sanitize(`'; rm -rf / #"` + "`$(x)\\")
	for _, bad := range []string{`"`, `'`, "`", `\`} {
		if strings.Contains(got, bad) {
			t.Fatalf("Sanitize left %q in %q", bad, got)
		}
	}
}

func TestStartReportsFailureThenSuccessOnRetry(t *testing.T) {
	// A failed cmd.Start() (e.g. notifier binary missing) must be reported to
	// the caller rather than logged and silently dropped — the frontend uses
	// this to decide whether the activity event may be marked as delivered
	// (and therefore not retried). A subsequent successful start (retry) must
	// report true.
	//
	// The "succeeding" command uses `go version` rather than a Unix-only
	// binary (e.g. `true`) so this test also passes on Windows, which this
	// package has a notifier path for.
	logger := discardLogger()

	failing := exec.Command("bursa-desktopnotify-test-binary-does-not-exist")
	if got := start(logger, failing); got {
		t.Fatalf("start() with a nonexistent binary = %v, want false", got)
	}

	succeeding := exec.Command("go", "version")
	if got := start(logger, succeeding); !got {
		t.Fatalf("start() with a valid binary = %v, want true (retry after failure must succeed)", got)
	}
}

func TestStartReportsFalseOnImmediateExitFailure(t *testing.T) {
	// cmd.Start() only confirms the OS could launch the process. A notifier
	// that starts fine but exits with an error before notifyStartGrace
	// elapses (e.g. no display/session available) must not be reported as a
	// successful delivery.
	logger := discardLogger()

	// An unknown `go` subcommand starts the go binary successfully but exits
	// quickly with a non-zero status — portable across the OSes this
	// package supports, unlike a shell-only failing command.
	failingFast := exec.Command("go", "bursa-desktopnotify-unknown-subcommand")
	if got := start(logger, failingFast); got {
		t.Fatalf("start() with a command that exits with an error = %v, want false", got)
	}
}

func TestNotifyReturnsFalseForEmptyInput(t *testing.T) {
	logger := discardLogger()
	if got := Notify(logger, "", ""); got {
		t.Fatalf("Notify(empty, empty) = %v, want false (nothing to show)", got)
	}
}

func TestWindowsToastScriptEmbedsSanitizedText(t *testing.T) {
	script := windowsToastScript("Title", "Body")
	if !strings.Contains(script, "'Title'") || !strings.Contains(script, "'Body'") {
		t.Fatalf("windows script missing embedded fields: %q", script)
	}
}
