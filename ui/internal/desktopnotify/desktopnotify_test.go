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
	"strings"
	"testing"
	"unicode/utf8"
)

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

func TestWindowsToastScriptEmbedsSanitizedText(t *testing.T) {
	script := windowsToastScript("Title", "Body")
	if !strings.Contains(script, "'Title'") || !strings.Contains(script, "'Body'") {
		t.Fatalf("windows script missing embedded fields: %q", script)
	}
}
