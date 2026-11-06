// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package watermark

import "testing"

func TestSqliteFilePath(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"/data/wm.db":               "/data/wm.db",
		"wm.db":                     "wm.db",
		"file:/data/wm.db":          "/data/wm.db",
		"file:///data/wm.db":        "/data/wm.db",
		"file:wm.db":                "wm.db",
		"file:/data/wm.db?mode=rwc": "/data/wm.db",
	} {
		if got := SqliteFilePath(in); got != want {
			t.Fatalf("SqliteFilePath(%q) = %q, want %q", in, got, want)
		}
	}
}
