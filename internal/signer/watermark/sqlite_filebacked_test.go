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

import (
	"path/filepath"
	"testing"
)

func TestSqliteFileBacked(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for path, want := range map[string]bool{
		":memory:":                           false,
		"file::memory:":                      false,
		filepath.Join(dir, "a.db"):           true,
		"file:" + filepath.Join(dir, "b.db"): true,
	} {
		got, err := SqliteFileBacked(path)
		if err != nil {
			t.Fatalf("%q: %v", path, err)
		}
		if got != want {
			t.Fatalf("%q: file-backed = %v, want %v", path, got, want)
		}
	}
	// a memory URI with options does not open at all, so it cannot pass
	if ok, err := SqliteFileBacked("file:x?mode=memory"); err == nil && ok {
		t.Fatal("file:x?mode=memory reported file-backed")
	}
}
