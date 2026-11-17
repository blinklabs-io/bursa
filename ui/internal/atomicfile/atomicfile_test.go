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

//go:build unix

package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReplaceCreatesOwnerOnlyState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	path := filepath.Join(dir, "auth.json")
	var syncedDir string
	committed, err := Replace(path, []byte("state"), func(dir string) error {
		syncedDir = dir
		return nil
	})
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if !committed {
		t.Fatal("Replace reported an uncommitted write")
	}
	if syncedDir != dir {
		t.Fatalf("synced directory = %q, want %q", syncedDir, dir)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat directory: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("directory mode = %o, want 700", got)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat state file: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("state file mode = %o, want 600", got)
	}
}
