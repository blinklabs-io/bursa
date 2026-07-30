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
package openexternal

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

// fileURL builds a correctly percent-encoded file:// URL for a local path,
// exactly as the frontend (pathToFileUrl) does before calling the
// bursaOpenExternal bridge.
func fileURL(p string) string {
	return (&url.URL{Scheme: "file", Path: p}).String()
}

func TestResolveTargetFileScheme(t *testing.T) {
	dir := t.TempDir()

	spacedDir := filepath.Join(dir, "logs with spaces")
	if err := os.Mkdir(spacedDir, 0o755); err != nil {
		t.Fatal(err)
	}

	filePath := filepath.Join(dir, "bursa-wallet.log")
	if err := os.WriteFile(filePath, []byte("log\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		rawurl     string
		wantOK     bool
		wantIsFile bool
		wantTarget string // only checked when wantOK
	}{
		{
			name:       "existing directory accepted",
			rawurl:     fileURL(dir),
			wantOK:     true,
			wantIsFile: true,
			wantTarget: dir,
		},
		{
			name:       "directory path with spaces is decoded and accepted",
			rawurl:     fileURL(spacedDir),
			wantOK:     true,
			wantIsFile: true,
			wantTarget: spacedDir,
		},
		{
			name:   "existing file (not a directory) refused",
			rawurl: fileURL(filePath),
			wantOK: false,
		},
		{
			name:   "nonexistent path refused",
			rawurl: fileURL(filepath.Join(dir, "does-not-exist")),
			wantOK: false,
		},
		{
			name:   "remote host refused",
			rawurl: "file://evil.example/etc",
			wantOK: false,
		},
		{
			name:       "http url accepted as a browser link",
			rawurl:     "https://cardanoscan.io/",
			wantOK:     true,
			wantIsFile: false,
			wantTarget: "https://cardanoscan.io/",
		},
		{
			name:   "unsupported scheme refused",
			rawurl: "javascript:alert(1)",
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target, isFile, ok := ResolveTarget(tc.rawurl)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (target=%q)", ok, tc.wantOK, target)
			}
			if !tc.wantOK {
				return
			}
			if isFile != tc.wantIsFile {
				t.Errorf("isFile = %v, want %v", isFile, tc.wantIsFile)
			}
			if target != tc.wantTarget {
				t.Errorf("target = %q, want %q", target, tc.wantTarget)
			}
		})
	}
}
