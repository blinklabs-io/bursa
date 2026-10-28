//go:build !windows

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

package signer_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestPrepareQuickstartOwnerOnly(t *testing.T) {
	tmpDir := t.TempDir()
	cmd := exec.Command("sh", "-c", `umask 000; exec sh "$1"`, "sh", "./prepare-quickstart.sh")
	cmd.Env = append(os.Environ(), "TMPDIR="+tmpDir)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("prepare quickstart: %v", err)
	}

	devDir := strings.TrimSpace(string(output))
	if filepath.Dir(devDir) != tmpDir {
		t.Fatalf("development directory %q is outside the selected temporary directory", devDir)
	}

	assertMode(t, devDir, 0o700)
	assertMode(t, filepath.Join(devDir, "keys"), 0o700)
	assertMode(t, filepath.Join(devDir, "signer.yaml"), 0o600)
	authFile := filepath.Join(devDir, "auth.env")
	assertMode(t, authFile, 0o600)

	auth, err := os.ReadFile(authFile)
	if err != nil {
		t.Fatalf("read auth environment: %v", err)
	}
	if !regexp.MustCompile(`^SIGNER_JWT_SECRET=[0-9a-f]{64}\n$`).Match(auth) {
		t.Fatal("authentication environment does not contain one generated 32-byte hex secret")
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", filepath.Base(path), err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %04o, want %04o owner-only permissions", filepath.Base(path), got, want)
	}
}
