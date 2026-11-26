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

package bursa

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMacOSSigningSecretPrompt(t *testing.T) {
	expect, err := exec.LookPath("expect")
	if err != nil {
		t.Skip("expect is required")
	}
	data, err := os.ReadFile(".github/workflows/publish.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Env map[string]string `yaml:"env"`
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	script := workflow.Env["MACOS_SECRET_EXPECT"]
	if script == "" {
		t.Fatal("missing signing prompt handler")
	}
	dir := t.TempDir()
	security := filepath.Join(dir, "security")
	stub := `#!/bin/sh
[ "${TEST_NO_PROMPT:-}" != 1 ] || exit 0
printf 'Password:'
IFS= read -r secret
[ "$secret" = 'fixture-secret' ] || exit 4
[ "${TEST_FAIL:-}" != 1 ] || exit 7
`
	if err := os.WriteFile(security, []byte(stub), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "xcrun"), []byte(stub), 0755); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"create", "unlock", "partition-cli", "partition-wallet", "notary"} {
		t.Run(action, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), expect, "-c", script)
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "SECRET_INPUT=fixture-secret", "SECRET_ACTION="+action, "SECRET_KEYCHAIN=fixture.keychain", "SECRET_PROFILE=fixture", "NOTARY_APPLE_ID=fixture@example.test", "NOTARY_TEAM_ID=fixture")
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("secret handler failed: %v\n%s", err, output)
			}
			if strings.Contains(string(output), "fixture-secret") {
				t.Fatal("secret appeared in output")
			}
			if len(strings.TrimSpace(string(output))) != 0 {
				t.Fatalf("successful prompt emitted unexpected output: %s", output)
			}
		})
	}
	t.Run("missing prompt", func(t *testing.T) {
		cmd := exec.CommandContext(t.Context(), expect, "-c", script)
		cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "SECRET_INPUT=fixture-secret", "SECRET_ACTION=create", "SECRET_KEYCHAIN=fixture.keychain", "TEST_NO_PROMPT=1")
		output, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(output), "did not request its secret") {
			t.Fatalf("missing prompt not detected: %v\n%s", err, output)
		}
	})
	t.Run("command failure", func(t *testing.T) {
		cmd := exec.CommandContext(t.Context(), expect, "-c", script)
		cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "SECRET_INPUT=fixture-secret", "SECRET_ACTION=create", "SECRET_KEYCHAIN=fixture.keychain", "TEST_FAIL=1")
		output, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(output), "failed with exit status 7") {
			t.Fatalf("command failure not propagated: %v\n%s", err, output)
		}
	})

}
