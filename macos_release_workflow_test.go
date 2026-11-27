// Copyright 2026 Blink Labs Software
// SPDX-License-Identifier: Apache-2.0

package bursa

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type macOSReleaseWorkflow struct {
	Jobs map[string]struct {
		Steps []struct {
			Name, ID, If, Uses, Run string
			With, Env               map[string]string
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func loadMacOSReleaseWorkflow(t *testing.T) macOSReleaseWorkflow {
	t.Helper()
	data, err := os.ReadFile(".github/workflows/publish.yml")
	if err != nil {
		t.Fatal(err)
	}
	var wf macOSReleaseWorkflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatal(err)
	}
	return wf
}

func TestMacOSReleaseUsesGovernedSettings(t *testing.T) {
	wf := loadMacOSReleaseWorkflow(t)
	for job, tc := range map[string]struct{ action, config, artifactType string }{
		"build-binaries":        {"macos-cli", "macos-cli-config", "cli"},
		"build-wallet-binaries": {"macos-package", "macos-wallet-config", "wallet"},
	} {
		t.Run(job, func(t *testing.T) {
			var configured, found bool
			for _, step := range wf.Jobs[job].Steps {
				if step.ID == tc.config {
					configured = true
					if !strings.Contains(step.Run, ".github/governance/macos-"+tc.artifactType+".json") {
						t.Error("settings must come from governance")
					}
				}
				if step.ID == tc.action {
					found = true
					if !configured {
						t.Error("settings must load before the release action")
					}
					if step.Uses != "blinklabs-io/shared-actions/macos-release@a80f7002ed898be8536905f5a59002fce59890c4" || step.With["config"] != "${{ steps."+tc.config+".outputs.config }}" {
						t.Errorf("unexpected shared action: %+v", step)
					}
					for input, value := range map[string]string{
						"application-certificate": "${{ secrets.APPLE_CERTIFICATE }}",
						"application-password":    "${{ secrets.APPLE_CERTIFICATE_PASSWORD }}",
						"keychain-password":       "${{ secrets.APPLE_KEYCHAIN_PASSWORD }}",
						"apple-id":                "${{ secrets.APPLE_ID }}",
						"apple-password":          "${{ secrets.APPLE_APP_SPECIFIC_PASSWORD }}",
						"team-id":                 "${{ secrets.APPLE_TEAM_ID }}",
					} {
						if step.With[input] != value {
							t.Errorf("%s input is not mapped correctly", input)
						}
					}
					if tc.artifactType == "wallet" && (step.With["installer-certificate"] != "${{ secrets.APPLE_INSTALLER_CERTIFICATE }}" || step.With["installer-password"] != "${{ secrets.APPLE_CERTIFICATE_PASSWORD }}") {
						t.Error("wallet installer credentials are not mapped correctly")
					}
					if tc.artifactType == "cli" && step.With["mode"] != "signed" {
						t.Error("CLI release must require signing")
					}
					if step.With["architecture"] != "${{ matrix.arch }}" {
						t.Error("release architecture must follow the matrix")
					}
					if tc.artifactType == "cli" && (step.If != "startsWith(github.ref, 'refs/tags/') && runner.os == 'macOS'" || step.With["version"] != "${{ env.RELEASE_TAG }}") {
						t.Error("CLI signing must use the release tag on macOS")
					}
					if tc.artifactType == "wallet" && (step.If != "matrix.os == 'darwin'" || step.With["mode"] != "${{ (startsWith(github.ref, 'refs/tags/') || inputs.exercise_macos_signing) && 'signed' || 'unsigned' }}") {
						t.Error("wallet signing must follow the release and manual pilot gates")
					}
				}
			}
			if !found {
				t.Fatal("missing shared macOS release step")
			}
		})
	}
}

func TestMacOSCLIUploadsOnlyVerifiedArchive(t *testing.T) {
	var script string
	for _, step := range loadMacOSReleaseWorkflow(t).Jobs["build-binaries"].Steps {
		if step.Name == "Upload release assets" {
			script = step.Run
			if step.Env["MACOS_CLI_PATH"] != "${{ steps.macos-cli.outputs.artifact }}" {
				t.Fatal("archive path must come from shared action")
			}
		}
	}
	if script == "" {
		t.Fatal("missing upload step")
	}
	script = strings.ReplaceAll(script, "${{ secrets.GITHUB_TOKEN }}", "fixture-token")
	script = strings.ReplaceAll(script, "${{ github.repository_owner }}", "example")
	script = strings.ReplaceAll(script, "${{ needs.create-draft-release.outputs.RELEASE_ID }}", "123")
	for _, tc := range []struct {
		name, filename      string
		exists, wantSuccess bool
	}{
		{"verified archive", "bursa-v1.2.3-darwin-arm64.zip", true, true},
		{"missing archive", "bursa-v1.2.3-darwin-arm64.zip", false, false},
		{"wrong name", "other.zip", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0755); err != nil {
				t.Fatal(err)
			}
			curl := filepath.Join(bin, "curl")
			if err := os.WriteFile(curl, []byte("#!/bin/bash\nprintf '%s\\n' \"$*\" > \"$TEST_CURL_LOG\"\n"), 0755); err != nil {
				t.Fatal(err)
			}
			archive := filepath.Join(dir, tc.filename)
			if tc.exists {
				if err := os.WriteFile(archive, []byte("signed"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			envfile := filepath.Join(dir, "env")
			log := filepath.Join(dir, "calls")
			cmd := exec.Command("bash", "-e", "-c", script)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "TARGETS=darwin/arm64", "RELEASE_TAG=v1.2.3", "MACOS_CLI_PATH="+archive, "GITHUB_RUN_ID=1", "GITHUB_RUN_ATTEMPT=1", "GITHUB_ENV="+envfile, "TEST_CURL_LOG="+log)
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.wantSuccess {
				t.Fatalf("result %v: %s", err, out)
			}
			if tc.wantSuccess {
				calls, err := os.ReadFile(log)
				if err != nil || !strings.Contains(string(calls), "@"+archive) {
					t.Fatalf("uploaded wrong path: %s %v", calls, err)
				}
				env, err := os.ReadFile(envfile)
				if err != nil || !strings.Contains(string(env), archive) {
					t.Fatalf("attestation did not use archive: %s %v", env, err)
				}
			} else if _, err := os.Stat(log); !os.IsNotExist(err) {
				t.Fatal("upload happened for invalid archive")
			}
		})
	}
}

func TestMacOSWalletUploadsAndAttestsVerifiedPackage(t *testing.T) {
	var script string
	var attests bool
	for _, step := range loadMacOSReleaseWorkflow(t).Jobs["build-wallet-binaries"].Steps {
		if step.Name == "Upload release asset (macOS pkg)" {
			script = step.Run
			if step.Env["MACOS_PACKAGE_PATH"] != "${{ steps.macos-package.outputs.artifact }}" {
				t.Fatal("package path must come from shared action")
			}
		}
		if step.Name == "Attest pkg (macOS)" {
			attests = true
			if step.With["subject-path"] != "${{ steps.macos-package.outputs.artifact }}" {
				t.Fatal("attestation must cover the verified package")
			}
		}
	}
	if script == "" || !attests {
		t.Fatal("missing package upload or attestation")
	}
	for _, tc := range []struct {
		name, filename      string
		exists, wantSuccess bool
	}{
		{"verified package", "bursa-wallet-1.2.3-darwin-arm64.pkg", true, true},
		{"missing package", "bursa-wallet-1.2.3-darwin-arm64.pkg", false, false},
		{"wrong name", "other.pkg", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bin, "curl"), []byte("#!/bin/bash\nprintf '%s\\n' \"$*\" > \"$TEST_CURL_LOG\"\n"), 0755); err != nil {
				t.Fatal(err)
			}
			pkg := filepath.Join(dir, tc.filename)
			if tc.exists {
				if err := os.WriteFile(pkg, []byte("signed"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			log := filepath.Join(dir, "calls")
			cmd := exec.Command("bash", "-e", "-c", script)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "RELEASE_TAG=v1.2.3", "MATRIX_OS=darwin", "MATRIX_ARCH=arm64", "MACOS_PACKAGE_PATH="+pkg, "GH_TOKEN=fixture", "RELEASE_ID=123", "GITHUB_REPOSITORY=example/bursa", "TEST_CURL_LOG="+log)
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.wantSuccess {
				t.Fatalf("result %v: %s", err, out)
			}
			if tc.wantSuccess {
				calls, err := os.ReadFile(log)
				if err != nil || !strings.Contains(string(calls), "@"+pkg) {
					t.Fatalf("uploaded wrong package: %s %v", calls, err)
				}
			} else if _, err := os.Stat(log); !os.IsNotExist(err) {
				t.Fatal("upload happened for invalid package")
			}
		})
	}
}

func TestMacOSSettingsLoader(t *testing.T) {
	wf := loadMacOSReleaseWorkflow(t)
	for job, id := range map[string]string{"build-binaries": "macos-cli-config", "build-wallet-binaries": "macos-wallet-config"} {
		var script string
		for _, step := range wf.Jobs[job].Steps {
			if step.ID == id {
				script = step.Run
			}
		}
		if script == "" {
			t.Fatalf("%s loader is missing", job)
		}
		filename := "macos-cli.json"
		if job == "build-wallet-binaries" {
			filename = "macos-wallet.json"
		}
		for _, tc := range []struct {
			name, content string
			success       bool
		}{{"valid", `{"artifact_type":"pkg"}`, true}, {"invalid", `{`, false}} {
			t.Run(job+"/"+tc.name, func(t *testing.T) {
				dir := t.TempDir()
				settingsDir := filepath.Join(dir, ".github", "governance")
				if err := os.MkdirAll(settingsDir, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(settingsDir, filename), []byte(tc.content), 0600); err != nil {
					t.Fatal(err)
				}
				output := filepath.Join(dir, "output")
				cmd := exec.Command("bash", "-e", "-c", script)
				cmd.Dir = dir
				cmd.Env = append(os.Environ(), "GITHUB_OUTPUT="+output)
				out, err := cmd.CombinedOutput()
				if (err == nil) != tc.success {
					t.Fatalf("loader result %v: %s", err, out)
				}
				if tc.success {
					got, err := os.ReadFile(output)
					if err != nil || string(got) != "config={\"artifact_type\":\"pkg\"}\n" {
						t.Fatalf("wrong output: %q %v", got, err)
					}
				}
			})
		}
	}
}
