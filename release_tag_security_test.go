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

func TestSigningJobsUseProtectedEnvironment(t *testing.T) {
	// The matching GitHub deployment_branch_policy has protected_branches false,
	// custom_branch_policies true, and can_admins_bypass disabled.
	workflowPaths, err := filepath.Glob(filepath.Join(".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}

	markers := []string{
		"secrets.APPLE_",
		"secrets.CERTIFICATE_",
		"secrets.ANDROID_KEY",
		"uses: actions/attest@",
	}
	const environment = "release-signing"
	signingJobs := 0
	for _, workflowPath := range workflowPaths {
		data, err := os.ReadFile(workflowPath)
		if err != nil {
			t.Fatal(err)
		}
		var workflow struct {
			Jobs map[string]map[string]any `yaml:"jobs"`
		}
		if err := yaml.Unmarshal(data, &workflow); err != nil {
			t.Fatalf("parse %s: %v", workflowPath, err)
		}
		for jobName, job := range workflow.Jobs {
			jobData, err := yaml.Marshal(job)
			if err != nil {
				t.Fatalf("render %s job %s: %v", workflowPath, jobName, err)
			}
			jobText := string(jobData)
			isSigningJob := false
			for _, marker := range markers {
				if strings.Contains(jobText, marker) {
					isSigningJob = true
					break
				}
			}
			if !isSigningJob {
				continue
			}

			signingJobs++
			if got, ok := job["environment"].(string); !ok || got != environment {
				t.Errorf("%s job %s uses signing material without environment %q", workflowPath, jobName, environment)
			}
		}
	}
	if signingJobs == 0 {
		t.Fatal("no signing-capable workflow jobs found")
	}
}

func TestReleaseTagRejectedBeforeReleaseCreation(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is required for release workflow checks")
	}

	data, err := os.ReadFile(filepath.Join(".github", "workflows", "publish.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				ID  string `yaml:"id"`
				If  string `yaml:"if"`
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	job, ok := workflow.Jobs["create-draft-release"]
	if !ok {
		t.Fatal("create-draft-release job is missing")
	}

	for _, tc := range []struct {
		tag     string
		allowed bool
	}{
		{tag: "v0.21.0", allowed: true},
		{tag: "v0.22.0-rc.2", allowed: true},
		{tag: "v1.2.3+build.4"},
		{tag: "v1.2.3$(id)"},
		{tag: "v1.2.3;id"},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			foundRelease := false
			var rejected bool
			for _, step := range job.Steps {
				if step.ID == "create-release" {
					foundRelease = true
					break
				}
				if step.Run == "" || strings.Contains(step.If, "workflow_dispatch") {
					continue
				}
				cmd := exec.Command("bash", "-e", "-o", "pipefail", "-c", step.Run)
				cmd.Env = append(os.Environ(),
					"GITHUB_REF=refs/tags/"+tc.tag,
					"GITHUB_ENV="+filepath.Join(t.TempDir(), "github-env"),
				)
				output, err := cmd.CombinedOutput()
				if err != nil {
					if !strings.Contains(string(output), "Invalid release tag") {
						t.Fatalf("release setup failed for another reason: %v\n%s", err, output)
					}
					rejected = true
					break
				}
			}
			if !foundRelease && !rejected {
				t.Fatal("release creation step is missing")
			}
			if rejected == tc.allowed {
				t.Fatalf("release setup accepted=%t for tag %q", !rejected, tc.tag)
			}
		})
	}
}

func TestMakeVersionStaysData(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make is required for release build checks")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is required for release build checks")
	}

	makefile, err := os.ReadFile("Makefile")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for path, content := range map[string]string{
		"Makefile":          string(makefile),
		"go.mod":            "module example.com/bursa\n",
		"ui/go.mod":         "module example.com/bursa/ui\n",
		"cmd/bursa/main.go": "package main\n",
	} {
		fullPath := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	shim := filepath.Join(root, "shim")
	if err := os.Mkdir(shim, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"git": "#!/bin/sh\ncase \"$1\" in\n  describe) printf '%s\\n' \"$FAKE_TAG\" ;;\n  rev-parse) if [ \"$2\" = --is-inside-work-tree ]; then exit 1; fi; printf 'abcdef0\\n' ;;\nesac\n",
		"go":  "#!/bin/sh\nif [ \"$1\" = build ]; then printf '%s\\n' \"$@\" > \"$TRACE\"; fi\n",
	} {
		if err := os.WriteFile(filepath.Join(shim, name), []byte(content), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range []struct {
		tag string
	}{
		{tag: "v0.21.0"},
		{tag: "v1.2.3$(id)"},
	} {
		for _, target := range []string{"bursa", "wallet-binary"} {
			t.Run(tc.tag+"/"+target, func(t *testing.T) {
				trace := filepath.Join(t.TempDir(), "go-args")
				cmd := exec.Command("make", "-C", root, target)
				cmd.Env = append(os.Environ(),
					"PATH="+shim+string(os.PathListSeparator)+os.Getenv("PATH"),
					"FAKE_TAG="+tc.tag,
					"TRACE="+trace,
					"GOOS=linux",
				)
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("make %s failed: %v\n%s", target, err, output)
				}
				args, err := os.ReadFile(trace)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(args), "Version="+tc.tag) {
					t.Fatalf("tag was reinterpreted in %s linker arguments: %q", target, args)
				}
			})
		}
	}
}
