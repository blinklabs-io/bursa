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

package version

import (
	"strings"
	"testing"
)

func TestGetVersionStringDevel(t *testing.T) {
	origVersion, origCommit := Version, CommitHash
	t.Cleanup(func() {
		Version, CommitHash = origVersion, origCommit
	})

	Version = ""
	CommitHash = "abc123"
	got := GetVersionString()
	if !strings.HasPrefix(got, "devel") {
		t.Errorf("expected devel prefix when Version empty, got %q", got)
	}
	if !strings.Contains(got, "abc123") {
		t.Errorf("expected commit hash in output, got %q", got)
	}
}

func TestGetVersionStringTagged(t *testing.T) {
	origVersion, origCommit := Version, CommitHash
	t.Cleanup(func() {
		Version, CommitHash = origVersion, origCommit
	})

	Version = "v1.2.3"
	CommitHash = "deadbeef"
	got := GetVersionString()
	if !strings.Contains(got, "v1.2.3") {
		t.Errorf("expected version in output, got %q", got)
	}
	if !strings.Contains(got, "deadbeef") {
		t.Errorf("expected commit hash in output, got %q", got)
	}
	if strings.HasPrefix(got, "devel") {
		t.Errorf("did not expect devel prefix for tagged build, got %q", got)
	}
}
