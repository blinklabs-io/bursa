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

package signer

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/internal/config"
)

func TestCheckBackendWatermark_NitroRequiresEnforcingDurable(t *testing.T) {
	t.Parallel()
	nitro := []config.SignerBackendConfig{{Name: "n", Type: "nitro"}}
	for _, wm := range []config.SignerWatermarkConfig{
		{Type: "file", Path: "/x", Mode: "warn"},
		{Type: "file", Path: "/x", Mode: "off"},
		{Type: "postgres", Mode: "warn"},
		// durable type without the settings to open it
		{Type: "file", Mode: "enforce"},
		{Type: "postgres", Mode: "enforce"},
		{Type: "postgres", DSNEnv: "BURSA_TEST_UNSET_WATERMARK_DSN"},
		// SQLite opens these in memory, which a restart loses
		{Type: "file", Path: ":memory:", Mode: "enforce"},
		{Type: "file", Path: "file::memory:", Mode: "enforce"},
		{Type: "mem", Mode: "enforce"},
		{Type: "", Mode: "warn"},
		{Mode: "off"},
		{},
	} {
		err := CheckBackendWatermark(nitro, wm)
		if err == nil {
			t.Fatalf("watermark %+v: nitro backend must be refused", wm)
		}
		if !strings.Contains(err.Error(), "nitro") ||
			!strings.Contains(err.Error(), "enforce") ||
			!strings.Contains(err.Error(), "durable") {
			t.Fatalf("watermark %+v: unhelpful error %v", wm, err)
		}
	}
}

func TestCheckBackendWatermark_Allowed(t *testing.T) {
	t.Parallel()
	nitro := []config.SignerBackendConfig{{Name: "n", Type: "nitro"}}
	dir := t.TempDir()
	for _, wm := range []config.SignerWatermarkConfig{
		{Type: "file", Path: filepath.Join(dir, "a.db"), Mode: "enforce"},
		{Type: "file", Path: filepath.Join(dir, "b.db")},
		{Type: "file", Path: "file:" + filepath.Join(dir, "c.db"), Mode: "enforce"},
		{Type: "postgres", Mode: "enforce", DSN: "postgres://x"},
		// New coerces any mode other than warn or off to enforce
		{Type: "file", Path: filepath.Join(dir, "d.db"), Mode: "Enforce"},
	} {
		if err := CheckBackendWatermark(nitro, wm); err != nil {
			t.Fatalf("watermark %+v: %v", wm, err)
		}
	}
	// Other backends keep their existing latitude, including
	// confidential-space, whose counter lives in the measured workload.
	for _, typ := range []string{"dir", "confidential-space", "armory"} {
		err := CheckBackendWatermark(
			[]config.SignerBackendConfig{{Name: "b", Type: typ}},
			config.SignerWatermarkConfig{Mode: "off"},
		)
		if err != nil {
			t.Fatalf("backend %q: %v", typ, err)
		}
	}
}
