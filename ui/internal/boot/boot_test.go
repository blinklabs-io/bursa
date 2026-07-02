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
package boot

import (
	"context"
	"strings"
	"testing"
)

// TestBootValidatesConfig covers the cheap, no-node validation paths so a
// misconfiguration is reported synchronously by Boot (before any node is
// launched) rather than failing later.
func TestBootValidatesConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantSub string
	}{
		{
			name:    "missing network",
			cfg:     Config{DataDir: t.TempDir()},
			wantSub: "network is required",
		},
		{
			name:    "missing data dir",
			cfg:     Config{Network: "preview"},
			wantSub: "data dir is required",
		},
		{
			name:    "invalid network",
			cfg:     Config{Network: "bogus", DataDir: t.TempDir()},
			wantSub: "invalid network",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			app, err := Boot(context.Background(), tc.cfg)
			if app != nil {
				_ = app.Stop()
				t.Fatalf("expected nil App on error, got %v", app)
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}
