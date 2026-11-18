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

//go:build windows

package atomicfile

import "testing"

func TestExtendedWindowsPath(t *testing.T) {
	tests := map[string]struct {
		path string
		want string
	}{
		"drive": {
			path: `C:\state\wallet.json`,
			want: `\\?\C:\state\wallet.json`,
		},
		"UNC": {
			path: `\\server\share\state\wallet.json`,
			want: `\\?\UNC\server\share\state\wallet.json`,
		},
		"already extended": {
			path: `\\?\C:\state\wallet.json`,
			want: `\\?\C:\state\wallet.json`,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := extendedWindowsPath(test.path)
			if err != nil {
				t.Fatalf("extendedWindowsPath: %v", err)
			}
			if got != test.want {
				t.Fatalf("extended path = %q, want %q", got, test.want)
			}
		})
	}
}
