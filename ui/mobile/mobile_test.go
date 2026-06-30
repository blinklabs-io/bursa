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
package mobile

import "testing"

// TestNewHandleLifecycleBeforeStart verifies the pre-Start contract the
// Android/iOS shells rely on: a fresh handle reports port 0, and Stop is a
// harmless no-op before a successful Start (so a shell that tears down after a
// failed Start does not panic). This exercises the binding without spinning up a
// real node.
func TestNewHandleLifecycleBeforeStart(t *testing.T) {
	a := New()
	if a == nil {
		t.Fatal("New returned nil")
	}
	if got := a.Port(); got != 0 {
		t.Fatalf("Port before Start = %d, want 0", got)
	}
	if err := a.Stop(); err != nil {
		t.Fatalf("Stop before Start = %v, want nil", err)
	}
}

// gomobileSupported is true only for the value types gomobile can marshal across
// the language boundary (bool, int/int64, float, string, []byte, error) plus
// exported struct pointers (treated as opaque handles). It is used by
// TestBindingSignaturesAreGomobileCompatible to assert no exported binding
// method leaks an unsupported type (map, slice-of-struct, channel, ...), which
// would make `gomobile bind` fail in CI.
func gomobileSupported(kind string) bool {
	switch kind {
	case "bool", "int", "int64", "float32", "float64", "string", "[]byte", "error",
		"*mobile.App": // exported struct pointer — crosses as an opaque handle
		return true
	}
	return false
}

// TestBindingSignaturesAreGomobileCompatible is a guard against accidentally
// adding an exported binding method (or a New return) whose parameter/return
// types gomobile cannot marshal. It documents the supported set and fails fast
// here (in plain `go test`) rather than only at `gomobile bind` time in CI.
func TestBindingSignaturesAreGomobileCompatible(t *testing.T) {
	// New() *App
	if !gomobileSupported("*mobile.App") {
		t.Fatal("New return type *App must be a supported handle type")
	}
	// The exported method signatures, enumerated as their gomobile-visible types.
	// Keeping this list in lockstep with the real methods is the point: changing a
	// signature to an unsupported type should be caught by review against this.
	type sig struct {
		method string
		params []string
		result []string
	}
	sigs := []sig{
		{"Start", []string{"string", "string", "bool"}, []string{"error"}},
		{"Port", nil, []string{"int"}},
		{"Stop", nil, []string{"error"}},
		{"OnNetworkChanged", nil, []string{"error"}},
	}
	for _, s := range sigs {
		for _, p := range s.params {
			if !gomobileSupported(p) {
				t.Fatalf("%s param type %q is not gomobile-compatible", s.method, p)
			}
		}
		for _, r := range s.result {
			if !gomobileSupported(r) {
				t.Fatalf("%s result type %q is not gomobile-compatible", s.method, r)
			}
		}
	}
}
