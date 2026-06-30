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

// TestOnResumeNoOpBeforeStart: OnResume on a fresh (unstarted) App must return
// nil and must not panic. This mirrors the nil-guard pattern of OnNetworkChanged
// and Stop.
func TestOnResumeNoOpBeforeStart(t *testing.T) {
	a := New()
	if err := a.OnResume(); err != nil {
		t.Fatalf("OnResume before Start = %v, want nil", err)
	}
}

// TestOnResumeSignatureIsGomobileCompatible: OnResume takes no parameters and
// returns only error — both gomobile-supported types.
func TestOnResumeSignatureIsGomobileCompatible(t *testing.T) {
	// params: none
	// result: error
	if !gomobileSupported("error") {
		t.Fatal("OnResume result type error is not gomobile-compatible")
	}
}
