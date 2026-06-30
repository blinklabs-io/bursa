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
	"testing"
)

// TestAppOnNetworkChangedBeforeStop: OnNetworkChanged on a nil (pre-Boot) App
// must not panic and must return nil. Boot is heavyweight (real node); we test
// OnNetworkChanged's nil-guard through the zero App value path directly.
func TestAppOnNetworkChangedNilApp(t *testing.T) {
	// A zero-value App has sup == nil. OnNetworkChanged must guard this
	// just as Stop does (a.stopped check / nil-guard pattern).
	a := &App{}
	if err := a.OnNetworkChanged(); err != nil {
		t.Fatalf("OnNetworkChanged on zero App = %v, want nil", err)
	}
}
