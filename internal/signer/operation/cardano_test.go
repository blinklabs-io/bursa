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

package operation

import "testing"

// compile-time assertion that the real adapter satisfies the interface.
var _ Cardano = BursaCardano{}

func TestBursaCardano_TxID_BadInput(t *testing.T) {
	if _, err := (BursaCardano{}).TxID([]byte{0x00}); err == nil {
		t.Fatalf("expected error decoding garbage tx")
	}
}
