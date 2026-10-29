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

//go:build testnet

package main

import "github.com/blinklabs-io/bursa/armory/se050"

// keyTests generates, imports and deletes transient test keys.
func keyTests(r *Report, se *se050.SE050) bool {
	pass := testGenerated(r, se)
	return testImported(r, se) && pass
}
