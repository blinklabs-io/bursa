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

//go:build provision

package main

import (
	"sync"

	"github.com/blinklabs-io/bursa/armory/device"
)

// The provisioning image does not sign, so it neither opens nor requires the
// signing log: the signing image formats a blank card on its first start,
// when the head object in the SE050 is not yet set.
func requireSigningLog(*device.Service) {}

func openSigningLog(r *Report, _ sync.Locker, _ *device.Service, _ *chip) bool {
	r.Logf("signing log: not used by the provisioning image")

	return true
}
