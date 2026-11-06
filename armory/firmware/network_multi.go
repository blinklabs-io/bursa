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

//go:build multi

package main

import "github.com/blinklabs-io/bursa/armory/device"

// configureScope makes the image serve the scopes of device.MultiScopes:
// every testnet, the Cardano mainnet and the Prime mainnet. Every request
// needs a host key of the scope it acts on.
func configureScope(svc *device.Service, report *Report) {
	svc.SetScopes(device.MultiScopes())

	for _, sc := range device.MultiScopes() {
		report.Logf("scope: %s (network id %d)", sc.Name(), sc.Network)
	}

	report.Logf(
		"multi image: other profiles are refused; every request needs a host key of the profile's scope",
	)
}
