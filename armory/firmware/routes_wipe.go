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

//go:build wipe

package main

import (
	"net/http"
	"sync"

	"github.com/blinklabs-io/bursa/armory/device"
)

const buildMode = "wipe build: deletes profiles and keys on request; signing and provisioning endpoints are not served"

// imageOpenRoutes are the routes of this image that never take host
// authentication. /wipe/device is confirmed by the identity public key,
// /wipe/objects only lists object IDs.
var imageOpenRoutes = []string{
	"/v1/challenge",
	"/wipe/device",
	"/wipe/objects",
}

// servesInventory is clear: this image does not serve /v1/inventory.
const servesInventory = false

// routes serves only the wipe endpoints and reset. Removing a profile,
// resetting the signing log head or wiping the device needs this image,
// loaded over USB recovery boot.
func routes(svc *device.Service, _ *signer, mu *sync.Mutex) {
	http.Handle("/wipe/", svc.WipeHandler())
	http.Handle("/v1/challenge", svc.WipeHandler())

	http.Handle(
		"POST "+device.RouteReset,
		svc.ResetHandler(scheduleReset(mu)),
	)
}
