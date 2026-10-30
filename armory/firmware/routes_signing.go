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

//go:build !provision && !wipe

package main

import (
	"net/http"
	"sync"

	"github.com/blinklabs-io/bursa/armory/device"
)

const buildMode = "signing build: provisioning endpoints are not served"

// routes serves inventory and signing only. Provisioning, the opcert floor
// and reset need the provisioning image, loaded over USB recovery boot.
func routes(svc *device.Service, _ *signer, _ *sync.Mutex) {
	http.Handle("/v1/", svc.SigningHandler())
}
