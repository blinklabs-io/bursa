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
	"fmt"
	"net/http"
	"sync"
	"time"

	usbarmory "github.com/usbarmory/tamago/board/usbarmory/mk2"

	"github.com/blinklabs-io/bursa/armory/device"
)

const buildMode = "wipe build: deletes profiles and keys on request; signing and provisioning endpoints are not served"

// routes serves only the wipe endpoints and reset. Removing a profile,
// resetting the signing log head or wiping the device needs this image,
// loaded over USB recovery boot.
func routes(svc *device.Service, _ *signer, mu *sync.Mutex) {
	http.Handle("/wipe/", svc.WipeHandler())

	// a cold reset returns an unflashed board to USB recovery mode, ready
	// for the next image
	http.HandleFunc("/reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}

		fmt.Fprintln(w, "resetting")

		go func() {
			time.Sleep(100 * time.Millisecond)
			// never reset in the middle of an SE050 delete
			mu.Lock()
			usbarmory.Reset()
		}()
	})
}
