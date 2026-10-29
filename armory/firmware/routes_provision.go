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
	"fmt"
	"net/http"
	"sync"
	"time"

	usbarmory "github.com/usbarmory/tamago/board/usbarmory/mk2"

	"github.com/blinklabs-io/bursa/armory/device"
)

const buildMode = "provisioning build: signing endpoints are not served"

// routes serves provisioning only: key import, profiles, the reward account,
// the opcert floor and reset. /pubkey returns the key the legacy /provision
// imported, not the identity key.
func routes(svc *device.Service, s *signer, mu *sync.Mutex) {
	http.HandleFunc("/provision", s.provision)
	http.HandleFunc("/pubkey", s.publicKey)
	http.Handle("/provision/", svc.ProvisioningHandler())

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
			// never reset in the middle of an SE050 write
			mu.Lock()
			usbarmory.Reset()
		}()
	})
}
