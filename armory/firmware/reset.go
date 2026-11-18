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

//go:build provision || wipe

package main

import (
	"sync"
	"time"

	usbarmory "github.com/usbarmory/tamago/board/usbarmory/mk2"
)

// scheduleReset returns an action that lets the response finish, then waits
// for any in-flight SE050 operation before resetting into recovery mode.
func scheduleReset(mu *sync.Mutex) func() {
	return func() {
		go func() {
			time.Sleep(100 * time.Millisecond)
			mu.Lock()
			usbarmory.Reset()
		}()
	}
}
