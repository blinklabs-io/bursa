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

import (
	"fmt"
	"net/http"
)

// maxSignable bounds signing requests; an operational certificate body is
// 48 bytes.
const maxSignable = 128

func init() {
	http.HandleFunc("/sign", (&legacy).sign)
	http.HandleFunc("/pubkey", (&legacy).publicKey)
}

// sign returns a cold key signature over the hex request body.
//
// TESTNET ONLY: this endpoint is unauthenticated, anything that can reach
// the USB network can obtain signatures.
func (s *signer) sign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	msg, err := readHexBody(r, maxSignable)

	if err != nil || len(msg) == 0 || len(msg) > maxSignable {
		http.Error(w, "expected hex message", http.StatusBadRequest)
		return
	}

	s.Lock()
	defer s.Unlock()

	if s.se == nil {
		http.Error(w, errNotOpen.Error(), http.StatusServiceUnavailable)
		return
	}

	sig, err := s.se.SignEd25519(coldKeyID, msg)

	if err != nil {
		http.Error(w, fmt.Sprintf("sign: %v", err), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "%x\n", sig)
}
