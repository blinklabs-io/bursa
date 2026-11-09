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

package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/blinklabs-io/bursa/armory/se050"
)

// coldKeyID holds the persistent pool cold key. It is outside the bring-up
// test range so bring-up cleanup can never delete it.
const coldKeyID uint32 = 0x20e50010

var errNotOpen = errors.New("SE050 not available")

var firmwareSigner signer

// signer serializes access to the SE050 session, which bring-up opens.
type signer struct {
	*sync.Mutex
	se *se050.SE050
	// record logs a signature before it is made; /sign in testnet builds
	// signs only when it returns nil
	record func(msg []byte) error
}

func (s *signer) set(se *se050.SE050) {
	s.Lock()
	defer s.Unlock()

	s.se = se
}

func readHexBody(r *http.Request, max int) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(2*max+2)))

	if err != nil {
		return nil, err
	}

	return hex.DecodeString(string(bytes.TrimSpace(body)))
}

func (s *signer) writePublicKey(w http.ResponseWriter) {
	pub, err := s.se.PublicKeyEd25519(coldKeyID)

	if err != nil {
		http.Error(
			w,
			fmt.Sprintf("read public key: %v", err),
			http.StatusInternalServerError,
		)
		return
	}

	fmt.Fprintf(w, "%x\n", []byte(pub))
}

func (s *signer) publicKey(w http.ResponseWriter, _ *http.Request) {
	s.Lock()
	defer s.Unlock()

	if s.se == nil {
		http.Error(w, errNotOpen.Error(), http.StatusServiceUnavailable)
		return
	}

	s.writePublicKey(w)
}
