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
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"github.com/blinklabs-io/bursa/armory/device"
	"github.com/blinklabs-io/bursa/armory/hostkey"
)

const (
	hostKeyType = hostkey.Type
	hostKeyDesc = hostkey.Description
)

// newHostKey writes a new host signing key to file, which must not exist,
// and prints its public key in hex for /provision/host-key.
func newHostKey(file string, out io.Writer) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}

	// O_EXCL means this call created file, so a failed write removes it
	if _, err = f.Write(marshalEnvelope(hostKeyType, hostKeyDesc, vkeyCBOR(priv.Seed()))); err != nil {
		f.Close()
		_ = os.Remove(file)

		return err
	}

	if err = f.Close(); err != nil {
		_ = os.Remove(file)

		return err
	}

	_, err = fmt.Fprintf(out, "%x\n", pub)

	return err
}

// readHostKey reads a host signing key file, refusing one others can read.
func readHostKey(file string) (ed25519.PrivateKey, error) { return hostkey.Read(file) }

// sign posts a signing request, first authenticating it with the host key
// when the session has one.
func (s *session) sign(req device.SignRequest, resp *device.SignResponse) error {
	if s.hostKey != nil {
		var ch device.ChallengeResponse

		if err := s.c.post("/v1/challenge", struct{}{}, &ch); err != nil {
			return err
		}

		req = hostkey.Authenticate(req, s.hostKey, ch.Challenge)
	}

	return s.c.post("/v1/sign", req, resp)
}
