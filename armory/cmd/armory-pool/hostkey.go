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
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/blinklabs-io/bursa/armory/device"
)

const (
	hostKeyType = "ArmoryHostSigningKey_ed25519"
	hostKeyDesc = "Armory host signing key"
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

	if _, err = f.Write(marshalEnvelope(hostKeyType, hostKeyDesc, vkeyCBOR(priv.Seed()))); err != nil {
		f.Close()
		return err
	}

	if err = f.Close(); err != nil {
		return err
	}

	_, err = fmt.Fprintf(out, "%x\n", pub)

	return err
}

// readHostKey reads a host signing key file, refusing one others can read.
func readHostKey(file string) (ed25519.PrivateKey, error) {
	fi, err := os.Stat(file)
	if err != nil {
		return nil, err
	}

	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("host key file %s is readable by others; chmod 600 it", file)
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	env, raw, err := readEnvelope(data)
	if err != nil {
		return nil, err
	}

	if env.Type != hostKeyType {
		return nil, fmt.Errorf("envelope type %q, want %q", env.Type, hostKeyType)
	}

	if len(raw) != 34 || raw[0] != 0x58 || raw[1] != 0x20 {
		return nil, errors.New("host key cborHex is not a 32-byte seed")
	}

	return ed25519.NewKeyFromSeed(raw[2:]), nil
}

// sign posts a signing request, first authenticating it with the host key
// when the session has one.
func (s *session) sign(req device.SignRequest, resp *device.SignResponse) error {
	if s.hostKey != nil {
		var ch device.ChallengeResponse

		if err := s.c.post("/v1/challenge", struct{}{}, &ch); err != nil {
			return err
		}

		req.Challenge = ch.Challenge
		req.HostKey = s.hostKey.Public().(ed25519.PublicKey)
		req.HostSignature = ed25519.Sign(s.hostKey, device.RequestBinding(req))
	}

	return s.c.post("/v1/sign", req, resp)
}
