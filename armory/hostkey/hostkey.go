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

// Package hostkey reads the host signing key armory-pool host-key writes and
// authenticates signing requests with it, for the armory commands that talk
// to a device holding registered host keys.
package hostkey

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/blinklabs-io/bursa/armory/device"
)

const (
	// Type is the text envelope type of a host signing key file.
	Type = "ArmoryHostSigningKey_ed25519"
	// Description is the text envelope description of a host signing key file.
	Description = "Armory host signing key"
)

// Read reads a host signing key file, refusing one others can read.
func Read(file string) (ed25519.PrivateKey, error) {
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

	var env struct {
		Type    string `json:"type"`
		CborHex string `json:"cborHex"`
	}

	if err = json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("not a text envelope: %w", err)
	}

	raw, err := hex.DecodeString(strings.TrimSpace(env.CborHex))
	if err != nil {
		return nil, fmt.Errorf("bad cborHex: %w", err)
	}

	if env.Type != Type {
		return nil, fmt.Errorf("envelope type %q, want %q", env.Type, Type)
	}

	if len(raw) != 34 || raw[0] != 0x58 || raw[1] != 0x20 {
		return nil, errors.New("host key cborHex is not a 32-byte seed")
	}

	return ed25519.NewKeyFromSeed(raw[2:]), nil
}

// Authenticate returns req carrying the challenge, the host public key and
// the host signature over the request binding.
func Authenticate(req device.SignRequest, key ed25519.PrivateKey, challenge []byte) device.SignRequest {
	req.Challenge = challenge
	req.HostKey = key.Public().(ed25519.PublicKey)
	req.HostSignature = ed25519.Sign(key, device.RequestBinding(req))

	return req
}
