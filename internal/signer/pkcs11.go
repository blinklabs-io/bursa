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

package signer

import (
	"errors"
	"fmt"
	"os"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

// buildPKCS11Backend validates config and constructs a PKCS#11 HSM backend. It
// is pure Go and compiles in both build configurations: the actual driver is
// backend.NewPKCS11Backend, which is the real CGO implementation under
// -tags pkcs11 and a not-compiled-in stub otherwise. The user PIN is read from
// the configured env var and never taken from plaintext config.
func buildPKCS11Backend(c config.SignerBackendConfig) (backend.Backend, error) {
	if c.Module == "" {
		return nil, errors.New("pkcs11 backend requires module (path to the PKCS#11 .so)")
	}
	if c.TokenLabel == "" && c.Slot == nil {
		return nil, errors.New("pkcs11 backend requires token_label or slot")
	}
	if c.PINEnv == "" {
		return nil, errors.New("pkcs11 backend requires pin_env (env var holding the user PIN)")
	}
	pin := os.Getenv(c.PINEnv)
	if pin == "" {
		return nil, fmt.Errorf("pkcs11 pin env var %s is empty", c.PINEnv)
	}
	keys := make([]backend.PKCS11KeyConfig, 0, len(c.Keys))
	for _, k := range c.Keys {
		kt := backend.KeyType(k.Type)
		if !kt.Valid() {
			return nil, fmt.Errorf("pkcs11 key %q: invalid key type %q", k.Name, k.Type)
		}
		keys = append(keys, backend.PKCS11KeyConfig{Label: k.Name, Type: kt})
	}
	return backend.NewPKCS11Backend(backend.PKCS11Config{
		Name:       c.Name,
		Module:     c.Module,
		TokenLabel: c.TokenLabel,
		Slot:       c.Slot,
		PIN:        pin,
		Keys:       keys,
	})
}
