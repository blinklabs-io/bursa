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
	"errors"

	"github.com/blinklabs-io/bursa/armory/se050"
)

// chip serves the signing endpoints from an SE050 session, reopening the
// session once when a command fails in transport rather than with a status
// word. Callers hold the session lock.
type chip struct {
	se  *se050.SE050
	log func(format string, args ...any)
}

func retry[T any](c *chip, fn func() (T, error)) (T, error) {
	v, err := fn()

	var sw *se050.StatusError

	if err == nil || errors.As(err, &sw) {
		return v, err
	}

	c.log("se050: transport error, reopening session: %v", err)

	if rerr := c.se.Reopen(); rerr != nil {
		c.log("se050: reopen: %v", rerr)
		return v, err
	}

	return fn()
}

func (c *chip) Exists(id uint32) (bool, error) {
	return retry(c, func() (bool, error) { return c.se.Exists(id) })
}

func (c *chip) GenerateEd25519(id uint32, transient bool) error {
	_, err := retry(c, func() (struct{}, error) { return struct{}{}, c.se.GenerateEd25519(id, transient) })
	return err
}

func (c *chip) ImportEd25519(id uint32, seed []byte, transient bool) error {
	_, err := retry(c, func() (struct{}, error) { return struct{}{}, c.se.ImportEd25519(id, seed, transient) })
	return err
}

func (c *chip) PublicKeyEd25519(id uint32) (ed25519.PublicKey, error) {
	return retry(c, func() (ed25519.PublicKey, error) { return c.se.PublicKeyEd25519(id) })
}

func (c *chip) SignEd25519(id uint32, msg []byte) ([]byte, error) {
	return retry(c, func() ([]byte, error) { return c.se.SignEd25519(id, msg) })
}

func (c *chip) WriteBinary(id uint32, data []byte) error {
	_, err := retry(c, func() (struct{}, error) { return struct{}{}, c.se.WriteBinary(id, data) })
	return err
}

func (c *chip) Delete(id uint32) error {
	return c.se.Delete(id)
}

func (c *chip) ReadBinary(id uint32) ([]byte, error) {
	return retry(c, func() ([]byte, error) { return c.se.ReadBinary(id) })
}
