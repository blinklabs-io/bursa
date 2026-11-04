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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// fileChip is a virtual SE050 whose objects persist in a JSON file, so the
// provisioning, signing and wipe images can run one after another against
// the same chip, as on a device that is reflashed. Private keys are stored
// as plaintext seeds: it is for test keys only.
type fileChip struct {
	mu   sync.Mutex
	path string
	keys map[uint32][]byte // Ed25519 seeds
	bins map[uint32][]byte
	// transient keys live until the process exits, as SE050 transient
	// objects live until reset, and are never saved
	transient map[uint32]bool
}

type chipState struct {
	Keys map[string][]byte `json:"keys"`
	Bins map[string][]byte `json:"bins"`
}

var (
	errExists   = errors.New("object exists")
	errNoObject = errors.New("no such object")
)

// openChip loads the chip state from path, or starts an empty chip if the
// file does not exist yet.
func openChip(path string) (*fileChip, error) {
	c := &fileChip{path: path, keys: map[uint32][]byte{}, bins: map[uint32][]byte{}, transient: map[uint32]bool{}}

	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}

	if err != nil {
		return nil, err
	}

	var st chipState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("chip state %s: %w", path, err)
	}

	for k, v := range st.Keys {
		id, err := parseID(k)
		if err != nil {
			return nil, err
		}

		if len(v) != ed25519.SeedSize {
			return nil, fmt.Errorf("chip state: key %s is not a seed", k)
		}

		c.keys[id] = v
	}

	for k, v := range st.Bins {
		id, err := parseID(k)
		if err != nil {
			return nil, err
		}

		c.bins[id] = v
	}

	return c, nil
}

func parseID(s string) (uint32, error) {
	v, err := strconv.ParseUint(s, 0, 32)
	if err != nil {
		return 0, fmt.Errorf("chip state: object id %q: %w", s, err)
	}

	return uint32(v), nil
}

// save writes the state atomically; callers hold c.mu.
func (c *fileChip) save() error {
	st := chipState{Keys: map[string][]byte{}, Bins: map[string][]byte{}}
	for id, v := range c.keys {
		if !c.transient[id] {
			st.Keys[fmt.Sprintf("%#08x", id)] = v
		}
	}

	for id, v := range c.bins {
		st.Bins[fmt.Sprintf("%#08x", id)] = v
	}

	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(c.path), ".chip-*")
	if err != nil {
		return err
	}

	defer os.Remove(tmp.Name()) //nolint:errcheck // gone after the rename

	if _, err := tmp.Write(b); err != nil {
		tmp.Close() //nolint:errcheck,gosec // the write error is returned
		return err
	}

	if err := tmp.Sync(); err != nil {
		tmp.Close() //nolint:errcheck,gosec // the sync error is returned
		return err
	}

	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmp.Name(), c.path)
}

// commit applies a change to object id and saves the chip. If the save
// fails, the object is restored, so the chip in memory never holds state
// that a restart would lose. Callers hold c.mu.
func (c *fileChip) commit(id uint32, change func()) error {
	key, hadKey := c.keys[id]
	bin, hadBin := c.bins[id]
	transient := c.transient[id]

	change()

	if err := c.save(); err != nil {
		delete(c.keys, id)
		delete(c.bins, id)
		delete(c.transient, id)

		if hadKey {
			c.keys[id] = key
		}

		if hadBin {
			c.bins[id] = bin
		}

		if transient {
			c.transient[id] = true
		}

		return err
	}

	return nil
}

func (c *fileChip) exists(id uint32) bool {
	_, k := c.keys[id]
	_, b := c.bins[id]

	return k || b
}

func (c *fileChip) Exists(id uint32) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.exists(id), nil
}

func (c *fileChip) GenerateEd25519(id uint32, transient bool) error {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return err
	}

	return c.ImportEd25519(id, seed, transient)
}

func (c *fileChip) ImportEd25519(id uint32, seed []byte, transient bool) error {
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("seed must be %d bytes", ed25519.SeedSize)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.exists(id) {
		return errExists
	}

	if transient {
		c.keys[id] = bytes.Clone(seed)
		c.transient[id] = true

		return nil
	}

	return c.commit(id, func() { c.keys[id] = bytes.Clone(seed) })
}

func (c *fileChip) PublicKeyEd25519(id uint32) (ed25519.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	seed, ok := c.keys[id]
	if !ok {
		return nil, errNoObject
	}

	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), nil
}

func (c *fileChip) SignEd25519(id uint32, msg []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	seed, ok := c.keys[id]
	if !ok {
		return nil, errNoObject
	}

	return ed25519.Sign(ed25519.NewKeyFromSeed(seed), msg), nil
}

func (c *fileChip) WriteBinary(id uint32, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.keys[id]; ok {
		return errExists
	}

	return c.commit(id, func() { c.bins[id] = bytes.Clone(data) })
}

func (c *fileChip) ReadBinary(id uint32) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	b, ok := c.bins[id]
	if !ok {
		return nil, errNoObject
	}

	return bytes.Clone(b), nil
}

func (c *fileChip) Delete(id uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.exists(id) {
		return errNoObject
	}

	return c.commit(id, func() {
		delete(c.keys, id)
		delete(c.bins, id)
		delete(c.transient, id)
	})
}
