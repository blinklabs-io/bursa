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

package confidentialspace

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var (
	// ErrEnvelopeNotFound indicates that no wrapped key has been created.
	ErrEnvelopeNotFound = errors.New("wrapped key not found")
	// ErrEnvelopeExists indicates that another workload created the key first.
	ErrEnvelopeExists = errors.New("wrapped key already exists")
	// ErrEnvelopeChanged indicates that another workload replaced the expected
	// bootstrap envelope.
	ErrEnvelopeChanged = errors.New("wrapped key changed")
)

// FileEnvelopeStore persists one wrapped key with restrictive permissions and
// atomic create-only publication. It never overwrites an existing identity.
type FileEnvelopeStore struct {
	path string
}

// NewFileEnvelopeStore constructs a wrapped-key store at path.
func NewFileEnvelopeStore(path string) (*FileEnvelopeStore, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New("wrapped key path must be absolute")
	}
	return &FileEnvelopeStore{path: filepath.Clean(path)}, nil
}

// Load reads the wrapped key without following a final-component symlink.
func (s *FileEnvelopeStore) Load() ([]byte, error) {
	info, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrEnvelopeNotFound
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("wrapped key path is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New(
			"wrapped key permissions allow group or other access",
		)
	}
	f, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxRequestBody+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxRequestBody {
		return nil, errors.New("wrapped key exceeds size limit")
	}
	return data, nil
}

// Create atomically publishes a new wrapped key and refuses replacement.
func (s *FileEnvelopeStore) Create(data []byte) error {
	tmpName, err := s.writeTemp(data)
	if err != nil {
		return err
	}
	defer os.Remove(tmpName)
	if err := os.Link(tmpName, s.path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrEnvelopeExists
		}
		return fmt.Errorf("publish wrapped key: %w", err)
	}
	return syncDirectory(filepath.Dir(s.path))
}

// Replace atomically activates a bootstrap envelope only when its expected
// contents still identify the file being replaced.
func (s *FileEnvelopeStore) Replace(expected, data []byte) error {
	current, err := s.Load()
	if err != nil {
		return err
	}
	if !bytes.Equal(current, expected) {
		return ErrEnvelopeChanged
	}
	tmpName, err := s.writeTemp(data)
	if err != nil {
		return err
	}
	defer os.Remove(tmpName)
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("replace wrapped key: %w", err)
	}
	return syncDirectory(filepath.Dir(s.path))
}

func (s *FileEnvelopeStore) writeTemp(data []byte) (string, error) {
	if len(data) == 0 || len(data) > maxRequestBody {
		return "", errors.New("wrapped key has invalid size")
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".bursa-wrapped-key-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	remove = false
	return tmpName, nil
}

func syncDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync wrapped key directory: %w", err)
	}
	return nil
}
