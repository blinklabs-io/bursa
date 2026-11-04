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
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// maxDirSecretSize bounds one SOPS-encrypted key file. A cardano-cli signing
// key envelope encrypted to a few recipients is a few KiB.
const maxDirSecretSize = 64 << 10

// dirSecretExt is the extension of the files a DirSecretSource serves. The
// sops backend decrypts in the SOPS JSON format.
const dirSecretExt = ".json"

// DirSecretSource serves SOPS-encrypted key files from a local directory, such
// as a mounted Kubernetes Secret. Each regular *.json file whose name does not
// start with a dot is one secret, named by its file name. Symlinks to regular
// files are followed, so the ..data links of a Secret volume work; the
// entries starting with a dot that the volume uses internally are skipped.
//
// The files hold ciphertext, so they are read without the owner-only
// permission check that plaintext key files get.
type DirSecretSource struct {
	dir string
}

// NewDirSecretSource returns a source over dir, which must be a directory.
func NewDirSecretSource(dir string) (*DirSecretSource, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("secret directory %q: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("secret directory %q is not a directory", dir)
	}
	return &DirSecretSource{dir: dir}, nil
}

// validName reports whether name is a file name this source serves.
func validName(name string) bool {
	return name != "" &&
		!strings.HasPrefix(name, ".") &&
		filepath.Base(name) == name &&
		!strings.ContainsRune(name, filepath.Separator) &&
		strings.HasSuffix(name, dirSecretExt)
}

// List returns the names of the secrets in the directory, sorted. An entry
// that looks like a secret but cannot be stat'ed, such as a dangling symlink,
// fails the whole listing: skipping it would boot a signer that silently lacks
// a configured key.
func (s *DirSecretSource) List(_ context.Context) ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("read secret directory %q: %w", s.dir, err)
	}
	var names []string
	for _, e := range entries {
		if !validName(e.Name()) {
			continue
		}
		info, err := os.Stat(filepath.Join(s.dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("stat secret %q: %w", e.Name(), err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

// Get returns the contents of the named secret file.
func (s *DirSecretSource) Get(_ context.Context, name string) ([]byte, error) {
	if !validName(name) {
		return nil, fmt.Errorf("invalid secret name %q", name)
	}
	f, err := openDirSecret(filepath.Join(s.dir, name))
	if err != nil {
		return nil, fmt.Errorf("open secret %q: %w", name, err)
	}
	defer f.Close() //nolint:errcheck // read-only handle
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat secret %q: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("secret %q is not a regular file", name)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxDirSecretSize+1))
	if err != nil {
		return nil, fmt.Errorf("read secret %q: %w", name, err)
	}
	if len(data) > maxDirSecretSize {
		return nil, fmt.Errorf("secret %q exceeds %d bytes", name, maxDirSecretSize)
	}
	return data, nil
}

// errSopsSourceConflict is returned when a sops backend names both sources.
var errSopsSourceConflict = errors.New("set either path or secret_prefix, not both")
