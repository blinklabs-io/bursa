// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nft

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// cache is a content-addressed on-disk store keyed by CID. Because a CID is the
// hash of its content, an entry is immutable and may be cached forever — there
// is no invalidation. Files live under <dataDir>/nft-cache.
type cache struct {
	dir string
}

// maxImageBytes caps a single cached image. NFT art is small; a multi-megabyte
// "image" is almost certainly hostile (a decompression bomb or an attempt to
// fill the disk) and is refused.
const maxImageBytes = 8 << 20 // 8 MiB

func newCache(dataDir string) (*cache, error) {
	dir := filepath.Join(dataDir, "nft-cache")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("nft: create cache dir: %w", err)
	}
	return &cache{dir: dir}, nil
}

// path is the on-disk location for a CID. The CID string is used verbatim as
// the filename; CIDs are restricted to base32/base58 alphanumerics (validated
// upstream by parseImageCID), so they contain no path separators and cannot
// escape the cache directory.
func (c *cache) path(cid string) string {
	return filepath.Join(c.dir, cid)
}

// has reports whether the CID is already cached.
func (c *cache) has(cid string) bool {
	if cid == "" {
		return false
	}
	_, err := os.Stat(c.path(cid))
	return err == nil
}

// get returns the cached bytes for a CID, or os.ErrNotExist if absent.
func (c *cache) get(cid string) ([]byte, error) {
	if cid == "" {
		return nil, os.ErrNotExist
	}
	b, err := os.ReadFile(c.path(cid))
	if err != nil {
		return nil, err
	}
	return b, nil
}

// put atomically writes bytes for a CID. It writes to a temp file in the same
// directory and renames, so a crashed write never leaves a partial entry that a
// later has() would treat as complete.
func (c *cache) put(cid string, data []byte) error {
	if cid == "" {
		return errors.New("nft: empty cid")
	}
	if len(data) > maxImageBytes {
		return fmt.Errorf("nft: image %d bytes exceeds cap %d", len(data), maxImageBytes)
	}
	tmp, err := os.CreateTemp(c.dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, c.path(cid))
}
