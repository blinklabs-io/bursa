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
	"sort"
	"strings"
	"sync"
	"time"
)

// cache is a content-addressed on-disk store keyed by CID. Entries are immutable
// but may be evicted to enforce the aggregate quota. Files live under
// <dataDir>/nft-cache.
type cache struct {
	dir      string
	maxBytes int64
	mu       sync.Mutex
}

// maxImageBytes caps a single cached image. NFT art is small; a multi-megabyte
// "image" is almost certainly hostile (a decompression bomb or an attempt to
// fill the disk) and is refused.
const maxImageBytes = 8 << 20 // 8 MiB

// maxCacheBytes bounds the aggregate persistent media cache. Entries are
// evicted least-recently-used when a new image would exceed this quota.
const maxCacheBytes = 256 << 20 // 256 MiB

func newCache(dataDir string) (*cache, error) {
	dir := filepath.Join(dataDir, "nft-cache")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("nft: create cache dir: %w", err)
	}
	// A crash can strand an incomplete atomic-write temporary file. It is never
	// a valid cache entry and must not consume space outside the quota.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("nft: scan cache dir: %w", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".tmp-") {
			if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
				return nil, fmt.Errorf("nft: remove stale cache temp: %w", err)
			}
		}
	}
	return &cache{dir: dir, maxBytes: maxCacheBytes}, nil
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
	c.mu.Lock()
	defer c.mu.Unlock()
	path := c.path(cid)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Revalidate on every read so entries written by an older application
	// version cannot bypass newly introduced decoder resource limits.
	if err := validateImage(b); err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	// The modification time is the persistent LRU timestamp. Failure to update
	// it does not make an otherwise valid cached image unavailable.
	now := time.Now()
	_ = os.Chtimes(path, now, now)
	return b, nil
}

// put atomically writes bytes for a CID. It writes to a temp file in the same
// directory and renames, so a crashed write never leaves a partial entry that a
// later has() would treat as complete.
func (c *cache) put(cid string, data []byte) error {
	if cid == "" {
		return errors.New("nft: empty cid")
	}
	if err := validateImage(data); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.makeSpace(cid, int64(len(data))); err != nil {
		return err
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

type cacheEntry struct {
	path    string
	size    int64
	modTime time.Time
}

// makeSpace removes the oldest entries until replacing target with incoming
// will fit. Temporary files and non-regular directory entries are ignored.
func (c *cache) makeSpace(target string, incoming int64) error {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return fmt.Errorf("nft: scan cache: %w", err)
	}
	var total int64
	oldest := make([]cacheEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Name() == target || strings.HasPrefix(entry.Name(), ".tmp-") || entry.Type()&os.ModeType != 0 {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("nft: stat cache entry: %w", err)
		}
		total += info.Size()
		oldest = append(oldest, cacheEntry{
			path: filepath.Join(c.dir, entry.Name()), size: info.Size(), modTime: info.ModTime(),
		})
	}
	sort.Slice(oldest, func(i, j int) bool { return oldest[i].modTime.Before(oldest[j].modTime) })
	for _, entry := range oldest {
		if total+incoming <= c.maxBytes {
			break
		}
		if err := os.Remove(entry.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("nft: evict cache entry: %w", err)
		}
		total -= entry.size
	}
	if total+incoming > c.maxBytes {
		return fmt.Errorf("nft: image %d bytes exceeds cache quota %d", incoming, c.maxBytes)
	}
	return nil
}
