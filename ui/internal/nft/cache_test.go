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
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCachePutGetHas(t *testing.T) {
	c, err := newCache(t.TempDir())
	if err != nil {
		t.Fatalf("newCache: %v", err)
	}
	const cid = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
	if c.has(cid) {
		t.Fatal("has() true before put")
	}
	if _, err := c.get(cid); !os.IsNotExist(err) {
		t.Fatalf("get() before put = %v, want ErrNotExist", err)
	}

	data := validTestPNG()
	if err := c.put(cid, data); err != nil {
		t.Fatalf("put: %v", err)
	}
	if !c.has(cid) {
		t.Fatal("has() false after put")
	}
	got, err := c.get(cid)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("get() = %q, want %q", got, data)
	}
}

func TestCacheEvictsLeastRecentlyUsedToEnforceQuota(t *testing.T) {
	c, err := newCache(t.TempDir())
	if err != nil {
		t.Fatalf("newCache: %v", err)
	}
	data := validTestPNG()
	c.maxBytes = int64(2 * len(data))
	if err := c.put("old", data); err != nil {
		t.Fatalf("put old: %v", err)
	}
	oldTime := time.Now().Add(-time.Hour)
	if err := os.Chtimes(c.path("old"), oldTime, oldTime); err != nil {
		t.Fatalf("age old: %v", err)
	}
	if err := c.put("recent", data); err != nil {
		t.Fatalf("put recent: %v", err)
	}
	if err := c.put("new", data); err != nil {
		t.Fatalf("put new: %v", err)
	}

	if c.has("old") {
		t.Fatal("oldest entry was not evicted")
	}
	if !c.has("recent") || !c.has("new") {
		t.Fatal("cache did not retain the two newest entries")
	}
}

func TestCacheGetRefreshesEntryRecency(t *testing.T) {
	c, err := newCache(t.TempDir())
	if err != nil {
		t.Fatalf("newCache: %v", err)
	}
	data := validTestPNG()
	c.maxBytes = int64(2 * len(data))
	if err := c.put("first", data); err != nil {
		t.Fatalf("put first: %v", err)
	}
	oldTime := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(c.path("first"), oldTime, oldTime); err != nil {
		t.Fatalf("age first: %v", err)
	}
	if err := c.put("second", data); err != nil {
		t.Fatalf("put second: %v", err)
	}
	if _, err := c.get("first"); err != nil {
		t.Fatalf("get first: %v", err)
	}
	if err := c.put("third", data); err != nil {
		t.Fatalf("put third: %v", err)
	}

	if !c.has("first") {
		t.Fatal("recently read entry was evicted")
	}
	if c.has("second") {
		t.Fatal("least-recently-used entry was not evicted")
	}
}

func TestCachePersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	const cid = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
	c1, _ := newCache(dir)
	if err := c1.put(cid, validTestPNG()); err != nil {
		t.Fatalf("put: %v", err)
	}
	// A new cache over the same dir sees the entry until quota eviction is needed.
	c2, _ := newCache(dir)
	if !c2.has(cid) {
		t.Fatal("entry not visible to a second cache instance")
	}
}

func TestNewCacheRemovesStaleTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "nft-cache")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		t.Fatalf("mkdir cache: %v", err)
	}
	tmp := filepath.Join(cacheDir, ".tmp-stale")
	if err := os.WriteFile(tmp, []byte("partial"), 0o600); err != nil {
		t.Fatalf("write stale temp: %v", err)
	}
	if _, err := newCache(dir); err != nil {
		t.Fatalf("newCache: %v", err)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatalf("stale temp stat = %v, want ErrNotExist", err)
	}
}

func TestCacheRejectsOversizeImage(t *testing.T) {
	c, _ := newCache(t.TempDir())
	if err := c.put("QmTooBig", make([]byte, maxImageBytes+1)); err == nil {
		t.Fatal("put oversize image: want error, got nil")
	}
}

func TestCacheRejectsLargeDecodedImage(t *testing.T) {
	c, _ := newCache(t.TempDir())
	if err := c.put("QmDecodedTooBig", pngWithDimensions(5000, 5000)); !errors.Is(err, ErrUnsafeImage) {
		t.Fatalf("put decoded-oversize image = %v, want ErrUnsafeImage", err)
	}
	if c.has("QmDecodedTooBig") {
		t.Fatal("decoded-oversize image was cached")
	}
}

func TestCacheGetRemovesUnsafeLegacyEntry(t *testing.T) {
	c, _ := newCache(t.TempDir())
	const cid = "QmLegacyBomb"
	if err := os.WriteFile(c.path(cid), pngWithDimensions(5000, 5000), 0o600); err != nil {
		t.Fatalf("seed legacy entry: %v", err)
	}
	if _, err := c.get(cid); !errors.Is(err, ErrUnsafeImage) {
		t.Fatalf("get legacy bomb = %v, want ErrUnsafeImage", err)
	}
	if c.has(cid) {
		t.Fatal("unsafe legacy cache entry was not removed")
	}
}

func TestCacheEmptyCID(t *testing.T) {
	c, _ := newCache(t.TempDir())
	if c.has("") {
		t.Fatal("has(\"\") = true")
	}
	if err := c.put("", validTestPNG()); err == nil {
		t.Fatal("put with empty cid: want error")
	}
}
