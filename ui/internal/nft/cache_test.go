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
	"os"
	"testing"
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

	data := []byte("\x89PNG\r\n\x1a\nblob")
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

func TestCachePersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	const cid = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
	c1, _ := newCache(dir)
	if err := c1.put(cid, []byte("persisted")); err != nil {
		t.Fatalf("put: %v", err)
	}
	// A new cache over the same dir sees the entry (content-addressed, forever).
	c2, _ := newCache(dir)
	if !c2.has(cid) {
		t.Fatal("entry not visible to a second cache instance")
	}
}

func TestCacheRejectsOversizeImage(t *testing.T) {
	c, _ := newCache(t.TempDir())
	if err := c.put("QmTooBig", make([]byte, maxImageBytes+1)); err == nil {
		t.Fatal("put oversize image: want error, got nil")
	}
}

func TestCacheEmptyCID(t *testing.T) {
	c, _ := newCache(t.TempDir())
	if c.has("") {
		t.Fatal("has(\"\") = true")
	}
	if err := c.put("", []byte("x")); err == nil {
		t.Fatal("put with empty cid: want error")
	}
}
