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

//go:build nftmedia

package nft

import (
	"context"
	"fmt"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/ipfs/go-datastore"
	query "github.com/ipfs/go-datastore/query"
)

// lruDatastore is an in-memory, byte-bounded datastore for transient IPFS
// blocks. The mutex keeps byte accounting and LRU mutations atomic even when
// the datastore is used without an outer datastore mutex.
type lruDatastore struct {
	mu       sync.Mutex
	cache    *lru.Cache[datastore.Key, []byte]
	maxBytes int
	maxEntry int
	bytes    int
}

const blockCacheMaxEntries = 1024

func newLRUDatastore(maxBytes, maxEntry int) (*lruDatastore, error) {
	if maxEntry <= 0 || maxEntry > maxBytes {
		return nil, fmt.Errorf("nft: invalid block cache entry limit %d for byte limit %d", maxEntry, maxBytes)
	}
	// Retain a modest count ceiling as defense against many zero/tiny blocks;
	// the byte limit remains the primary bound for ordinary block data.
	d := &lruDatastore{maxBytes: maxBytes, maxEntry: maxEntry}
	cache, err := lru.NewWithEvict[datastore.Key, []byte](
		blockCacheMaxEntries,
		func(_ datastore.Key, value []byte) { d.bytes -= len(value) },
	)
	if err != nil {
		return nil, err
	}
	d.cache = cache
	return d, nil
}

func (d *lruDatastore) Put(_ context.Context, key datastore.Key, value []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(value) > d.maxEntry {
		return fmt.Errorf("nft: IPFS block is %d bytes, per-block limit is %d", len(value), d.maxEntry)
	}
	if d.cache.Contains(key) {
		d.cache.Remove(key)
	}
	for d.bytes+len(value) > d.maxBytes {
		_, _, ok := d.cache.RemoveOldest()
		if !ok {
			break
		}
	}
	d.cache.Add(key, value)
	d.bytes += len(value)
	return nil
}

func (d *lruDatastore) Get(_ context.Context, key datastore.Key) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	value, ok := d.cache.Get(key)
	if !ok {
		return nil, datastore.ErrNotFound
	}
	return value, nil
}

func (d *lruDatastore) Has(_ context.Context, key datastore.Key) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cache.Contains(key), nil
}

func (d *lruDatastore) GetSize(_ context.Context, key datastore.Key) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	value, ok := d.cache.Peek(key)
	if !ok {
		return -1, datastore.ErrNotFound
	}
	return len(value), nil
}

func (d *lruDatastore) Delete(_ context.Context, key datastore.Key) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cache.Contains(key) {
		d.cache.Remove(key)
	}
	return nil
}

func (d *lruDatastore) Query(_ context.Context, q query.Query) (query.Results, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	entries := make([]query.Entry, 0, d.cache.Len())
	for _, key := range d.cache.Keys() {
		value, ok := d.cache.Peek(key)
		if !ok {
			continue
		}
		entry := query.Entry{Key: key.String(), Size: len(value)}
		if !q.KeysOnly {
			entry.Value = value
		}
		entries = append(entries, entry)
	}
	results := query.ResultsWithEntries(q, entries)
	return query.NaiveQueryApply(q, results), nil
}

func (d *lruDatastore) Sync(context.Context, datastore.Key) error { return nil }

func (d *lruDatastore) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cache.Purge()
	return nil
}

func (d *lruDatastore) Batch(context.Context) (datastore.Batch, error) {
	return datastore.NewBasicBatch(d), nil
}
