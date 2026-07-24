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
	"errors"
	"testing"

	"github.com/ipfs/go-datastore"
)

func TestLRUDatastoreEvictsLeastRecentlyUsed(t *testing.T) {
	ds, err := newLRUDatastore(3, 3)
	if err != nil {
		t.Fatalf("newLRUDatastore: %v", err)
	}
	ctx := context.Background()
	one, two, three := datastore.NewKey("one"), datastore.NewKey("two"), datastore.NewKey("three")
	if err := ds.Put(ctx, one, []byte("11")); err != nil {
		t.Fatal(err)
	}
	if err := ds.Put(ctx, two, []byte("2")); err != nil {
		t.Fatal(err)
	}
	if _, err := ds.Get(ctx, one); err != nil {
		t.Fatal(err)
	}
	if err := ds.Put(ctx, three, []byte("33")); err != nil {
		t.Fatal(err)
	}
	if _, err := ds.Get(ctx, two); !errors.Is(err, datastore.ErrNotFound) {
		t.Fatalf("evicted key error = %v, want ErrNotFound", err)
	}
}

func TestNewLRUDatastoreRejectsEntryLimitAboveByteLimit(t *testing.T) {
	if _, err := newLRUDatastore(3, 4); err == nil {
		t.Fatal("newLRUDatastore accepted per-entry limit above aggregate byte limit")
	}
}

func TestLRUDatastoreRejectsEntryLargerThanPerBlockLimit(t *testing.T) {
	ds, err := newLRUDatastore(8, 3)
	if err != nil {
		t.Fatalf("newLRUDatastore: %v", err)
	}
	if err := ds.Put(context.Background(), datastore.NewKey("large"), []byte("1234")); err == nil {
		t.Fatal("Put above per-block limit succeeded, want error")
	}
}

func TestLRUDatastoreReplacementUpdatesByteAccounting(t *testing.T) {
	ds, err := newLRUDatastore(4, 4)
	if err != nil {
		t.Fatalf("newLRUDatastore: %v", err)
	}
	ctx := context.Background()
	one, two := datastore.NewKey("one"), datastore.NewKey("two")
	if err := ds.Put(ctx, one, []byte("123")); err != nil {
		t.Fatal(err)
	}
	if err := ds.Put(ctx, one, []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := ds.Put(ctx, two, []byte("234")); err != nil {
		t.Fatal(err)
	}
	if _, err := ds.Get(ctx, one); err != nil {
		t.Fatalf("replacement used stale byte accounting: %v", err)
	}
}
