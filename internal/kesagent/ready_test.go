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

package kesagent

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blinklabs-io/gouroboros/kes"
)

// flakyKeyStore fails Installed while fail is set.
type flakyKeyStore struct {
	*memKeyStore
	fail atomic.Bool
}

var errStoreDown = errors.New("key store unreachable")

func (f *flakyKeyStore) Installed(
	ctx context.Context,
	pool, network string,
) (SealedKey, bool, error) {
	if f.fail.Load() {
		return SealedKey{}, false, errStoreDown
	}
	return f.memKeyStore.Installed(ctx, pool, network)
}

// TestReadyFollowsKeyLoad: an agent with no installed record is ready, a
// sync that cannot read the record makes it unready, and the next good sync
// makes it ready again.
func TestReadyFollowsKeyLoad(t *testing.T) {
	t.Parallel()
	mem, _ := memReplicas()
	flaky := &flakyKeyStore{memKeyStore: mem.keys.(*memKeyStore)}
	r := replica{guard: mem.guard, keys: flaky}
	cold := newColdKey(t)
	sealer := testSealer(t)
	a := sharedKeyAgent(t, cold, r, sealer)
	b := sharedKeyAgent(t, cold, r, sealer)

	syncKeys(t, "B with no installed record", b)
	if err := b.Ready(); err != nil {
		t.Fatalf("B Ready with no installed record: %v", err)
	}

	vkey, err := a.GenStagedKey()
	if err != nil {
		t.Fatalf("GenStagedKey: %v", err)
	}
	opcert := makeOpCert(t, vkey, 7, 3, cold)
	if _, err := a.InstallKey(opcert); err != nil {
		t.Fatalf("InstallKey: %v", err)
	}

	flaky.fail.Store(true)
	if err := b.SyncKeys(context.Background()); !errors.Is(err, errStoreDown) {
		t.Fatalf("B SyncKeys with the store down: want errStoreDown, got %v", err)
	}
	if err := b.Ready(); !errors.Is(err, errStoreDown) {
		t.Fatalf("B Ready after a failed sync: want errStoreDown, got %v", err)
	}

	flaky.fail.Store(false)
	syncKeys(t, "B after the store recovers", b)
	if err := b.Ready(); err != nil {
		t.Fatalf("B Ready after a good sync: %v", err)
	}
	signAndVerify(t, "B", b, sharedSpec(t, cold, vkey, opcert, 7, 52))
}

// TestReadyDoesNotWaitOnSync: Ready answers while a sync holds the profile
// lock across a slow key store call.
func TestReadyDoesNotWaitOnSync(t *testing.T) {
	t.Parallel()
	r, _ := memReplicas()
	a := sharedKeyAgent(t, newColdKey(t), r, testSealer(t))
	p := a.profiles[0]
	p.mu.Lock()
	defer p.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- a.Ready() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Ready: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Ready blocked on the profile lock")
	}
}

// TestReadyWithoutKeyStore: an agent without a shared key store is always
// ready.
func TestReadyWithoutKeyStore(t *testing.T) {
	t.Parallel()
	a := testAgent(t, ModeSign, newColdKey(t), kes.CardanoKesDepth, atPeriod(5))
	if err := a.Ready(); err != nil {
		t.Fatalf("Ready without a key store: %v", err)
	}
}
