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
	"crypto/ed25519"
	"encoding/hex"
	"math"
	"sync"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer/watermark"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

func verifyChainOpCert(t *testing.T, res *OpCertResult, kes []byte, issue, period uint64) {
	t.Helper()
	if res == nil || res.IssueCounter != issue {
		t.Fatalf("result %+v, want issue counter %d", res, issue)
	}
	pub, _ := hex.DecodeString(res.ColdVKeyHex)
	sig, _ := hex.DecodeString(res.SignatureHex)
	if !ed25519.Verify(pub, lcommon.OpCertSignableBytes(kes, issue, period), sig) {
		t.Fatalf("signature does not verify for issue %d", issue)
	}
}

// TestSignOpCertFromChain: the issue number is the on-chain counter + 1, and a
// pool that has not forged since gets the same number again.
func TestSignOpCertFromChain(t *testing.T) {
	k := newFakeKey(t)
	c, _ := newOpCertCoordinator(t, k, watermark.NewMemWatermark(), watermark.ModeEnforce)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	res, code, err := c.SignOpCertFromChain(ctx, kes, 4, 100, k.hash.String())
	if err != nil {
		t.Fatalf("chain 4: %v (code=%s)", err, code)
	}
	verifyChainOpCert(t, res, kes, 5, 100)

	// no block forged with issue 5 yet: chain still reports 4
	res, code, err = c.SignOpCertFromChain(ctx, kes, 4, 101, k.hash.String())
	if err != nil {
		t.Fatalf("chain 4 again: %v (code=%s)", err, code)
	}
	verifyChainOpCert(t, res, kes, 5, 101)

	if res, code, err := c.SignOpCertFromChain(ctx, kes, 3, 102, k.hash.String()); err == nil || code != CodeConflict || res != nil {
		t.Fatalf("chain 3 after 4: want CodeConflict, got (res=%v, code=%s, err=%v)", res, code, err)
	}

	res, code, err = c.SignOpCertFromChain(ctx, kes, 5, 103, k.hash.String())
	if err != nil {
		t.Fatalf("chain 5: %v (code=%s)", err, code)
	}
	verifyChainOpCert(t, res, kes, 6, 103)

	if _, code, err := c.SignOpCertFromChain(ctx, kes, math.MaxUint64, 104, k.hash.String()); err == nil || code != CodeBadRequest {
		t.Fatalf("chain MaxUint64: want CodeBadRequest, got (code=%s, err=%v)", code, err)
	}
}

// TestSignOpCertFromChain_LegacyUnchanged: the chain floor and the legacy
// strictly increasing counter are separate records.
func TestSignOpCertFromChain_LegacyUnchanged(t *testing.T) {
	k := newFakeKey(t)
	c, _ := newOpCertCoordinator(t, k, watermark.NewMemWatermark(), watermark.ModeEnforce)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	if _, code, err := c.SignOpCert(ctx, kes, 5, 100, k.hash.String()); err != nil {
		t.Fatalf("legacy 5: %v (code=%s)", err, code)
	}
	if _, code, err := c.SignOpCertFromChain(ctx, kes, 4, 100, k.hash.String()); err != nil {
		t.Fatalf("chain 4 after legacy 5: %v (code=%s)", err, code)
	}
	if _, code, err := c.SignOpCert(ctx, kes, 5, 101, k.hash.String()); err == nil || code != CodeConflict {
		t.Fatalf("legacy 5 repeat: want CodeConflict, got (code=%s, err=%v)", code, err)
	}
	res, _, err := c.SignOpCert(ctx, kes, 6, 102, k.hash.String())
	if err != nil || res.IssueCounter != 6 {
		t.Fatalf("legacy 6: %+v, %v", res, err)
	}
}

// TestSignOpCertFromChain_Concurrent: concurrent requests with the same chain
// counter may all succeed with the same issue number; the floor never drops.
func TestSignOpCertFromChain_Concurrent(t *testing.T) {
	k := newFakeKey(t)
	wm := watermark.NewMemWatermark()
	c, _ := newOpCertCoordinator(t, k, wm, watermark.ModeEnforce)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, _, err := c.SignOpCertFromChain(ctx, kes, 9, 100, k.hash.String())
			if err == nil && res.IssueCounter != 10 {
				t.Errorf("issue %d, want 10", res.IssueCounter)
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent same chain counter refused: %v", err)
		}
	}
	if v, _, _ := wm.CounterFor(ctx, k.hash, opcertChainFloorScope); v != 9 {
		t.Fatalf("floor = %d, want 9", v)
	}
}
