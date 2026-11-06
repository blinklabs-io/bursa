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
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func verifyChainOpCert(
	t *testing.T,
	res *OpCertResult,
	kes []byte,
	issue, period uint64,
) {
	t.Helper()
	if res == nil || res.IssueCounter != issue {
		t.Fatalf("result %+v, want issue counter %d", res, issue)
	}
	pub, _ := hex.DecodeString(res.ColdVKeyHex)
	sig, _ := hex.DecodeString(res.SignatureHex)
	if !ed25519.Verify(
		pub,
		lcommon.OpCertSignableBytes(kes, issue, period),
		sig,
	) {
		t.Fatalf("signature does not verify for issue %d", issue)
	}
}

// TestSignOpCertFromChain: the issue number is the on-chain counter + 1, and a
// pool that has not forged since gets the same number again.
func TestSignOpCertFromChain(t *testing.T) {
	k := newFakeKey(t)
	c, _ := newOpCertCoordinator(
		t,
		k,
		watermark.NewMemWatermark(),
		watermark.ModeEnforce,
	)
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

	if res, code, err := c.SignOpCertFromChain(ctx, kes, 3, 102, k.hash.String()); err == nil ||
		code != CodeConflict ||
		res != nil {
		t.Fatalf(
			"chain 3 after 4: want CodeConflict, got (res=%v, code=%s, err=%v)",
			res,
			code,
			err,
		)
	}

	res, code, err = c.SignOpCertFromChain(ctx, kes, 5, 103, k.hash.String())
	if err != nil {
		t.Fatalf("chain 5: %v (code=%s)", err, code)
	}
	verifyChainOpCert(t, res, kes, 6, 103)

	if _, code, err := c.SignOpCertFromChain(ctx, kes, math.MaxUint64, 104, k.hash.String()); err == nil ||
		code != CodeBadRequest {
		t.Fatalf(
			"chain MaxUint64: want CodeBadRequest, got (code=%s, err=%v)",
			code,
			err,
		)
	}
}

// TestSignOpCertFromChain_LegacyUnchanged: the chain floor and the legacy
// strictly increasing counter are separate records.
func TestSignOpCertFromChain_LegacyUnchanged(t *testing.T) {
	k := newFakeKey(t)
	c, _ := newOpCertCoordinator(
		t,
		k,
		watermark.NewMemWatermark(),
		watermark.ModeEnforce,
	)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	if _, code, err := c.SignOpCert(ctx, kes, 5, 100, k.hash.String()); err != nil {
		t.Fatalf("legacy 5: %v (code=%s)", err, code)
	}
	if _, code, err := c.SignOpCertFromChain(ctx, kes, 4, 100, k.hash.String()); err != nil {
		t.Fatalf("chain 4 after legacy 5: %v (code=%s)", err, code)
	}
	if _, code, err := c.SignOpCert(ctx, kes, 5, 101, k.hash.String()); err == nil ||
		code != CodeConflict {
		t.Fatalf(
			"legacy 5 repeat: want CodeConflict, got (code=%s, err=%v)",
			code,
			err,
		)
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
			res, _, err := c.SignOpCertFromChain(
				ctx,
				kes,
				9,
				100,
				k.hash.String(),
			)
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

// TestSignOpCertFromChain_AboveIssued: the ledger holds only counters this
// signer issued, so a chain counter above the last issued one is refused and
// cannot raise the floor past every counter the ledger would accept.
func TestSignOpCertFromChain_AboveIssued(t *testing.T) {
	k := newFakeKey(t)
	wm := watermark.NewMemWatermark()
	c, _ := newOpCertCoordinator(t, k, wm, watermark.ModeEnforce)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	// no record yet: the first chain counter is not bounded
	if _, code, err := c.SignOpCertFromChain(ctx, kes, 4, 100, k.hash.String()); err != nil {
		t.Fatalf("chain 4: %v (code=%s)", err, code)
	}
	// issued 5: chain 6 cannot have been forged
	if res, code, err := c.SignOpCertFromChain(ctx, kes, 6, 101, k.hash.String()); err == nil ||
		code != CodeConflict ||
		res != nil {
		t.Fatalf(
			"chain 6 after issuing 5: want CodeConflict, got (res=%v, code=%s, err=%v)",
			res,
			code,
			err,
		)
	}
	if v, _, _ := wm.CounterFor(ctx, k.hash, opcertChainFloorScope); v != 4 {
		t.Fatalf("floor = %d after a refused raise, want 4", v)
	}
	// the pool forged with 5
	res, code, err := c.SignOpCertFromChain(ctx, kes, 5, 102, k.hash.String())
	if err != nil {
		t.Fatalf("chain 5: %v (code=%s)", err, code)
	}
	verifyChainOpCert(t, res, kes, 6, 102)
	if _, code, err := c.SignOpCertFromChain(ctx, kes, 6, 103, k.hash.String()); err != nil {
		t.Fatalf("chain 6 after issuing 6: %v (code=%s)", err, code)
	}
	if _, code, err := c.SignOpCertFromChain(ctx, kes, 8, 104, k.hash.String()); err == nil ||
		code != CodeConflict {
		t.Fatalf(
			"chain 8 after issuing 7: want CodeConflict, got (code=%s, err=%v)",
			code,
			err,
		)
	}
}

// TestSignOpCertFromChain_AboveIssuedWarn: warn mode signs, but leaves the
// floor and the issued record unchanged, so the bogus counter cannot lock out
// later renewals.
func TestSignOpCertFromChain_AboveIssuedWarn(t *testing.T) {
	k := newFakeKey(t)
	wm := watermark.NewMemWatermark()
	c, _ := newOpCertCoordinator(t, k, wm, watermark.ModeWarn)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	if _, _, err := c.SignOpCertFromChain(ctx, kes, 4, 100, k.hash.String()); err != nil {
		t.Fatalf("chain 4: %v", err)
	}
	res, _, err := c.SignOpCertFromChain(ctx, kes, 9, 101, k.hash.String())
	if err != nil {
		t.Fatalf("chain 9 in warn mode: %v", err)
	}
	verifyChainOpCert(t, res, kes, 10, 101)
	if v, _, _ := wm.CounterFor(ctx, k.hash, opcertChainFloorScope); v != 4 {
		t.Fatalf("floor = %d, want 4", v)
	}
	if v, _, _ := wm.CounterFor(ctx, k.hash, opcertChainIssuedScope); v != 5 {
		t.Fatalf("issued = %d, want 5", v)
	}
	if _, _, err := c.SignOpCertFromChain(ctx, kes, 5, 102, k.hash.String()); err != nil {
		t.Fatalf("chain 5 after the warned request: %v", err)
	}
}

// TestSignOpCert_RaisesChainIssued: an opcert issued with an explicit
// issue_counter is on the chain once the pool forges with it, so it raises the
// bound on later chain_counter requests.
func TestSignOpCert_RaisesChainIssued(t *testing.T) {
	k := newFakeKey(t)
	wm := watermark.NewMemWatermark()
	c, _ := newOpCertCoordinator(t, k, wm, watermark.ModeEnforce)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	if _, code, err := c.SignOpCertFromChain(ctx, kes, 4, 100, k.hash.String()); err != nil {
		t.Fatalf("chain 4: %v (code=%s)", err, code)
	}
	if _, code, err := c.SignOpCert(ctx, kes, 7, 101, k.hash.String()); err != nil {
		t.Fatalf("issue 7: %v (code=%s)", err, code)
	}
	if v, _, _ := wm.CounterFor(ctx, k.hash, opcertChainIssuedScope); v != 7 {
		t.Fatalf("issued = %d, want 7", v)
	}
	res, code, err := c.SignOpCertFromChain(ctx, kes, 7, 102, k.hash.String())
	if err != nil {
		t.Fatalf("chain 7 after issuing 7: %v (code=%s)", err, code)
	}
	verifyChainOpCert(t, res, kes, 8, 102)
}

// TestSignOpCertFromChain_StaleWarnNoIssued: warn mode signs a chain counter
// below the floor, but does not record its issue number, which would set the
// bound below the floor and refuse every later chain counter.
func TestSignOpCertFromChain_StaleWarnNoIssued(t *testing.T) {
	k := newFakeKey(t)
	wm := watermark.NewMemWatermark()
	c, _ := newOpCertCoordinator(t, k, wm, watermark.ModeWarn)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	// a floor recorded before the issued record existed
	if err := wm.CheckAndRaiseFloor(ctx, k.hash, opcertChainFloorScope, 9); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.SignOpCertFromChain(ctx, kes, 3, 100, k.hash.String()); err != nil {
		t.Fatalf("chain 3 in warn mode: %v", err)
	}
	if v, ok, _ := wm.CounterFor(ctx, k.hash, opcertChainIssuedScope); ok {
		t.Fatalf("issued = %d after a stale request, want no record", v)
	}
}

// An issue_counter request is bounded by the issue numbers chain_counter
// requests produced for the key, so switching request forms cannot reissue or
// go back below a counter already issued.
func TestSignOpCert_AtOrBelowChainIssued(t *testing.T) {
	k := newFakeKey(t)
	wm := watermark.NewMemWatermark()
	c, _ := newOpCertCoordinator(t, k, wm, watermark.ModeEnforce)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	if _, code, err := c.SignOpCertFromChain(ctx, kes, 8, 100, k.hash.String()); err != nil {
		t.Fatalf("chain 8: %v (code=%s)", err, code)
	}
	for _, n := range []uint64{9, 5} {
		if _, code, err := c.SignOpCert(ctx, kes, n, 101, k.hash.String()); code != CodeConflict {
			t.Fatalf(
				"issue %d after issuing 9: code=%s err=%v, want %s",
				n,
				code,
				err,
				CodeConflict,
			)
		}
	}
	res, code, err := c.SignOpCert(ctx, kes, 10, 101, k.hash.String())
	if err != nil {
		t.Fatalf("issue 10: %v (code=%s)", err, code)
	}
	verifyChainOpCert(t, res, kes, 10, 101)
}

// A chain_counter request is bounded below by the issue numbers issue_counter
// requests produced: chain + 1 may repeat the last issued counter, never go
// under it.
func TestSignOpCertFromChain_BelowIssued(t *testing.T) {
	k := newFakeKey(t)
	wm := watermark.NewMemWatermark()
	c, _ := newOpCertCoordinator(t, k, wm, watermark.ModeEnforce)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	if _, code, err := c.SignOpCert(ctx, kes, 10, 100, k.hash.String()); err != nil {
		t.Fatalf("issue 10: %v (code=%s)", err, code)
	}
	if _, code, err := c.SignOpCertFromChain(ctx, kes, 8, 101, k.hash.String()); code != CodeConflict {
		t.Fatalf(
			"chain 8 after issuing 10: code=%s err=%v, want %s",
			code,
			err,
			CodeConflict,
		)
	}
	if v, ok, _ := wm.CounterFor(ctx, k.hash, opcertChainFloorScope); ok {
		t.Fatalf("floor = %d after a refused request, want none", v)
	}
	res, code, err := c.SignOpCertFromChain(ctx, kes, 9, 102, k.hash.String())
	if err != nil {
		t.Fatalf("chain 9 after issuing 10: %v (code=%s)", err, code)
	}
	verifyChainOpCert(t, res, kes, 10, 102)
}

// Warn mode signs a request below the issued record, counts the conflict and
// does not record it.
func TestSignOpCert_BelowIssuedWarn(t *testing.T) {
	k := newFakeKey(t)
	wm := watermark.NewMemWatermark()
	c, m := newOpCertCoordinator(t, k, wm, watermark.ModeWarn)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	if _, code, err := c.SignOpCertFromChain(ctx, kes, 8, 100, k.hash.String()); err != nil {
		t.Fatalf("chain 8: %v (code=%s)", err, code)
	}
	if _, code, err := c.SignOpCert(ctx, kes, 5, 101, k.hash.String()); err != nil {
		t.Fatalf("issue 5 in warn mode: %v (code=%s)", err, code)
	}
	if got := testutil.ToFloat64(m.watermarkConflicts); got != 1 {
		t.Fatalf("watermark conflicts = %v, want 1", got)
	}
	if v, _, _ := wm.CounterFor(ctx, k.hash, opcertChainIssuedScope); v != 9 {
		t.Fatalf("issued = %d, want 9", v)
	}
	if v, ok, _ := wm.CounterFor(ctx, k.hash, opcertCounterScope); ok {
		t.Fatalf(
			"issue counter record = %d after a warned request, want none",
			v,
		)
	}
}

// newPausingOpCert returns a coordinator whose first issued-record lookup
// blocks until release is closed, so a second request can complete between
// the paused request's pre-sign checks and its commit.
func newPausingOpCert(
	t *testing.T,
	mode watermark.Mode,
) (*Coordinator, *pausingCounterWatermark, *fakeKey) {
	t.Helper()
	k := newFakeKey(t)
	pw := &pausingCounterWatermark{
		Watermark: watermark.NewMemWatermark(),
		counter:   watermark.NewMemWatermark(),
		paused:    make(chan struct{}),
		release:   make(chan struct{}),
	}
	c, _ := newOpCertCoordinator(t, k, pw, mode)
	return c, pw, k
}

// An issue_counter request that passed its pre-sign checks is refused at
// commit when a chain_counter request issued the same counter meanwhile.
func TestSignOpCert_ConcurrentChainIssued(t *testing.T) {
	c, pw, k := newPausingOpCert(t, watermark.ModeEnforce)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	var (
		wg   sync.WaitGroup
		res  *OpCertResult
		code ErrorCode
		err  error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		res, code, err = c.SignOpCert(ctx, kes, 9, 100, k.hash.String())
	}()
	<-pw.paused
	if _, ccode, err := c.SignOpCertFromChain(ctx, kes, 8, 101, k.hash.String()); err != nil {
		t.Fatalf("chain 8: %v (code=%s)", err, ccode)
	}
	close(pw.release)
	wg.Wait()
	if code != CodeConflict || err == nil || res != nil {
		t.Fatalf(
			"issue 9 racing chain 8: res=%v code=%s err=%v, want no signature and %s",
			res,
			code,
			err,
			CodeConflict,
		)
	}
}

// A chain_counter request that passed its pre-sign checks is refused at
// commit when an issue_counter request issued a higher counter meanwhile.
func TestSignOpCertFromChain_ConcurrentIssueAbove(t *testing.T) {
	c, pw, k := newPausingOpCert(t, watermark.ModeEnforce)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	var (
		wg   sync.WaitGroup
		res  *OpCertResult
		code ErrorCode
		err  error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		res, code, err = c.SignOpCertFromChain(
			ctx,
			kes,
			8,
			100,
			k.hash.String(),
		)
	}()
	<-pw.paused
	if _, icode, err := c.SignOpCert(ctx, kes, 10, 101, k.hash.String()); err != nil {
		t.Fatalf("issue 10: %v (code=%s)", err, icode)
	}
	close(pw.release)
	wg.Wait()
	if code != CodeConflict || err == nil || res != nil {
		t.Fatalf(
			"chain 8 racing issue 10: res=%v code=%s err=%v, want no signature and %s",
			res,
			code,
			err,
			CodeConflict,
		)
	}
}

// On a key's first opcert, a chain_counter request whose pre-sign check found
// no issued record is refused at commit when an issue_counter request
// recorded a counter below its chain counter meanwhile.
func TestSignOpCertFromChain_ConcurrentFirstIssueBelow(t *testing.T) {
	c, pw, k := newPausingOpCert(t, watermark.ModeEnforce)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	var (
		wg   sync.WaitGroup
		res  *OpCertResult
		code ErrorCode
		err  error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		res, code, err = c.SignOpCertFromChain(
			ctx,
			kes,
			20,
			100,
			k.hash.String(),
		)
	}()
	<-pw.paused
	if _, icode, ierr := c.SignOpCert(ctx, kes, 5, 101, k.hash.String()); ierr != nil {
		t.Fatalf("issue 5: %v (code=%s)", ierr, icode)
	}
	close(pw.release)
	wg.Wait()
	if code != CodeConflict || err == nil || res != nil {
		t.Fatalf(
			"chain 20 racing issue 5: res=%v code=%s err=%v, want no signature and %s",
			res,
			code,
			err,
			CodeConflict,
		)
	}
}

// Warn mode leaves the request form's own record alone after an issued-record
// conflict, as it does for a chain counter above the record.
func TestSignOpCertFromChain_BelowIssuedWarnKeepsFloor(t *testing.T) {
	k := newFakeKey(t)
	wm := watermark.NewMemWatermark()
	c, _ := newOpCertCoordinator(t, k, wm, watermark.ModeWarn)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	if _, code, err := c.SignOpCert(ctx, kes, 10, 100, k.hash.String()); err != nil {
		t.Fatalf("issue 10: %v (code=%s)", err, code)
	}
	if _, code, err := c.SignOpCertFromChain(ctx, kes, 5, 101, k.hash.String()); err != nil {
		t.Fatalf("chain 5 in warn mode: %v (code=%s)", err, code)
	}
	if v, ok, _ := wm.CounterFor(ctx, k.hash, opcertChainFloorScope); ok {
		t.Fatalf("floor = %d after a warned request, want none", v)
	}
}

// raceOpCert runs first against a pausing store, lets second complete while
// first is paused after its pre-sign checks, then releases first and returns
// its outcome.
func raceOpCert(
	t *testing.T,
	pw *pausingCounterWatermark,
	first, second func() (*OpCertResult, ErrorCode, error),
) (*OpCertResult, ErrorCode, error) {
	t.Helper()
	var (
		wg   sync.WaitGroup
		res  *OpCertResult
		code ErrorCode
		err  error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		res, code, err = first()
	}()
	<-pw.paused
	if _, scode, serr := second(); serr != nil {
		close(pw.release)
		wg.Wait()
		t.Fatalf("second request: %v (code=%s)", serr, scode)
	}
	close(pw.release)
	wg.Wait()
	return res, code, err
}

func requireNoRecord(
	t *testing.T,
	pw *pausingCounterWatermark,
	k *fakeKey,
	scope string,
) {
	t.Helper()
	if v, ok, err := pw.counter.CounterFor(context.Background(), k.hash, scope); err != nil ||
		ok {
		t.Fatalf(
			"%s record = (%d, %v, %v) after a refused request, want none",
			scope,
			v,
			ok,
			err,
		)
	}
}

// An issue_counter request refused at the issued record must not leave its own
// record behind.
func TestSignOpCert_ConcurrentChainIssuedLeavesNoIssueRecord(t *testing.T) {
	t.Parallel()
	c, pw, k := newPausingOpCert(t, watermark.ModeEnforce)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	res, code, err := raceOpCert(
		t,
		pw,
		func() (*OpCertResult, ErrorCode, error) { return c.SignOpCert(ctx, kes, 9, 100, k.hash.String()) },
		func() (*OpCertResult, ErrorCode, error) {
			return c.SignOpCertFromChain(ctx, kes, 8, 101, k.hash.String())
		},
	)
	if code != CodeConflict || err == nil || res != nil {
		t.Fatalf(
			"issue 9 racing chain 8: res=%v code=%s err=%v, want no signature and %s",
			res,
			code,
			err,
			CodeConflict,
		)
	}
	requireNoRecord(t, pw, k, opcertCounterScope)
	if res, code, err := c.SignOpCert(ctx, kes, 10, 102, k.hash.String()); err != nil ||
		res == nil {
		t.Fatalf(
			"issue 10 after the refused request: res=%v code=%s err=%v",
			res,
			code,
			err,
		)
	}
}

// A chain_counter request refused at the issued record must not leave its
// floor behind: a floor above the issued record locks out every renewal.
func TestSignOpCertFromChain_ConcurrentFirstIssueBelowLeavesNoFloor(
	t *testing.T,
) {
	t.Parallel()
	c, pw, k := newPausingOpCert(t, watermark.ModeEnforce)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	res, code, err := raceOpCert(
		t,
		pw,
		func() (*OpCertResult, ErrorCode, error) {
			return c.SignOpCertFromChain(ctx, kes, 20, 100, k.hash.String())
		},
		func() (*OpCertResult, ErrorCode, error) { return c.SignOpCert(ctx, kes, 5, 101, k.hash.String()) },
	)
	if code != CodeConflict || err == nil || res != nil {
		t.Fatalf(
			"chain 20 racing issue 5: res=%v code=%s err=%v, want no signature and %s",
			res,
			code,
			err,
			CodeConflict,
		)
	}
	requireNoRecord(t, pw, k, opcertChainFloorScope)
	if res, code, err := c.SignOpCertFromChain(ctx, kes, 5, 102, k.hash.String()); err != nil ||
		res == nil {
		t.Fatalf(
			"chain 5 after the refused request: res=%v code=%s err=%v",
			res,
			code,
			err,
		)
	}
}

func TestSignOpCertFromChain_ConcurrentIssueAboveLeavesNoFloor(t *testing.T) {
	t.Parallel()
	c, pw, k := newPausingOpCert(t, watermark.ModeEnforce)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	res, code, err := raceOpCert(
		t,
		pw,
		func() (*OpCertResult, ErrorCode, error) {
			return c.SignOpCertFromChain(ctx, kes, 8, 100, k.hash.String())
		},
		func() (*OpCertResult, ErrorCode, error) { return c.SignOpCert(ctx, kes, 10, 101, k.hash.String()) },
	)
	if code != CodeConflict || err == nil || res != nil {
		t.Fatalf(
			"chain 8 racing issue 10: res=%v code=%s err=%v, want no signature and %s",
			res,
			code,
			err,
			CodeConflict,
		)
	}
	requireNoRecord(t, pw, k, opcertChainFloorScope)
}

// Warn mode returns the signature of a chain_counter request refused at the
// issued record at commit, but leaves its floor unwritten, as it does when the
// pre-sign check finds the conflict.
func TestSignOpCertFromChain_ConcurrentFirstIssueBelowWarnLeavesNoFloor(
	t *testing.T,
) {
	t.Parallel()
	c, pw, k := newPausingOpCert(t, watermark.ModeWarn)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	res, code, err := raceOpCert(
		t,
		pw,
		func() (*OpCertResult, ErrorCode, error) {
			return c.SignOpCertFromChain(ctx, kes, 20, 100, k.hash.String())
		},
		func() (*OpCertResult, ErrorCode, error) { return c.SignOpCert(ctx, kes, 5, 101, k.hash.String()) },
	)
	if err != nil || res == nil {
		t.Fatalf(
			"chain 20 racing issue 5 in warn mode: res=%v code=%s err=%v, want a signature",
			res,
			code,
			err,
		)
	}
	requireNoRecord(t, pw, k, opcertChainFloorScope)
	if res, code, err := c.SignOpCertFromChain(ctx, kes, 5, 102, k.hash.String()); err != nil ||
		res == nil {
		t.Fatalf(
			"chain 5 after the warned request: res=%v code=%s err=%v",
			res,
			code,
			err,
		)
	}
}
