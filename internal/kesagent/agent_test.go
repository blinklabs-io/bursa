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
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/internal/kesagent/securemem"
	"github.com/blinklabs-io/gouroboros/kes"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestCurrentKESPeriodMath(t *testing.T) {
	cold := newColdKey(t)
	// now = period 5 start + 5s (still in period 5), 10s per period.
	a := testAgent(t, ModeSign, cold, kes.CardanoKesDepth, atPeriod(5).Add(5*time.Second))
	if got := a.currentKESPeriod(); got != 5 {
		t.Fatalf("currentKESPeriod = %d, want 5", got)
	}
	// Before genesis -> 0.
	a.now = func() time.Time { return epoch.Add(-time.Hour) }
	if got := a.currentKESPeriod(); got != 0 {
		t.Fatalf("pre-genesis currentKESPeriod = %d, want 0", got)
	}
}

func TestGenStagedKey(t *testing.T) {
	cold := newColdKey(t)
	a := testAgent(t, ModeSign, cold, kes.CardanoKesDepth, atPeriod(0))
	vkey, err := a.GenStagedKey()
	if err != nil {
		t.Fatalf("GenStagedKey: %v", err)
	}
	if len(vkey) != kes.PublicKeySize {
		t.Fatalf("vkey len = %d, want %d", len(vkey), kes.PublicKeySize)
	}
	info := a.Info()
	if !bytes.Equal(info.StagedKESVKey, vkey) {
		t.Fatal("info staged vkey mismatch")
	}
	if info.HasActiveKey {
		t.Fatal("no active key expected before install")
	}
}

func TestInstallAndSign(t *testing.T) {
	cold := newColdKey(t)
	// Current period 5; opcert issued at period 3.
	a := testAgent(t, ModeSign, cold, kes.CardanoKesDepth, atPeriod(5))
	vkey, err := a.GenStagedKey()
	if err != nil {
		t.Fatalf("GenStagedKey: %v", err)
	}
	opcert := makeOpCert(t, vkey, 1, 3, cold)
	info, err := a.InstallKey(opcert)
	if err != nil {
		t.Fatalf("InstallKey: %v", err)
	}
	if !info.HasActiveKey {
		t.Fatal("expected active key after install")
	}
	if info.ActiveStart != 3 {
		t.Fatalf("ActiveStart = %d, want 3", info.ActiveStart)
	}
	if info.ActivePeriod != 5 {
		t.Fatalf("ActivePeriod = %d, want 5 (evolved to current)", info.ActivePeriod)
	}

	// Sign at the current period; verify with the internal evolution period.
	msg := []byte("block-header-body")
	sig, err := a.Sign(5, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	internal := uint64(5 - 3)
	if !kes.VerifySignedKES(vkey, internal, msg, sig) {
		t.Fatal("KES signature failed to verify at evolution period 2")
	}
	// It must NOT verify at the wrong evolution period.
	if kes.VerifySignedKES(vkey, internal+1, msg, sig) {
		t.Fatal("signature verified at wrong period")
	}
}

func TestSignPastPeriodRejected(t *testing.T) {
	cold := newColdKey(t)
	a := testAgent(t, ModeSign, cold, kes.CardanoKesDepth, atPeriod(5))
	vkey, _ := a.GenStagedKey()
	if _, err := a.InstallKey(makeOpCert(t, vkey, 1, 3, cold)); err != nil {
		t.Fatalf("InstallKey: %v", err)
	}
	// Active key is at absolute period 5; signing period 4 is in the past.
	if _, err := a.Sign(4, []byte("x")); !errors.Is(err, ErrPastPeriod) {
		t.Fatalf("Sign past period: want ErrPastPeriod, got %v", err)
	}
}

func TestNewRequiresDurableGuardPath(t *testing.T) {
	cold := newColdKey(t)
	a, err := New(Config{
		Mode:              ModeSign,
		Depth:             kes.CardanoKesDepth,
		SystemStart:       epoch,
		SlotLength:        time.Second,
		SlotsPerKESPeriod: 10,
		MaxKESEvolutions:  62,
		ColdVKey:          cold.pub,
		EvolveInterval:    time.Hour,
	}, nil, nil)
	if err == nil {
		a.Close()
		t.Fatal("New accepted an empty guard path")
	}
}

func TestAgentGuardFloorSurvivesRestart(t *testing.T) {
	cold := newColdKey(t)
	guardPath := filepath.Join(t.TempDir(), "guard.json")
	cfg := Config{
		Mode:              ModeSign,
		Depth:             kes.CardanoKesDepth,
		SystemStart:       epoch,
		SlotLength:        time.Second,
		SlotsPerKESPeriod: 10,
		MaxKESEvolutions:  62,
		ColdVKey:          cold.pub,
		EvolveInterval:    time.Hour,
		GuardPath:         guardPath,
		Version:           "test",
	}
	newAgent := func(period uint64) *Agent {
		a, err := New(cfg, nil, nil)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		a.now = func() time.Time { return atPeriod(period) }
		return a
	}

	a := newAgent(5)
	vkey, _ := a.GenStagedKey()
	if _, err := a.InstallKey(makeOpCert(t, vkey, 1, 3, cold)); err != nil {
		t.Fatalf("InstallKey: %v", err)
	}
	a.Close()

	restarted := newAgent(4)
	t.Cleanup(restarted.Close)
	info := restarted.Info()
	if !info.FloorInitialized || info.MonotonicFloor != 5 {
		t.Fatalf("restarted guard floor = (%d, %v), want (5, true)", info.MonotonicFloor, info.FloorInitialized)
	}
	restartedVKey, _ := restarted.GenStagedKey()
	if _, err := restarted.InstallKey(makeOpCert(t, restartedVKey, 2, 4, cold)); !errors.Is(err, ErrPeriodRollback) {
		t.Fatalf("InstallKey below restarted floor: want ErrPeriodRollback, got %v", err)
	}
}

func TestSignFuturePeriodRejectedWithoutStateChange(t *testing.T) {
	cold := newColdKey(t)
	a := testAgent(t, ModeSign, cold, kes.CardanoKesDepth, atPeriod(3))
	vkey, _ := a.GenStagedKey()
	if _, err := a.InstallKey(makeOpCert(t, vkey, 1, 3, cold)); err != nil {
		t.Fatalf("InstallKey: %v", err)
	}
	if _, err := a.Sign(7, []byte("future")); !errors.Is(err, ErrFuturePeriod) {
		t.Fatalf("Sign future period: want ErrFuturePeriod, got %v", err)
	}
	info := a.Info()
	if info.ActivePeriod != 3 {
		t.Fatalf("active period = %d after rejected request, want 3", info.ActivePeriod)
	}
	if info.MonotonicFloor != 3 {
		t.Fatalf("guard floor = %d after rejected request, want 3", info.MonotonicFloor)
	}
	if info.Exhausted {
		t.Fatal("rejected future request marked the active key exhausted")
	}
}

func TestSignFuturePeriodDoesNotPoisonRestart(t *testing.T) {
	cold := newColdKey(t)
	guardPath := filepath.Join(t.TempDir(), "guard.json")
	cfg := Config{
		Mode:              ModeSign,
		Depth:             kes.CardanoKesDepth,
		SystemStart:       epoch,
		SlotLength:        time.Second,
		SlotsPerKESPeriod: 10,
		MaxKESEvolutions:  62,
		ColdVKey:          cold.pub,
		EvolveInterval:    time.Hour,
		GuardPath:         guardPath,
		Version:           "test",
	}
	newAgent := func() *Agent {
		a, err := New(cfg, nil, nil)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		a.now = func() time.Time { return atPeriod(3) }
		return a
	}

	a := newAgent()
	vkey, _ := a.GenStagedKey()
	if _, err := a.InstallKey(makeOpCert(t, vkey, 1, 3, cold)); err != nil {
		t.Fatalf("InstallKey: %v", err)
	}
	if _, err := a.Sign(4, []byte("future")); !errors.Is(err, ErrFuturePeriod) {
		t.Fatalf("Sign future period: want ErrFuturePeriod, got %v", err)
	}
	a.Close()

	restarted := newAgent()
	t.Cleanup(restarted.Close)
	restartedVKey, _ := restarted.GenStagedKey()
	if _, err := restarted.InstallKey(makeOpCert(t, restartedVKey, 2, 3, cold)); err != nil {
		t.Fatalf("InstallKey after restart: %v", err)
	}
	if got := restarted.Info().MonotonicFloor; got != 3 {
		t.Fatalf("guard floor after restart = %d, want 3", got)
	}
}

func TestInstallOpCertMismatches(t *testing.T) {
	cold := newColdKey(t)
	other := newColdKey(t)
	a := testAgent(t, ModeServeKey, cold, kes.CardanoKesDepth, atPeriod(2))
	vkey, _ := a.GenStagedKey()

	// Opcert signed and stamped by a DIFFERENT cold key.
	if _, err := a.InstallKey(makeOpCert(t, vkey, 1, 2, other)); !errors.Is(err, ErrOpCertColdVK) {
		t.Fatalf("wrong cold vkey: want ErrOpCertColdVK, got %v", err)
	}

	// Opcert carrying the correct cold vkey but a bad signature (tamper).
	bad := makeOpCert(t, vkey, 1, 2, cold)
	// Flip a byte inside the signature region by rebuilding with a mismatched
	// KES vkey but correct cold vkey stamp: signature won't cover this vkey.
	otherVkey := make([]byte, len(vkey))
	copy(otherVkey, vkey)
	otherVkey[0] ^= 0xff
	badSig := tamperOpCertKESVkey(t, bad, otherVkey)
	if _, err := a.InstallKey(badSig); err == nil {
		t.Fatal("tampered opcert signature: expected error")
	}

	// Opcert for a different KES key (validly signed) -> ErrOpCertKESVK.
	wrongKey := make([]byte, len(vkey))
	copy(wrongKey, vkey)
	wrongKey[1] ^= 0xff
	if _, err := a.InstallKey(makeOpCert(t, wrongKey, 1, 2, cold)); !errors.Is(err, ErrOpCertKESVK) {
		t.Fatalf("wrong kes vkey: want ErrOpCertKESVK, got %v", err)
	}
}

func TestInstallNoStagedKey(t *testing.T) {
	cold := newColdKey(t)
	a := testAgent(t, ModeSign, cold, kes.CardanoKesDepth, atPeriod(2))
	if _, err := a.InstallKey(makeOpCert(t, make([]byte, 32), 1, 2, cold)); !errors.Is(err, ErrNoStagedKey) {
		t.Fatalf("install without staged: want ErrNoStagedKey, got %v", err)
	}
}

func TestInstallFuturePeriodRejected(t *testing.T) {
	cold := newColdKey(t)
	a := testAgent(t, ModeSign, cold, kes.CardanoKesDepth, atPeriod(2))
	vkey, _ := a.GenStagedKey()
	// Opcert period 9 while current period is 2 -> future.
	if _, err := a.InstallKey(makeOpCert(t, vkey, 1, 9, cold)); err == nil {
		t.Fatal("expected error for future opcert period")
	}
}

func TestDropKey(t *testing.T) {
	cold := newColdKey(t)
	a := testAgent(t, ModeSign, cold, kes.CardanoKesDepth, atPeriod(2))
	vkey, _ := a.GenStagedKey()
	if _, err := a.InstallKey(makeOpCert(t, vkey, 1, 2, cold)); err != nil {
		t.Fatalf("InstallKey: %v", err)
	}
	if err := a.DropKey("active"); err != nil {
		t.Fatalf("DropKey: %v", err)
	}
	if a.Info().HasActiveKey {
		t.Fatal("active key should be gone after drop")
	}
	if _, err := a.Sign(2, []byte("x")); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("sign after drop: want ErrNoActiveKey, got %v", err)
	}
}

func TestEvolveExhaustion(t *testing.T) {
	cold := newColdKey(t)
	// depth 2 -> MaxPeriod 4 (internal periods 0..3).
	a := testAgent(t, ModeServeKey, cold, 2, atPeriod(0))
	vkey, _ := a.GenStagedKey()
	if _, err := a.InstallKey(makeOpCert(t, vkey, 1, 0, cold)); err != nil {
		t.Fatalf("InstallKey: %v", err)
	}
	// Advance the clock well past the key's reach and tick the scheduler.
	a.now = func() time.Time { return atPeriod(10) }
	a.Tick()
	info := a.Info()
	if !info.Exhausted {
		t.Fatal("expected key to be exhausted")
	}
	// It reached its last servable period (start 0 + MaxPeriod-1 = 3).
	if info.ActivePeriod != 3 {
		t.Fatalf("ActivePeriod = %d, want 3 (last evolution)", info.ActivePeriod)
	}
}

// TestEvolveToLockedDiscardsKeyWhenStoreFails drives evolveToLocked's real
// discard-on-failure branch by making the locked-buffer store fail, rather than
// hand-replicating the close+nil+metrics sequence (which would assert only what
// the test itself just did). The branch matters because the buffer has already
// been zeroized by the time the store runs: leaving the key installed would let
// Sign produce a signature over zeroed key material for the period the key
// still claims.
func TestEvolveToLockedDiscardsKeyWhenStoreFails(t *testing.T) {
	cold := newColdKey(t)
	a := testAgent(t, ModeSign, cold, kes.CardanoKesDepth, atPeriod(1))
	metrics := NewMetrics()
	a.metrics = metrics
	vkey, _ := a.GenStagedKey()
	if _, err := a.InstallKey(makeOpCert(t, vkey, 1, 1, cold)); err != nil {
		t.Fatalf("InstallKey: %v", err)
	}
	metrics.setExhausted(true) // stale reading that the discard must clear

	orig := storeEvolvedKey
	storeEvolvedKey = func(*securemem.Buffer, []byte) error {
		return errors.New("simulated locked-buffer store failure")
	}
	t.Cleanup(func() { storeEvolvedKey = orig })

	// Ask for a later period so evolveToLocked actually iterates and reaches
	// the store step.
	a.mu.Lock()
	a.evolveToLocked(a.active.absPeriod() + 1)
	active := a.active
	a.mu.Unlock()

	if active != nil {
		t.Fatal("active key retained after a failed store; it holds a zeroized buffer")
	}
	if got := testutil.ToFloat64(metrics.exhausted); got != 0 {
		t.Fatalf("exhausted gauge = %v, want 0 (no active key, not an exhausted one)", got)
	}
	if _, err := a.Sign(2, []byte("msg")); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("Sign after key discard: want ErrNoActiveKey, got %v", err)
	}
}

func TestInstallRefusedByGuardFloor(t *testing.T) {
	cold := newColdKey(t)
	path := filepath.Join(t.TempDir(), "guard.json")
	// Pre-seed the durable guard with a high floor.
	g, err := NewPeriodGuard(path)
	if err != nil {
		t.Fatalf("NewPeriodGuard: %v", err)
	}
	if err := g.Authorize("prev", 100); err != nil {
		t.Fatalf("seed guard: %v", err)
	}

	cfg := Config{
		Mode:              ModeServeKey,
		Depth:             kes.CardanoKesDepth,
		SystemStart:       epoch,
		SlotLength:        time.Second,
		SlotsPerKESPeriod: 10,
		ColdVKey:          cold.pub,
		EvolveInterval:    time.Hour,
		GuardPath:         path,
	}
	a, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	a.now = func() time.Time { return atPeriod(5) }

	vkey, _ := a.GenStagedKey()
	// Install at period 5, but the floor is 100 -> rollback refused.
	if _, err := a.InstallKey(makeOpCert(t, vkey, 1, 5, cold)); !errors.Is(err, ErrPeriodRollback) {
		t.Fatalf("install below floor: want ErrPeriodRollback, got %v", err)
	}
	if a.Info().HasActiveKey {
		t.Fatal("no active key should remain after refused install")
	}
}

// TestInfoReportsActiveIssueNumberAndOpCert covers the two fields an operator
// needs to confirm a KES rotation took effect: the issue counter the network
// uses to accept the pool's blocks, and the opcert bytes themselves, which in
// sign mode are otherwise unobtainable from the agent.
func TestInfoReportsActiveIssueNumberAndOpCert(t *testing.T) {
	cold := newColdKey(t)
	a := testAgent(t, ModeSign, cold, kes.CardanoKesDepth, atPeriod(1))
	vkey, _ := a.GenStagedKey()
	const issueNumber = 7
	opcert := makeOpCert(t, vkey, issueNumber, 1, cold)
	info, err := a.InstallKey(opcert)
	if err != nil {
		t.Fatalf("InstallKey: %v", err)
	}
	if info.ActiveIssueNumber != issueNumber {
		t.Fatalf("ActiveIssueNumber = %d, want %d", info.ActiveIssueNumber, issueNumber)
	}
	if !bytes.Equal(info.ActiveOpCert, opcert) {
		t.Fatalf("ActiveOpCert = %x, want the installed opcert %x", info.ActiveOpCert, opcert)
	}
	// Info() must report the same thing as the InstallKey response.
	later := a.Info()
	if later.ActiveIssueNumber != issueNumber || !bytes.Equal(later.ActiveOpCert, opcert) {
		t.Fatalf("Info() = (issue %d, opcert %x), want (%d, %x)",
			later.ActiveIssueNumber, later.ActiveOpCert, issueNumber, opcert)
	}
	// With no active key the fields must not report a stale certificate.
	if err := a.DropKey("all"); err != nil {
		t.Fatalf("DropKey: %v", err)
	}
	dropped := a.Info()
	if dropped.ActiveIssueNumber != 0 || dropped.ActiveOpCert != nil {
		t.Fatalf("after DropKey: issue %d opcert %x, want zero/nil",
			dropped.ActiveIssueNumber, dropped.ActiveOpCert)
	}
}

// TestSubscribeRefusesKeyBelowGuardFloor covers the case where the active key
// and the guard floor have diverged: an install advances the floor, then fails
// and restores the previous (lower-period) key. Serving that key would let a
// producer sign below the monotonic floor, which is the rollback the guard
// exists to prevent — so neither a new subscriber nor a broadcast may receive
// it.
func TestSubscribeRefusesKeyBelowGuardFloor(t *testing.T) {
	cold := newColdKey(t)
	a := testAgent(t, ModeServeKey, cold, kes.CardanoKesDepth, atPeriod(1))
	vkey, _ := a.GenStagedKey()
	if _, err := a.InstallKey(makeOpCert(t, vkey, 1, 1, cold)); err != nil {
		t.Fatalf("InstallKey: %v", err)
	}

	// Sanity: with the floor at the active period, a subscriber gets the key.
	id, _, current := a.subscribe()
	if current == nil {
		t.Fatal("subscribe returned no key push while the key is at the floor")
	}
	securemem.Wipe(current.KESSignKey)
	a.unsubscribe(id)

	// Advance the floor past the active key, as a failed install would.
	a.mu.Lock()
	active := a.active.absPeriod()
	a.mu.Unlock()
	if err := a.guard.Authorize("newer-key", active+1); err != nil {
		t.Fatalf("advance guard floor: %v", err)
	}

	id, _, current = a.subscribe()
	defer a.unsubscribe(id)
	if current != nil {
		securemem.Wipe(current.KESSignKey)
		t.Fatalf("subscribe served a key at period %d below guard floor %d",
			active, active+1)
	}
}

// TestQueuedPushBelowFloorIsDroppedOnRollback covers the gap between the guard
// floor and an already-enqueued push: buildKeyPushLocked refuses to build a
// below-floor push, but one enqueued while the key and floor still agreed sits
// in the subscriber's channel, and a serve-key client reading it would be
// handed a key for a period the floor has since passed.
func TestQueuedPushBelowFloorIsDroppedOnRollback(t *testing.T) {
	cold := newColdKey(t)
	a := testAgent(t, ModeServeKey, cold, kes.CardanoKesDepth, atPeriod(1))
	vkey, _ := a.GenStagedKey()
	if _, err := a.InstallKey(makeOpCert(t, vkey, 1, 1, cold)); err != nil {
		t.Fatalf("InstallKey: %v", err)
	}

	// A subscriber with a push queued at the current (soon to be stale) period.
	id, ch, current := a.subscribe()
	defer a.unsubscribe(id)
	if current == nil {
		t.Fatal("subscribe returned no key push")
	}
	securemem.Wipe(current.KESSignKey)
	a.mu.Lock()
	a.broadcastLocked()
	active := a.active.absPeriod()
	a.mu.Unlock()
	if len(ch) != 1 {
		t.Fatalf("queued pushes = %d, want 1 before the floor advances", len(ch))
	}

	// Advance the floor past the queued push, as a committed-but-failed
	// install would, then run the drain.
	if err := a.guard.Authorize("newer-key", active+1); err != nil {
		t.Fatalf("advance floor: %v", err)
	}
	a.mu.Lock()
	a.dropQueuedPushesBelowFloorLocked()
	a.mu.Unlock()

	if len(ch) != 0 {
		kp := <-ch
		t.Fatalf("a push for period %d survived a floor advance to %d",
			kp.Period, active+1)
	}
}
