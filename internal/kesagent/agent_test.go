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

	"github.com/blinklabs-io/gouroboros/kes"
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

func TestSignForwardEvolves(t *testing.T) {
	cold := newColdKey(t)
	a := testAgent(t, ModeSign, cold, kes.CardanoKesDepth, atPeriod(3))
	vkey, _ := a.GenStagedKey()
	if _, err := a.InstallKey(makeOpCert(t, vkey, 1, 3, cold)); err != nil {
		t.Fatalf("InstallKey: %v", err)
	}
	// Sign at a future period: the key must evolve forward to reach it.
	msg := []byte("future")
	sig, err := a.Sign(7, msg)
	if err != nil {
		t.Fatalf("Sign future: %v", err)
	}
	if !kes.VerifySignedKES(vkey, 7-3, msg, sig) {
		t.Fatal("forward-evolved signature failed to verify")
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
