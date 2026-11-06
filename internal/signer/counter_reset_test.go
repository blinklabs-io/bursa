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
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
)

func u64p(v uint64) *uint64 { return &v }

func newSqliteForReset(t *testing.T) (*watermark.SqliteWatermark, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wm.db")
	wm, err := watermark.NewSqliteWatermark(path)
	if err != nil {
		t.Fatalf("NewSqliteWatermark: %v", err)
	}
	t.Cleanup(func() { _ = wm.Close() })
	return wm, path
}

// TestResetOpCertChain_FailbackRefusedThenIssues drives the coordinator: a
// chain counter above the issued record is refused, and after the reset the
// next opcert issues chain + 1.
func TestResetOpCertChain_FailbackRefusedThenIssues(t *testing.T) {
	t.Parallel()
	wm, _ := newSqliteForReset(t)
	k := newFakeKey(t)
	c, _ := newOpCertCoordinator(t, k, wm, watermark.ModeEnforce)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	// This signer issued 9; another signer issued 10 and the chain is at 10.
	if _, code, err := c.SignOpCert(ctx, kes, 9, 100, k.hash.String()); err != nil {
		t.Fatalf("issue 9: %v (%s)", err, code)
	}
	res, code, err := c.SignOpCertFromChain(ctx, kes, 10, 101, k.hash.String())
	if err == nil || code != CodeConflict || res != nil {
		t.Fatalf(
			"chain 10 after issued 9: want CodeConflict, got (%v, %s, %v)",
			res,
			code,
			err,
		)
	}

	before, after, err := ResetOpCertChain(
		ctx, wm, watermark.ModeEnforce, k.hash, 10, true,
	)
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	if before.ChainIssued == nil || *before.ChainIssued != 9 {
		t.Fatalf("before issued = %v, want 9", before.ChainIssued)
	}
	if after.ChainFloor == nil || *after.ChainFloor != 10 ||
		after.ChainIssued != nil {
		t.Fatalf("after = %+v, want floor 10 and no issued record", after)
	}

	res, code, err = c.SignOpCertFromChain(ctx, kes, 10, 102, k.hash.String())
	if err != nil {
		t.Fatalf("chain 10 after reset: %v (%s)", err, code)
	}
	verifyChainOpCert(t, res, kes, 11, 102)

	// The floor was written: a lower chain counter is refused.
	if _, code, err := c.SignOpCertFromChain(ctx, kes, 9, 103, k.hash.String()); err == nil ||
		code != CodeConflict {
		t.Fatalf(
			"chain 9 after reset to 10: want CodeConflict, got (%s, %v)",
			code,
			err,
		)
	}
}

// TestResetOpCertChain_LowersFloor: the reset trusts the report in either
// direction, as the device's floor reset does.
func TestResetOpCertChain_LowersFloor(t *testing.T) {
	t.Parallel()
	wm, _ := newSqliteForReset(t)
	k := newFakeKey(t)
	c, _ := newOpCertCoordinator(t, k, wm, watermark.ModeEnforce)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	if err := wm.CheckAndRaiseFloor(ctx, k.hash, opcertChainFloorScope, 12); err != nil {
		t.Fatal(err)
	}
	if _, code, err := c.SignOpCertFromChain(ctx, kes, 10, 1, k.hash.String()); err == nil ||
		code != CodeConflict {
		t.Fatalf(
			"chain 10 under floor 12: want CodeConflict, got (%s, %v)",
			code,
			err,
		)
	}
	if _, _, err := ResetOpCertChain(ctx, wm, watermark.ModeEnforce, k.hash, 10, true); err != nil {
		t.Fatalf("reset: %v", err)
	}
	res, code, err := c.SignOpCertFromChain(ctx, kes, 10, 2, k.hash.String())
	if err != nil {
		t.Fatalf("chain 10 after lowering: %v (%s)", err, code)
	}
	verifyChainOpCert(t, res, kes, 11, 2)
}

func TestResetOpCertChain_DryRunWritesNothing(t *testing.T) {
	t.Parallel()
	wm, _ := newSqliteForReset(t)
	ctx := context.Background()
	var key backend.KeyHash
	key[0] = 1
	_ = wm.CheckAndRaiseFloor(ctx, key, opcertChainIssuedScope, 9)

	before, after, err := ResetOpCertChain(
		ctx,
		wm,
		watermark.ModeEnforce,
		key,
		10,
		false,
	)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if after.ChainFloor == nil || *after.ChainFloor != 10 ||
		after.ChainIssued != nil {
		t.Fatalf("planned after = %+v", after)
	}
	now, err := ReadOpCertRecords(ctx, wm, key)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(now, before) || now.ChainIssued == nil ||
		*now.ChainIssued != 9 ||
		now.ChainFloor != nil {
		t.Fatalf("dry run changed the store: before %+v now %+v", before, now)
	}
}

// TestResetOpCertChain_OnlyTouchesChainScopes: another key, the explicit
// counter and the payload watermarks keep their records.
func TestResetOpCertChain_OnlyTouchesChainScopes(t *testing.T) {
	t.Parallel()
	wm, _ := newSqliteForReset(t)
	ctx := context.Background()
	var key, other backend.KeyHash
	key[0], other[0] = 1, 2
	for _, k := range []backend.KeyHash{key, other} {
		for _, s := range []string{opcertCounterScope, opcertChainIssuedScope} {
			if err := wm.CheckAndRaiseFloor(ctx, k, s, 9); err != nil {
				t.Fatal(err)
			}
		}
		if err := wm.CheckAndRaiseFloor(ctx, k, opcertChainFloorScope, 8); err != nil {
			t.Fatal(err)
		}
	}
	if err := wm.CheckAndCommit(ctx, key, "tx", []byte("a")); err != nil {
		t.Fatal(err)
	}

	if _, _, err := ResetOpCertChain(ctx, wm, watermark.ModeEnforce, key, 10, true); err != nil {
		t.Fatalf("reset: %v", err)
	}

	got, _ := ReadOpCertRecords(ctx, wm, key)
	if got.Explicit == nil || *got.Explicit != 9 {
		t.Fatalf("explicit counter = %v, want 9 untouched", got.Explicit)
	}
	if got.ChainFloor == nil || *got.ChainFloor != 10 ||
		got.ChainIssued != nil {
		t.Fatalf("reset key = %+v", got)
	}
	o, _ := ReadOpCertRecords(ctx, wm, other)
	if o.Explicit == nil || *o.Explicit != 9 || o.ChainIssued == nil ||
		*o.ChainIssued != 9 || o.ChainFloor == nil || *o.ChainFloor != 8 {
		t.Fatalf("other key changed: %+v", o)
	}
	if err := wm.CheckAndCommit(ctx, key, "tx", []byte("b")); !errors.Is(
		err,
		watermark.ErrConflict,
	) {
		t.Fatalf("tx payload watermark lost: %v", err)
	}
}

func TestResetOpCertChain_Refusals(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var key backend.KeyHash
	if _, _, err := ResetOpCertChain(ctx, watermark.NewMemWatermark(), watermark.ModeOff, key, 10, true); !errors.Is(
		err,
		ErrResetModeOff,
	) {
		t.Fatalf("mode off: %v", err)
	}
	if _, _, err := ResetOpCertChain(ctx, watermark.NewMemWatermark(), watermark.ModeEnforce, key, ^uint64(0), true); err == nil {
		t.Fatal("max uint64 chain counter accepted")
	}
}

func TestOpenResetStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, path := newSqliteForReset(t)

	for _, tc := range []struct {
		name string
		cfg  config.SignerWatermarkConfig
		want error
	}{
		{"mem", config.SignerWatermarkConfig{Type: "mem", Mode: "warn"}, ErrResetMemStore},
		{"empty type", config.SignerWatermarkConfig{Mode: "enforce"}, ErrResetMemStore},
		{"mode off", config.SignerWatermarkConfig{Type: "file", Path: path, Mode: "off"}, ErrResetModeOff},
		{"missing file", config.SignerWatermarkConfig{Type: "file", Path: filepath.Join(t.TempDir(), "typo.db")}, ErrResetStoreMissing},
	} {
		for _, apply := range []bool{false, true} {
			t.Run(
				fmt.Sprintf("%s apply=%v", tc.name, apply),
				func(t *testing.T) {
					t.Parallel()
					_, _, closeFn, err := OpenResetStore(ctx, tc.cfg, apply)
					if closeFn != nil {
						closeFn()
					}
					if !errors.Is(err, tc.want) {
						t.Fatalf("err = %v, want %v", err, tc.want)
					}
				},
			)
		}
	}

	for _, apply := range []bool{false, true} {
		wm, mode, closeFn, err := OpenResetStore(
			ctx,
			config.SignerWatermarkConfig{Type: "file", Path: path},
			apply,
		)
		if err != nil {
			t.Fatalf("open file store (apply=%v): %v", apply, err)
		}
		closeFn()
		if wm == nil || mode != watermark.ModeEnforce {
			t.Fatalf("apply=%v: got (%v, %s)", apply, wm, mode)
		}
	}
}
