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

package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/signer"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
)

const (
	resetKeyHex   = "00000000000000000000000000000000000000000000000000000001"
	resetOtherHex = "00000000000000000000000000000000000000000000000000000002"
)

// seedResetStore writes a file store with a chain floor, an issued record and
// an explicit counter for both keys, as after the failover.
func seedResetStore(
	t *testing.T,
) (config.SignerWatermarkConfig, *watermark.SqliteWatermark) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wm.db")
	wm, err := watermark.NewSqliteWatermark(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wm.Close() })
	ctx := context.Background()
	for _, h := range []string{resetKeyHex, resetOtherHex} {
		k, _ := backend.ParseKeyHash(h)
		for scope, v := range map[string]uint64{
			"opcert-chain-floor":  8,
			"opcert-chain-issued": 9,
			"opcert-counter":      9,
		} {
			if err := wm.CheckAndRaiseFloor(ctx, k, scope, v); err != nil {
				t.Fatal(err)
			}
		}
	}
	return config.SignerWatermarkConfig{Type: "file", Path: path}, wm
}

func resetRecords(
	t *testing.T,
	wm *watermark.SqliteWatermark,
	hexKey string,
) signer.OpCertRecords {
	t.Helper()
	k, _ := backend.ParseKeyHash(hexKey)
	r, err := signer.ReadOpCertRecords(context.Background(), wm, k, "")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSignerCounterReset_WithoutYesWritesNothing(t *testing.T) {
	t.Parallel()
	cfg, wm := seedResetStore(t)
	var out bytes.Buffer
	err := runSignerCounterReset(
		context.Background(),
		&out,
		cfg,
		resetKeyHex,
		10,
		false,
	)
	if !errors.Is(err, errCounterResetNotConfirmed) {
		t.Fatalf("err = %v, want errCounterResetNotConfirmed", err)
	}
	r := resetRecords(t, wm, resetKeyHex)
	if *r.ChainFloor != 8 || r.ChainIssued == nil || *r.ChainIssued != 9 {
		t.Fatalf("store changed without --yes: %+v", r)
	}
	if !strings.Contains(out.String(), "would become") {
		t.Fatalf("output lacks the planned change:\n%s", out.String())
	}
}

func TestSignerCounterReset_YesAppliesToOneKey(t *testing.T) {
	t.Parallel()
	cfg, wm := seedResetStore(t)
	var out bytes.Buffer
	if err := runSignerCounterReset(context.Background(), &out, cfg, resetKeyHex, 10, true); err != nil {
		t.Fatalf("reset: %v", err)
	}
	r := resetRecords(t, wm, resetKeyHex)
	if *r.ChainFloor != 10 || r.ChainIssued != nil || *r.Explicit != 9 {
		t.Fatalf(
			"reset key: floor %d issued %v explicit %d",
			*r.ChainFloor,
			r.ChainIssued,
			*r.Explicit,
		)
	}
	o := resetRecords(t, wm, resetOtherHex)
	if *o.ChainFloor != 8 || *o.ChainIssued != 9 || *o.Explicit != 9 {
		t.Fatalf("other key changed: %+v", o)
	}
	for _, want := range []string{"before:", "after:", "opcert-chain-issued", "9", "10"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q:\n%s", want, out.String())
		}
	}
}

func TestSignerCounterReset_Refusals(t *testing.T) {
	t.Parallel()
	cfg, wm := seedResetStore(t)
	ctx := context.Background()

	off := cfg
	off.Mode = "off"
	mem := config.SignerWatermarkConfig{Type: "mem", Mode: "warn"}
	missing := config.SignerWatermarkConfig{
		Type: "file", Path: filepath.Join(t.TempDir(), "typo.db"),
	}
	for _, tc := range []struct {
		name string
		cfg  config.SignerWatermarkConfig
		key  string
		want string
	}{
		{"mem store", mem, resetKeyHex, "mem watermark store"},
		{"mode off", off, resetKeyHex, "watermark mode off"},
		{"missing store", missing, resetKeyHex, "does not exist"},
		{"short hash", cfg, "abcd", "must be 28 bytes"},
		{"non hex", cfg, strings.Repeat("zz", 28), "invalid key hash hex"},
	} {
		err := runSignerCounterReset(
			ctx,
			&bytes.Buffer{},
			tc.cfg,
			tc.key,
			10,
			true,
		)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want containing %q", tc.name, err, tc.want)
		}
	}
	if r := resetRecords(t, wm, resetKeyHex); *r.ChainFloor != 8 ||
		*r.ChainIssued != 9 {
		t.Fatalf("a refused reset changed the store: %+v", r)
	}
}

func TestSignerCounterResetCommandRegistered(t *testing.T) {
	t.Parallel()
	c, _, err := signerCommand().Find([]string{"counter-reset"})
	if err != nil || c.Name() != "counter-reset" {
		t.Fatalf("counter-reset not under signer: %v", err)
	}
	for _, f := range []string{"key", "chain-counter", "yes", "config"} {
		if c.Flags().Lookup(f) == nil {
			t.Errorf("missing flag --%s", f)
		}
	}
}
