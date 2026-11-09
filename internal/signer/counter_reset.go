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
	"math"
	"os"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
)

// Refusals of an opcert chain-counter reset.
var (
	ErrResetMemStore     = errors.New("reset refused: mem watermark store")
	ErrResetModeOff      = errors.New("reset refused: watermark mode off")
	ErrResetStoreMissing = errors.New(
		"reset refused: watermark store does not exist",
	)
)

// OpCertRecords are the opcert counter records kept for one cold key; nil
// means no record.
type OpCertRecords struct {
	// ChainFloor is the highest on-chain counter reported to
	// SignOpCertFromChain.
	ChainFloor *uint64
	// ChainIssued is the highest issue number signed by either request form.
	ChainIssued *uint64
	// Explicit is the strict issue-counter record of SignOpCert. A reset
	// never changes it.
	Explicit *uint64
	// LegacyChainIssued is the issued record written without a profile,
	// before profile scoping. It is read only for a profile.
	LegacyChainIssued *uint64
}

func readRecord(
	ctx context.Context,
	cw watermark.CounterReader,
	key backend.KeyHash,
	scope string,
) (*uint64, error) {
	v, ok, err := cw.CounterFor(ctx, key, scope)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", scope, err)
	}
	if !ok {
		return nil, nil
	}
	return &v, nil
}

// ReadOpCertRecords reads the opcert counter records for key under profile;
// an empty profile reads the records of an unprofiled backend.
func ReadOpCertRecords(
	ctx context.Context,
	cw watermark.CounterReader,
	key backend.KeyHash,
	profile string,
) (OpCertRecords, error) {
	var (
		r   OpCertRecords
		err error
	)
	for _, rec := range []struct {
		dst   **uint64
		scope string
	}{
		{&r.ChainFloor, scopeForProfile(opcertChainFloorScope, profile)},
		{&r.ChainIssued, scopeForProfile(opcertChainIssuedScope, profile)},
		{&r.Explicit, scopeForProfile(opcertCounterScope, profile)},
	} {
		if *rec.dst, err = readRecord(ctx, cw, key, rec.scope); err != nil {
			return r, err
		}
	}
	if profile != "" {
		r.LegacyChainIssued, err = readRecord(
			ctx, cw, key, opcertChainIssuedScope,
		)
	}
	return r, err
}

// ResetOpCertChain is the administrative reset of the chain-counter records,
// the signer's counterpart of the armory device's floor reset. It sets the
// chain floor of key to chainCounter, lower or higher than the stored value,
// and clears the issued record, in one transaction that first bumps the reset
// generation, which refuses any opcert request that read the records before
// the reset and commits after it. The reported counter is
// trusted. The explicit issue-counter record and the payload watermarks are
// not touched. With apply false no record is written and after is the planned
// state; store then needs only to read.
//
// A non-empty profile resets the records of a key served under that profile.
// The same transaction also deletes the issued record written without a
// profile: while the profile's backend is the key's only holder, the signer
// reads it whenever the profile has no issued record, so it would otherwise
// bound the next request again. The floor written without a profile needs no
// change, as the reset leaves a floor under the profile.
//
// It is for an operator command only: nothing on the signing path calls it.
func ResetOpCertChain(
	ctx context.Context,
	store watermark.CounterReader,
	mode watermark.Mode,
	key backend.KeyHash,
	profile string,
	chainCounter uint64,
	apply bool,
) (before, after OpCertRecords, err error) {
	if mode == watermark.ModeOff {
		return before, after, ErrResetModeOff
	}
	if chainCounter == math.MaxUint64 {
		return before, after, errors.New("chain counter out of range")
	}
	if before, err = ReadOpCertRecords(ctx, store, key, profile); err != nil {
		return before, after, err
	}
	if !apply {
		after = before
		after.ChainFloor = &chainCounter
		after.ChainIssued = nil
		after.LegacyChainIssued = nil
		return before, after, nil
	}
	admin, ok := store.(watermark.CounterAdmin)
	if !ok {
		return before, after, errors.New(
			"watermark store does not support administrative reset",
		)
	}
	clearScopes := []string{scopeForProfile(opcertChainIssuedScope, profile)}
	if profile != "" {
		clearScopes = append(clearScopes, opcertChainIssuedScope)
	}
	err = admin.AdminResetCounters(
		ctx,
		key,
		[]watermark.CounterSet{{
			Scope: scopeForProfile(opcertChainFloorScope, profile),
			Value: chainCounter,
		}},
		clearScopes,
		scopeForProfile(opcertResetGenScope, profile),
	)
	if err != nil {
		return before, after, err
	}
	after, err = ReadOpCertRecords(ctx, store, key, profile)
	return before, after, err
}

// OpenResetStore opens the configured watermark store for ResetOpCertChain.
// It refuses a mem store and mode off, and a file store that does not exist,
// since opening one would create an empty database the signer never reads.
// With apply true the store is opened through BuildWatermark, which
// initializes its schema. With apply false it is opened read-only, with no
// schema initialization, so a dry run writes no records. The returned function
// closes the store.
func OpenResetStore(
	ctx context.Context,
	c config.SignerWatermarkConfig,
	apply bool,
) (watermark.CounterReader, watermark.Mode, func(), error) {
	noop := func() {}
	if c.Type == "" || c.Type == "mem" {
		return nil, "", noop, ErrResetMemStore
	}
	mode := watermark.Mode(c.Mode)
	if mode == "" {
		mode = watermark.ModeEnforce
	}
	if mode == watermark.ModeOff {
		return nil, watermark.ModeOff, noop, ErrResetModeOff
	}
	if c.Type == "file" && c.Path != "" {
		if _, err := os.Stat(watermark.SqliteFilePath(c.Path)); err != nil {
			return nil, "", noop, fmt.Errorf(
				"%w: %w", ErrResetStoreMissing, err,
			)
		}
	}
	if !apply {
		return openResetReader(ctx, c, mode)
	}
	wm, mode, err := BuildWatermark(ctx, c)
	if err != nil {
		return nil, mode, noop, err
	}
	closeFn := noop
	switch s := wm.(type) {
	case interface{ Close() error }:
		closeFn = func() { _ = s.Close() }
	case interface{ Close() }:
		closeFn = s.Close
	}
	store, ok := wm.(watermark.CounterReader)
	if !ok {
		closeFn()
		return nil, mode, noop, errors.New(
			"watermark store does not support opcert counters",
		)
	}
	return store, mode, closeFn, nil
}

// openResetReader opens the configured store read-only for a dry run.
func openResetReader(
	ctx context.Context,
	c config.SignerWatermarkConfig,
	mode watermark.Mode,
) (watermark.CounterReader, watermark.Mode, func(), error) {
	noop := func() {}
	switch c.Type {
	case "file":
		if c.Path == "" {
			return nil, mode, noop, fmt.Errorf(
				"watermark type %q requires a non-empty path",
				c.Type,
			)
		}
		r, err := watermark.OpenSqliteCounterReader(c.Path)
		if err != nil {
			return nil, mode, noop, err
		}
		return r, mode, func() { _ = r.Close() }, nil
	case "postgres":
		dsn, err := watermarkPostgresDSN(c)
		if err != nil {
			return nil, mode, noop, err
		}
		r, err := watermark.OpenPostgresCounterReader(ctx, dsn)
		if err != nil {
			return nil, mode, noop, err
		}
		return r, mode, r.Close, nil
	default:
		return nil, mode, noop, fmt.Errorf("unknown watermark type %q", c.Type)
	}
}
