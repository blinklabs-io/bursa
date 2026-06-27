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
package supervisor

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/blinklabs-io/dingo"
	"github.com/blinklabs-io/dingo/database"
	"github.com/blinklabs-io/dingo/mithril"
)

// bootstrapMarker is written inside the node DB dir once a Mithril bootstrap
// completes, so subsequent starts skip the bootstrap and rely on P2P sync.
const bootstrapMarker = ".mithril-bootstrap-complete"

// BootstrapParams is the minimal input a Bootstrapper needs.
type BootstrapParams struct {
	Network    string
	DataDir    string
	OnProgress func(BootstrapProgress)
}

// Bootstrapper populates the node DB from a Mithril snapshot. It is an interface
// so the supervisor's orchestration can be unit-tested with a fake (no network).
type Bootstrapper interface {
	Bootstrap(ctx context.Context, p BootstrapParams) error
}

// mithrilBootstrapper is the real Bootstrapper backed by dingo's mithril.Sync.
type mithrilBootstrapper struct{ logger *slog.Logger }

func (b mithrilBootstrapper) Bootstrap(ctx context.Context, p BootstrapParams) error {
	_, err := mithril.Sync(ctx, syncConfigFor(p, b.logger))
	return err
}

// syncConfigFor builds the mithril.SyncConfig for a bootstrap. The storage mode
// and blob/metadata plugins MUST match the node's, or the imported DB will not
// open; we bind them to the same dingo defaults the supervisor's node uses
// (StorageModeAPI + database.DefaultConfig) so they can't silently drift.
// CardanoNodeConfig is left nil so mithril.Sync loads it from the embedded
// config for Network (same source the node uses).
func syncConfigFor(p BootstrapParams, logger *slog.Logger) mithril.SyncConfig {
	return mithril.SyncConfig{
		Network:          p.Network,
		DataDir:          p.DataDir,
		StorageMode:      string(dingo.StorageModeAPI),
		BlobPlugin:       database.DefaultConfig.BlobPlugin,
		MetadataPlugin:   database.DefaultConfig.MetadataPlugin,
		VerifyCertChain:  true,
		CleanupAfterLoad: true,
		// dingo v0.55.0's API-mode backfill phase requires a positive batch size
		// and applies no default of its own when the SyncConfig is built directly
		// (only dingo's config layer defaults it). Mirror dingo's own default
		// (node.DefaultBackfillBatchSize == 100, unexported) or the backfill phase
		// fails with "backfill batch size must be positive".
		BackfillBatchSize: 100,
		// DatabaseWorkers is deliberately left unset (0). It sizes the SQLite
		// read-connection pool; during the write-heavy backfill, extra readers
		// cause WAL-checkpoint contention that roughly HALVED throughput
		// (~119→~61 blocks/s when set to dingo's config default of 5). It also
		// only affects bootstrap — the running node config doesn't set it — so a
		// non-zero value is pure downside here.
		Logger: logger,
		OnProgress: func(sp mithril.SyncProgress) {
			if p.OnProgress != nil {
				p.OnProgress(toBootstrapProgress(sp))
			}
		},
	}
}

// toBootstrapProgress flattens dingo's SyncProgress into the package's API type
// so the UI can show which phase is running and how far it has got. Active is
// the one field we drop: it only marks a phase's begin/end edge, and Percent
// already conveys completion within a phase.
func toBootstrapProgress(sp mithril.SyncProgress) BootstrapProgress {
	return BootstrapProgress{
		Phase:           string(sp.Phase),
		Percent:         sp.Percent,
		BytesDownloaded: sp.BytesDownloaded,
		TotalBytes:      sp.TotalBytes,
		BytesPerSecond:  sp.BytesPerSecond,
		CurrentSlot:     sp.CurrentSlot,
		TipSlot:         sp.TipSlot,
		Count:           sp.Count,
		Total:           sp.Total,
		Description:     sp.Description,
	}
}

// shouldBootstrap reports whether a Mithril bootstrap should run: only when
// enabled and no completed bootstrap is recorded for the DB dir.
func shouldBootstrap(enabled bool, dataDir string) bool {
	return enabled && !bootstrapDone(dataDir)
}

func markerPath(dataDir string) string { return filepath.Join(dataDir, bootstrapMarker) }

// bootstrapDone reports whether a completed-bootstrap marker exists. Only a
// definitively-missing marker counts as "not bootstrapped": any other stat
// error (e.g. permissions) reads as done, so we never re-import a snapshot
// over a DB dir we cannot inspect — launching the node surfaces the real
// error instead.
func bootstrapDone(dataDir string) bool {
	_, err := os.Stat(markerPath(dataDir))
	return !errors.Is(err, fs.ErrNotExist)
}

// markBootstrapDone records a completed bootstrap. The DB dir exists by now
// (mithril.Sync created it).
func markBootstrapDone(dataDir string) error {
	return os.WriteFile(markerPath(dataDir), []byte("ok\n"), 0o600)
}
