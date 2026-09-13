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

import "time"

// NodeState is the coarse lifecycle state of the embedded node.
type NodeState string

const (
	StateStopped       NodeState = "stopped"
	StateStarting      NodeState = "starting"
	StateBootstrapping NodeState = "bootstrapping"
	StateSyncing       NodeState = "syncing"
	StateReady         NodeState = "ready"
	StateError         NodeState = "error"
)

// BootstrapProgress is a snapshot of an in-flight Mithril bootstrap, flattened
// from dingo's mithril.SyncProgress for the API. It is set while
// StateBootstrapping and retained in StateError as a diagnostic (how far the
// bootstrap got before failing); any other state clears it.
//
// Bytes* describe the snapshot-download phase; Count/Total and CurrentSlot/
// TipSlot describe the later block-replay phases (copy, gap-fill, backfill).
// Whichever pair is populated for the active phase is what the UI renders to
// show "where it is"; the rest stay zero (omitted).
//
// One report describes ONE phase. dingo runs some phases concurrently, so the
// newest report is not the whole picture — see Status.BootstrapPhases.
type BootstrapProgress struct {
	Phase           string  `json:"phase"`
	Percent         float64 `json:"percent"`
	BytesDownloaded int64   `json:"bytes_downloaded,omitempty"`
	TotalBytes      int64   `json:"total_bytes,omitempty"`
	BytesPerSecond  float64 `json:"bytes_per_second,omitempty"`
	CurrentSlot     uint64  `json:"current_slot,omitempty"`
	TipSlot         uint64  `json:"tip_slot,omitempty"`
	Count           int     `json:"count,omitempty"`
	Total           int     `json:"total,omitempty"`
	Description     string  `json:"description,omitempty"`
	// Done marks the phase's end edge. dingo signals the end with a bare
	// report carrying no measurements, so this is the only way to tell a
	// finished phase from one that has just started at 0%.
	Done bool `json:"done,omitempty"`
}

// Status is a point-in-time snapshot of the embedded node, serialised by the API.
type Status struct {
	State NodeState `json:"state"`
	// ReadinessGeneration changes whenever a ready node loses readiness. It is
	// intentionally internal to the process: consumers use it to reject a
	// query that crossed a transient syncing interval, even if the node is
	// ready again by the time the query completes.
	ReadinessGeneration uint64             `json:"-"`
	Tip                 uint64             `json:"tip"` // latest block slot known to the node
	LatestBlockTime     *time.Time         `json:"latestBlockTime,omitempty"`
	CaughtUp            bool               `json:"caughtUp"`
	Bootstrap           *BootstrapProgress `json:"bootstrap,omitempty"`
	// BootstrapPhases holds each phase's own latest progress, in the order the
	// phases were first seen. dingo imports the ledger state and copies the
	// immutable chain CONCURRENTLY (one errgroup, two goroutines) and reports
	// both through a single callback, so Bootstrap alone alternates between two
	// unrelated percentages. Keeping them apart is what lets a reader see two
	// things running instead of one number jumping around.
	BootstrapPhases []BootstrapProgress `json:"bootstrap_phases,omitempty"`
	Err             string              `json:"error,omitempty"`
}

// caughtUp reports whether the latest block is recent enough to consider the
// node synced to the chain tip. A zero latest time is never caught up.
func caughtUp(latest, now time.Time, threshold time.Duration) bool {
	if latest.IsZero() {
		return false
	}
	return now.Sub(latest) <= threshold
}

// deriveState maps a poll result into a NodeState. It is only called while the
// node is running; the starting state is set directly by the supervisor before
// the poll loop begins.
func deriveState(haveBlock, isCaughtUp bool) NodeState {
	switch {
	case !haveBlock:
		return StateSyncing
	case isCaughtUp:
		return StateReady
	default:
		return StateSyncing
	}
}
