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
// One report describes ONE piece of work: a phase, or one download within a
// phase that runs several. dingo runs both kinds concurrently, so the newest
// report is never the whole picture — see Status.BootstrapPhases.
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
	// BootstrapPhases holds the latest progress of each piece of work the
	// bootstrap has reported, in first-seen order.
	//
	// dingo runs work concurrently at two levels and reports all of it through
	// a single callback, so the newest report is never the whole picture: the
	// download phase fetches the immutable archives and the ancillary ledger
	// state in parallel, and the ledger import later runs alongside the
	// immutable copy. Bootstrap alone therefore alternates between unrelated
	// percentages over unrelated totals.
	//
	// Work is identified by phase and download size. dingo labels each download
	// report with the artifact it describes ("so concurrent downloads can be
	// distinguished by callers consuming one callback") but drops that label
	// when it flattens into mithril.SyncProgress, so the size — fixed for a
	// download and different for each — is the identity available to us. Two
	// downloads of exactly equal size would share a row; nothing worse.
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
