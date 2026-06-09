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
	StateStopped  NodeState = "stopped"
	StateStarting NodeState = "starting"
	StateSyncing  NodeState = "syncing"
	StateReady    NodeState = "ready"
	StateError    NodeState = "error"
)

// Status is a point-in-time snapshot of the embedded node, serialised by the API.
type Status struct {
	State           NodeState  `json:"state"`
	Tip             uint64     `json:"tip"` // latest block slot known to the node
	LatestBlockTime *time.Time `json:"latestBlockTime,omitempty"`
	CaughtUp        bool       `json:"caughtUp"`
	Err             string     `json:"error,omitempty"`
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
