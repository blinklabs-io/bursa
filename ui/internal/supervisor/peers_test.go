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
	"testing"

	"github.com/blinklabs-io/dingo/connmanager"
	"github.com/prometheus/client_golang/prometheus"
)

// TestMetricConnPrefixMatchesDingo guards the coupling between peers.go and
// dingo's connection-manager Prometheus gauges: the live peer counts are read
// by matching metricConnPrefix+suffix against the node's registry. If dingo
// renames the prefix or any of these gauges, the counts would silently read
// zero — so we build a real connection manager against a throwaway registry
// and assert the exact names we depend on are still emitted. A rename in the
// dingo dep therefore fails this test loudly instead of shipping a broken
// peers panel.
func TestMetricConnPrefixMatchesDingo(t *testing.T) {
	reg := prometheus.NewRegistry()
	// Constructing with a registry registers the gauges; we don't need a
	// running node to read their names.
	_ = connmanager.NewConnectionManager(connmanager.ConnectionManagerConfig{
		PromRegistry: reg,
	})

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	got := make(map[string]bool, len(families))
	for _, mf := range families {
		got[mf.GetName()] = true
	}

	// The suffixes peers.go looks up via gauge().
	for _, suffix := range []string{
		"incomingConns",
		"outgoingConns",
		"duplexConns",
		"fullDuplexConns",
		"unidirectionalConns",
		"prunableConns",
	} {
		name := metricConnPrefix + suffix
		if !got[name] {
			t.Errorf("dingo no longer emits %q; the diagnostics peer counts "+
				"depend on it — update metricConnPrefix / peers.go to match "+
				"the current dingo connmanager metric names", name)
		}
	}
}
