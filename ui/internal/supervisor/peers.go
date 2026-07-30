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

// metricConnPrefix is the name prefix Dingo's connection manager gives its
// Prometheus gauges (see dingo/connmanager). We gather them from the node's
// per-launch registry to read live connection counts, since the embedded
// node's public API exposes no direct peer accessor. It is a var (not a
// const) so it is overridable and so a test can assert it still matches what
// the pinned dingo dep emits — a rename there would otherwise silently zero
// the peer counts (see peers_test.go).
var metricConnPrefix = "cardano_node_metrics_connectionManager_"

// PeerCounts is a point-in-time snapshot of the embedded node's live
// connection-manager gauges. Dingo does not expose a per-peer accessor on its
// public Node type, so these aggregate counts are the live peer signal the
// wallet can read; the per-peer address list comes from the configured
// topology (ConfiguredPeers). Available is false when no node has been
// launched yet (no registry) or the gauges are not present.
type PeerCounts struct {
	Available      bool
	Inbound        int
	Outbound       int
	Duplex         int
	FullDuplex     int
	Unidirectional int
	Prunable       int
}

// Total is the live connection count (inbound + outbound).
func (p PeerCounts) Total() int { return p.Inbound + p.Outbound }

// ConfiguredPeer is one outbound access point the node is configured to dial,
// from the embedded topology. Source is "bootstrap", "localRoot", or
// "publicRoot". These are the peers the node MAY connect to, not a live
// connection list (which the node's public API does not expose).
type ConfiguredPeer struct {
	Address string
	Port    uint
	Source  string
}

// Peers gathers the running node's connection-manager gauges into a PeerCounts.
// It returns {Available: false} when no node has been launched (no registry).
func (s *Supervisor) Peers() PeerCounts {
	s.mu.RLock()
	reg := s.promRegistry
	s.mu.RUnlock()
	if reg == nil {
		return PeerCounts{}
	}
	families, err := reg.Gather()
	if err != nil {
		return PeerCounts{}
	}
	gauge := func(name string) (float64, bool) {
		for _, mf := range families {
			if mf.GetName() != metricConnPrefix+name {
				continue
			}
			for _, m := range mf.GetMetric() {
				if g := m.GetGauge(); g != nil {
					return g.GetValue(), true
				}
			}
		}
		return 0, false
	}
	pc := PeerCounts{}
	// The gauges only exist once the connection manager has initialised its
	// metrics; treat their presence as "peer data available".
	if v, ok := gauge("incomingConns"); ok {
		pc.Available = true
		pc.Inbound = int(v)
	}
	if v, ok := gauge("outgoingConns"); ok {
		pc.Available = true
		pc.Outbound = int(v)
	}
	if v, ok := gauge("duplexConns"); ok {
		pc.Duplex = int(v)
	}
	if v, ok := gauge("fullDuplexConns"); ok {
		pc.FullDuplex = int(v)
	}
	if v, ok := gauge("unidirectionalConns"); ok {
		pc.Unidirectional = int(v)
	}
	if v, ok := gauge("prunableConns"); ok {
		pc.Prunable = int(v)
	}
	return pc
}

// ConfiguredPeers flattens the embedded topology's bootstrap, local-root, and
// public-root access points into a single list for Diagnostics. It returns nil
// before the node has been started (no topology loaded yet).
func (s *Supervisor) ConfiguredPeers() []ConfiguredPeer {
	s.mu.RLock()
	topo := s.topologyCfg
	s.mu.RUnlock()
	if topo == nil {
		return nil
	}
	var out []ConfiguredPeer
	for _, bp := range topo.BootstrapPeers {
		out = append(out, ConfiguredPeer{Address: bp.Address, Port: bp.Port, Source: "bootstrap"})
	}
	for _, lr := range topo.LocalRoots {
		for _, ap := range lr.AccessPoints {
			out = append(out, ConfiguredPeer{Address: ap.Address, Port: ap.Port, Source: "localRoot"})
		}
	}
	for _, pr := range topo.PublicRoots {
		for _, ap := range pr.AccessPoints {
			out = append(out, ConfiguredPeer{Address: ap.Address, Port: ap.Port, Source: "publicRoot"})
		}
	}
	return out
}
