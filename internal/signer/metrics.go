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

import "github.com/prometheus/client_golang/prometheus"

// Metrics holds Prometheus counters for the signer. Construct one value per
// process and pass it in via Deps; call Register to publish to a registerer.
type Metrics struct {
	requests *prometheus.CounterVec
}

// NewMetrics creates a new Metrics instance.
func NewMetrics() *Metrics {
	return &Metrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "bursa_signer_requests_total",
			Help: "Per-signer signing operations by type and result.",
		}, []string{"type", "result"}),
	}
}

// Register registers the collectors with r (call once at startup; construct one
// Metrics value per process and pass it in via Deps).
func (m *Metrics) Register(r prometheus.Registerer) {
	r.MustRegister(m.requests)
}

func (m *Metrics) observe(reqType, result string) {
	m.requests.WithLabelValues(reqType, result).Inc()
}
