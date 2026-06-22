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

// Metrics holds Prometheus collectors for the signer. Construct one value per
// process and pass it in via Deps; call Register to publish to a registerer.
type Metrics struct {
	requests           *prometheus.CounterVec
	denials            *prometheus.CounterVec
	signDuration       *prometheus.HistogramVec
	backendErrors      *prometheus.CounterVec
	watermarkConflicts prometheus.Counter
}

// NewMetrics creates a new Metrics instance.
func NewMetrics() *Metrics {
	return &Metrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "bursa_signer_requests_total",
			Help: "Per-signer signing operations by type and result.",
		}, []string{"type", "result"}),
		denials: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "bursa_signer_deny_total",
			Help: "Denied signing operations by reason category (ErrorCode values plus \"acl\" for API-layer caller-ACL denials, which never reach requests_total).",
		}, []string{"reason"}),
		signDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "bursa_signer_sign_duration_seconds",
			Help:    "Time spent producing a signature, by custody backend.",
			Buckets: prometheus.DefBuckets,
		}, []string{"backend"}),
		backendErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "bursa_signer_backend_errors_total",
			Help: "Custody backend failures by backend name.",
		}, []string{"backend"}),
		watermarkConflicts: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "bursa_signer_watermark_conflicts_total",
			Help: "Anti-double-sign watermark conflicts.",
		}),
	}
}

// Register registers the collectors with r (call once at startup).
func (m *Metrics) Register(r prometheus.Registerer) {
	r.MustRegister(m.requests, m.denials, m.signDuration, m.backendErrors, m.watermarkConflicts)
}

func (m *Metrics) observe(reqType, result string) {
	m.requests.WithLabelValues(reqType, result).Inc()
}

func (m *Metrics) observeDeny(reason string) {
	m.denials.WithLabelValues(reason).Inc()
}

// ObserveDeny records a denial decided outside the coordinator (e.g. the API
// layer's caller ACL). reason must be a low-cardinality category.
func (m *Metrics) ObserveDeny(reason string) { m.observeDeny(reason) }

func (m *Metrics) observeSignDuration(backendName string, seconds float64) {
	m.signDuration.WithLabelValues(backendName).Observe(seconds)
}

func (m *Metrics) observeBackendError(backendName string) {
	m.backendErrors.WithLabelValues(backendName).Inc()
}

func (m *Metrics) observeWatermarkConflict() {
	m.watermarkConflicts.Inc()
}
