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

package kesagent

import "github.com/prometheus/client_golang/prometheus"

// Metrics holds Prometheus collectors for the KES agent. Construct one per
// process and call Register to publish it.
type Metrics struct {
	servedKeys  prometheus.Counter
	signs       *prometheus.CounterVec
	evolutions  prometheus.Counter
	currentPer  prometheus.Gauge
	exhausted   prometheus.Gauge
	activeConns prometheus.Gauge
}

// NewMetrics builds the KES agent metric set.
func NewMetrics() *Metrics {
	return &Metrics{
		servedKeys: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "bursa_kesagent_served_keys_total",
			Help: "KES key pushes delivered to producers (serve-key mode).",
		}),
		signs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "bursa_kesagent_sign_total",
			Help: "KES signing operations by result (ok|error).",
		}, []string{"result"}),
		evolutions: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "bursa_kesagent_evolutions_total",
			Help: "KES key forward-evolutions performed.",
		}),
		currentPer: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "bursa_kesagent_current_period",
			Help: "Current absolute KES period of the active key.",
		}),
		exhausted: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "bursa_kesagent_exhausted",
			Help: "1 when the active KES key has exhausted its evolutions, else 0.",
		}),
		activeConns: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "bursa_kesagent_service_connections",
			Help: "Currently connected service-socket clients.",
		}),
	}
}

// Register publishes the collectors to r (call once at startup).
func (m *Metrics) Register(r prometheus.Registerer) {
	r.MustRegister(
		m.servedKeys,
		m.signs,
		m.evolutions,
		m.currentPer,
		m.exhausted,
		m.activeConns,
	)
}

func (m *Metrics) incServedKeys() {
	if m != nil {
		m.servedKeys.Inc()
	}
}

func (m *Metrics) incSign(result string) {
	if m != nil {
		m.signs.WithLabelValues(result).Inc()
	}
}

func (m *Metrics) incEvolutions() {
	if m != nil {
		m.evolutions.Inc()
	}
}

func (m *Metrics) setCurrentPeriod(p uint64) {
	if m != nil {
		m.currentPer.Set(float64(p))
	}
}

func (m *Metrics) setExhausted(v bool) {
	if m == nil {
		return
	}
	if v {
		m.exhausted.Set(1)
	} else {
		m.exhausted.Set(0)
	}
}

func (m *Metrics) addConns(delta float64) {
	if m != nil {
		m.activeConns.Add(delta)
	}
}
