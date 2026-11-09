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
// process and call Register to publish it. Every series about a key carries a
// profile label; a profile works through the view forProfile returns.
type Metrics struct {
	servedKeys  *prometheus.CounterVec
	signs       *prometheus.CounterVec
	evolutions  *prometheus.CounterVec
	currentPer  *prometheus.GaugeVec
	exhausted   *prometheus.GaugeVec
	activeConns prometheus.Gauge

	slotGuardRefusals *prometheus.CounterVec
	guardFresh        *prometheus.GaugeVec

	profile string
}

// NewMetrics builds the KES agent metric set.
func NewMetrics() *Metrics {
	return &Metrics{
		servedKeys: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "bursa_kesagent_served_keys_total",
			Help: "KES key pushes delivered to producers (serve-key mode).",
		}, []string{"profile"}),
		signs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "bursa_kesagent_sign_total",
			Help: "KES signing operations by result (ok|error).",
		}, []string{"profile", "result"}),
		evolutions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "bursa_kesagent_evolutions_total",
			Help: "KES key forward-evolutions performed.",
		}, []string{"profile"}),
		currentPer: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "bursa_kesagent_current_period",
			Help: "Current absolute KES period of the active key.",
		}, []string{"profile"}),
		exhausted: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "bursa_kesagent_exhausted",
			Help: "1 when the active KES key has exhausted its evolutions, else 0.",
		}, []string{"profile"}),
		activeConns: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "bursa_kesagent_service_connections",
			Help: "Currently connected service-socket clients.",
		}),
		slotGuardRefusals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "bursa_kesagent_slot_guard_refusals_total",
			Help: "Block headers the slot guard refused, " +
				"by reason (equivocation|rollback).",
		}, []string{"profile", "reason"}),
		guardFresh: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "bursa_kesagent_guard_fresh",
			Help: "1 when the profile's guard file was missing or " +
				"empty at startup, so no signed slot was known, else 0.",
		}, []string{"profile"}),
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
		m.slotGuardRefusals,
		m.guardFresh,
	)
}

// forProfile returns a view of m whose per-key series are labelled with the
// profile name. It shares m's collectors.
func (m *Metrics) forProfile(name string) *Metrics {
	if m == nil {
		return nil
	}
	v := *m
	v.profile = name
	// Create the children now so each profile exports zero-valued series
	// before its first event, as an unlabelled gauge would.
	m.servedKeys.WithLabelValues(name)
	m.signs.WithLabelValues(name, "ok")
	m.signs.WithLabelValues(name, "error")
	m.evolutions.WithLabelValues(name)
	m.currentPer.WithLabelValues(name)
	m.exhausted.WithLabelValues(name)
	return &v
}

func (m *Metrics) incServedKeys() {
	if m != nil {
		m.servedKeys.WithLabelValues(m.profile).Inc()
	}
}

func (m *Metrics) incSign(result string) {
	if m != nil {
		m.signs.WithLabelValues(m.profile, result).Inc()
	}
}

func (m *Metrics) incEvolutions() {
	if m != nil {
		m.evolutions.WithLabelValues(m.profile).Inc()
	}
}

func (m *Metrics) setCurrentPeriod(p uint64) {
	if m != nil {
		m.currentPer.WithLabelValues(m.profile).Set(float64(p))
	}
}

func (m *Metrics) setExhausted(v bool) {
	if m == nil {
		return
	}
	if v {
		m.exhausted.WithLabelValues(m.profile).Set(1)
	} else {
		m.exhausted.WithLabelValues(m.profile).Set(0)
	}
}

func (m *Metrics) addConns(delta float64) {
	if m != nil {
		m.activeConns.Add(delta)
	}
}

// incSlotGuardRefusal counts a header the slot guard refused; reason is
// "equivocation" or "rollback".
func (m *Metrics) incSlotGuardRefusal(reason string) {
	if m != nil {
		m.slotGuardRefusals.WithLabelValues(m.profile, reason).Inc()
	}
}

// initSlotGuardRefusals creates the profile's refusal series at zero, so the
// first refusal shows up as an increase rather than a new series.
func (m *Metrics) initSlotGuardRefusals() {
	if m == nil {
		return
	}
	for _, reason := range []string{"equivocation", "rollback"} {
		m.slotGuardRefusals.WithLabelValues(m.profile, reason).Add(0)
	}
}

// setGuardFresh records whether the profile's guard file had no prior record
// when the profile opened it.
func (m *Metrics) setGuardFresh(v bool) {
	if m == nil {
		return
	}
	if v {
		m.guardFresh.WithLabelValues(m.profile).Set(1)
	} else {
		m.guardFresh.WithLabelValues(m.profile).Set(0)
	}
}
