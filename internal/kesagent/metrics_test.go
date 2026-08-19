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

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestMetricsRegisterAndNames pins the exported metric names and help text
// (the documented wire contract) so an accidental rename or help-text change
// in the collector set is caught, and exercises Register end to end.
func TestMetricsRegisterAndNames(t *testing.T) {
	m := NewMetrics()
	reg := prometheus.NewRegistry()
	m.Register(reg)

	// Touch every collector so each metric family is produced by Gather.
	m.incServedKeys()
	m.incSign("ok")
	m.incSign("error")
	m.incEvolutions()
	m.setCurrentPeriod(42)
	m.setExhausted(true)
	m.addConns(1)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	got := make(map[string]string, len(mfs))
	for _, mf := range mfs {
		got[mf.GetName()] = mf.GetHelp()
	}

	want := map[string]string{
		"bursa_kesagent_served_keys_total":   "KES key pushes delivered to producers (serve-key mode).",
		"bursa_kesagent_sign_total":          "KES signing operations by result (ok|error).",
		"bursa_kesagent_evolutions_total":    "KES key forward-evolutions performed.",
		"bursa_kesagent_current_period":      "Current absolute KES period of the active key.",
		"bursa_kesagent_exhausted":           "1 when the active KES key has exhausted its evolutions, else 0.",
		"bursa_kesagent_service_connections": "Currently connected service-socket clients.",
	}
	for name, help := range want {
		gotHelp, ok := got[name]
		if !ok {
			t.Errorf("metric %q not registered", name)
			continue
		}
		if gotHelp != help {
			t.Errorf("metric %q help = %q, want %q", name, gotHelp, help)
		}
	}
	if len(got) != len(want) {
		t.Errorf("registered metric family count = %d, want %d (got %v)", len(got), len(want), got)
	}
}

// TestMetricsNilReceiverSafe verifies the accessor helpers are no-ops on a nil
// *Metrics, since the agent may run without a metrics set installed.
func TestMetricsNilReceiverSafe(t *testing.T) {
	var m *Metrics
	m.incServedKeys()
	m.incSign("ok")
	m.incEvolutions()
	m.setCurrentPeriod(1)
	m.setExhausted(true)
	m.setExhausted(false)
	m.addConns(1)
	m.addConns(-1)
}
