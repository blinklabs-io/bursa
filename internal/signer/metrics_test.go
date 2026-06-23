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

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetrics_CountSign(t *testing.T) {
	m := NewMetrics()
	m.observe("tx", "signed")
	m.observe("tx", "denied")
	if got := testutil.ToFloat64(m.requests.WithLabelValues("tx", "signed")); got != 1 {
		t.Fatalf("expected 1 signed, got %v", got)
	}
	if got := testutil.ToFloat64(m.requests.WithLabelValues("tx", "denied")); got != 1 {
		t.Fatalf("expected 1 denied, got %v", got)
	}
}

func TestMetrics_NewCollectors(t *testing.T) {
	m := NewMetrics()
	m.observeDeny("denied")
	m.observeDeny("denied")
	m.observeSignDuration("software", 0.01)
	m.observeBackendError("vault")
	m.observeWatermarkConflict()

	if got := testutil.ToFloat64(m.denials.WithLabelValues("denied")); got != 2 {
		t.Fatalf("expected 2 denials, got %v", got)
	}
	if got := testutil.ToFloat64(m.backendErrors.WithLabelValues("vault")); got != 1 {
		t.Fatalf("expected 1 backend error, got %v", got)
	}
	if got := testutil.ToFloat64(m.watermarkConflicts); got != 1 {
		t.Fatalf("expected 1 watermark conflict, got %v", got)
	}
	// Histograms can't use ToFloat64; check sample count via CollectAndCount.
	if got := testutil.CollectAndCount(m.signDuration); got != 1 {
		t.Fatalf("expected 1 sign-duration series, got %v", got)
	}
}

func TestMetrics_ObserveDenyExported(t *testing.T) {
	m := NewMetrics()
	m.ObserveDeny("acl")
	if got := testutil.ToFloat64(m.denials.WithLabelValues("acl")); got != 1 {
		t.Fatalf("expected 1 acl denial, got %v", got)
	}
}

func TestMetrics_RegisterAll(t *testing.T) {
	m := NewMetrics()
	reg := prometheus.NewRegistry()
	m.Register(reg) // must not panic (MustRegister) and must register all collectors
	m.observe("tx", "signed")
	m.observeDeny("conflict")
	m.observeSignDuration("software", 0.02)
	m.observeBackendError("software")
	m.observeWatermarkConflict()
	names := []string{
		"bursa_signer_requests_total",
		"bursa_signer_deny_total",
		"bursa_signer_sign_duration_seconds",
		"bursa_signer_backend_errors_total",
		"bursa_signer_watermark_conflicts_total",
	}
	got, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	found := map[string]bool{}
	for _, mf := range got {
		found[mf.GetName()] = true
	}
	for _, n := range names {
		if !found[n] {
			t.Errorf("metric %s not registered", n)
		}
	}
}
