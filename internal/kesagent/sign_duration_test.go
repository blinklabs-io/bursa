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
	"context"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
	"github.com/prometheus/client_golang/prometheus"
)

// slowGuardStore delays the header guard write, standing in for a shared
// guard database some distance away.
type slowGuardStore struct {
	*watermark.MemWatermark

	delay time.Duration
}

func (s *slowGuardStore) CheckAndRaiseFloorAndCommit(
	ctx context.Context,
	key backend.KeyHash,
	floorScope string,
	floor uint64,
	scope string,
	payload []byte,
) error {
	time.Sleep(s.delay)
	return s.MemWatermark.CheckAndRaiseFloorAndCommit(
		ctx, key, floorScope, floor, scope, payload,
	)
}

// signDurationSamples returns the sample count and sum of the sign duration
// histogram for profile and result.
func signDurationSamples(
	t *testing.T,
	m *Metrics,
	profile string,
	result string,
) (uint64, float64) {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(m.signDur)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		for _, metric := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range metric.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["profile"] == profile && labels["result"] == result {
				h := metric.GetHistogram()
				return h.GetSampleCount(), h.GetSampleSum()
			}
		}
	}
	t.Fatalf("no sign duration series for %s/%s", profile, result)
	return 0, 0
}

func TestSignDurationCoversTheGuardWrite(t *testing.T) {
	t.Parallel()
	const delay = 50 * time.Millisecond
	store := &slowGuardStore{
		MemWatermark: watermark.NewMemWatermark(),
		delay:        delay,
	}
	a, spec := sharedHeaderAgent(t, newColdKey(t), store, 7)
	m := NewMetrics()
	p := sole(t, a)
	p.metrics = m.forProfile(p.cfg.Name)

	if _, err := a.SignHeader(5, spec.encode(t)); err != nil {
		t.Fatalf("SignHeader: %v", err)
	}
	count, sum := signDurationSamples(t, m, p.cfg.Name, "ok")
	if count != 1 {
		t.Fatalf("ok samples = %d, want 1", count)
	}
	if sum < delay.Seconds() {
		t.Fatalf(
			"ok sign duration = %vs, want at least the %v guard write",
			sum,
			delay,
		)
	}
	if count, _ := signDurationSamples(t, m, p.cfg.Name, "error"); count != 0 {
		t.Fatalf("error samples after one good sign = %d, want 0", count)
	}

	// A different body for the signed slot is refused and observed as an
	// error.
	spec.sequence++
	if _, err := a.SignHeader(5, spec.encode(t)); err == nil {
		t.Fatal("SignHeader of a second body for slot 52 succeeded")
	}
	if count, _ := signDurationSamples(t, m, p.cfg.Name, "error"); count != 1 {
		t.Fatalf("error samples = %d, want 1", count)
	}
	if count, _ := signDurationSamples(t, m, p.cfg.Name, "ok"); count != 1 {
		t.Fatalf("ok samples after the refusal = %d, want 1", count)
	}
}
