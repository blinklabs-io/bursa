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
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
	"github.com/blinklabs-io/gouroboros/kes"
)

// TestMetricsRegisterAndNames pins the exported metric names and help text
// (the documented wire contract) so an accidental rename or help-text change
// in the collector set is caught, and exercises Register end to end.
func TestMetricsRegisterAndNames(t *testing.T) {
	t.Parallel()
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
	m.incSlotGuardRefusal("equivocation")
	m.setGuardFresh(true)
	m.observeGuardWrite(time.Millisecond)
	m.incGuardStoreError()
	m.setLastPeriod(64)
	m.setIssueNumber(7)
	m.setLastSign(time.Unix(1, 0))

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
		"bursa_kesagent_slot_guard_refusals_total": "Block headers the slot " +
			"guard refused, by reason (equivocation|rollback).",
		"bursa_kesagent_guard_fresh": "1 when the profile's guard file was " +
			"missing or empty at startup, so no signed slot was known, else 0.",
		"bursa_kesagent_slot_guard_write_duration_seconds": "Duration of slot " +
			"guard writes to the shared guard store.",
		"bursa_kesagent_slot_guard_store_errors_total": "Shared guard store " +
			"calls that failed (timeout or unreachable), not counting refusals.",
		"bursa_kesagent_last_period": "Last absolute KES period the active " +
			"key can sign in.",
		"bursa_kesagent_opcert_issue_number": "Issue number of the active " +
			"key's operational certificate.",
		"bursa_kesagent_last_sign_timestamp_seconds": "Unix time of the last " +
			"successful sign, 0 before the first.",
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
		t.Errorf(
			"registered metric family count = %d, want %d (got %v)",
			len(got),
			len(want),
			got,
		)
	}
}

// TestMetricsNilReceiverSafe verifies the accessor helpers are no-ops on a nil
// *Metrics, since the agent may run without a metrics set installed.
func TestMetricsNilReceiverSafe(t *testing.T) {
	t.Parallel()
	var m *Metrics
	m.incServedKeys()
	m.incSign("ok")
	m.incEvolutions()
	m.setCurrentPeriod(1)
	m.setExhausted(true)
	m.setExhausted(false)
	m.addConns(1)
	m.addConns(-1)
	m.incSlotGuardRefusal("rollback")
	m.initSlotGuardRefusals()
	m.setGuardFresh(true)
	m.observeGuardWrite(time.Second)
	m.incGuardStoreError()
	m.setLastPeriod(1)
	m.setIssueNumber(1)
	m.setLastSign(time.Unix(1, 0))
}

// TestMetricsProfileSeriesExistBeforeFirstEvent verifies that a profile
// exports its zero-valued per-key series from the moment its view is built,
// so bursa_kesagent_exhausted reads 0 for a profile with no key installed.
func TestMetricsProfileSeriesExistBeforeFirstEvent(t *testing.T) {
	t.Parallel()
	m := NewMetrics()
	m.forProfile("pool-a")
	for name, c := range map[string]prometheus.Collector{
		"served_keys": m.servedKeys,
		"evolutions":  m.evolutions,
		"current":     m.currentPer,
		"exhausted":   m.exhausted,
		"guard_write": m.guardWrite,
		"guard_store": m.guardStoreErrors,
		"last_period": m.lastPeriod,
		"issue":       m.issueNumber,
		"last_sign":   m.lastSign,
	} {
		if n := testutil.CollectAndCount(c); n != 1 {
			t.Errorf("%s series = %d, want 1", name, n)
		}
	}
	if n := testutil.CollectAndCount(m.signs); n != 2 {
		t.Errorf("sign series = %d, want 2 (ok and error)", n)
	}
	if got := testutil.ToFloat64(m.exhausted.WithLabelValues("pool-a")); got != 0 {
		t.Errorf("exhausted = %v, want 0", got)
	}
}

// faultyStore is a shared guard store whose combined floor and payload write
// can be slowed or made to fail, as a database that is slow or unreachable.
type faultyStore struct {
	*watermark.MemWatermark

	delay time.Duration
	fail  atomic.Bool
}

var errStoreUnreachable = errors.New("store unreachable")

func (s *faultyStore) CheckAndRaiseFloorAndCommit(
	ctx context.Context,
	key backend.KeyHash,
	floorScope string,
	floor uint64,
	scope string,
	payload []byte,
) error {
	time.Sleep(s.delay) // simulated database latency
	if s.fail.Load() {
		return errStoreUnreachable
	}
	return s.MemWatermark.CheckAndRaiseFloorAndCommit(
		ctx, key, floorScope, floor, scope, payload,
	)
}

// metricsHeaderAgent is a sign-mode agent with its guard in store and
// metrics registered in reg, holding an opcert at issue number 7, start
// period 3, at KES period 5.
func metricsHeaderAgent(
	t *testing.T,
	store SharedGuardStore,
	reg *prometheus.Registry,
) (*Agent, headerSpec) {
	t.Helper()
	cold := newColdKey(t)
	m := NewMetrics()
	m.Register(reg)
	cfg := Config{
		Mode:              ModeSign,
		Depth:             kes.CardanoKesDepth,
		SystemStart:       epoch,
		SlotLength:        time.Second,
		SlotsPerKESPeriod: 10,
		MaxKESEvolutions:  62,
		ColdVKey:          cold.pub,
		EvolveInterval:    time.Hour,
		Version:           "test",
		SharedGuard:       store,
	}
	a, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), m)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a.now = func() time.Time { return atPeriod(5) }
	t.Cleanup(a.Close)
	vkey, err := a.GenStagedKey()
	if err != nil {
		t.Fatalf("GenStagedKey: %v", err)
	}
	opcert := makeOpCert(t, vkey, 7, 3, cold)
	if _, err := a.InstallKey(opcert); err != nil {
		t.Fatalf("InstallKey: %v", err)
	}
	return a, headerSpec{
		slot:      52,
		issuer:    cold.pub,
		hotVkey:   vkey,
		sequence:  7,
		kesPeriod: 3,
		coldSig:   opCertColdSig(t, opcert),
	}
}

// seriesValue is the reading of one series: a histogram's sample count and
// sum, or a counter's or gauge's value.
type seriesValue struct {
	count uint64
	sum   float64
	value float64
}

// metricOf returns the reading of the series of the named metric for the default
// profile.
func metricOf(
	t *testing.T,
	reg *prometheus.Registry,
	name string,
) seriesValue {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, mt := range mf.GetMetric() {
			for _, l := range mt.GetLabel() {
				if l.GetName() == "profile" && l.GetValue() == DefaultProfileName {
					return seriesValue{
						count: mt.GetHistogram().GetSampleCount(),
						sum:   mt.GetHistogram().GetSampleSum(),
						value: mt.GetCounter().GetValue() + mt.GetGauge().GetValue(),
					}
				}
			}
		}
	}
	t.Fatalf("no %s series for profile %q", name, DefaultProfileName)
	return seriesValue{}
}

func TestSlotGuardWriteDurationObservedForHeaderSign(t *testing.T) {
	t.Parallel()
	const delay = 40 * time.Millisecond
	store := &faultyStore{MemWatermark: watermark.NewMemWatermark(), delay: delay}
	reg := prometheus.NewRegistry()
	a, spec := metricsHeaderAgent(t, store, reg)
	const name = "bursa_kesagent_slot_guard_write_duration_seconds"
	before := metricOf(t, reg, name)

	if _, err := a.SignHeader(5, spec.encode(t)); err != nil {
		t.Fatalf("SignHeader: %v", err)
	}

	h := metricOf(t, reg, name)
	if n := h.count - before.count; n != 1 {
		t.Fatalf("guard write samples for one header sign = %d, want 1", n)
	}
	if d := h.sum - before.sum; d < delay.Seconds() {
		t.Fatalf("guard write duration = %vs, want at least the store delay %vs",
			d, delay.Seconds())
	}
}

func TestSlotGuardStoreErrorsCountFailuresNotRefusals(t *testing.T) {
	t.Parallel()
	store := &faultyStore{MemWatermark: watermark.NewMemWatermark()}
	reg := prometheus.NewRegistry()
	a, spec := metricsHeaderAgent(t, store, reg)
	const name = "bursa_kesagent_slot_guard_store_errors_total"
	errCount := func() float64 {
		return metricOf(t, reg, name).value
	}
	if _, err := a.SignHeader(5, spec.encode(t)); err != nil {
		t.Fatalf("SignHeader: %v", err)
	}

	// A refusal is the guard working, not the store failing.
	spec.blockNumber = 2
	if _, err := a.SignHeader(5, spec.encode(t)); !errors.Is(
		err, ErrSlotEquivocation,
	) {
		t.Fatalf("different body for slot 52: want ErrSlotEquivocation, got %v", err)
	}
	if got := errCount(); got != 0 {
		t.Fatalf("store errors after a refusal = %v, want 0", got)
	}

	store.fail.Store(true)
	spec.slot = 53
	if _, err := a.SignHeader(5, spec.encode(t)); !errors.Is(
		err, errStoreUnreachable,
	) {
		t.Fatalf("SignHeader on failing store: want errStoreUnreachable, got %v", err)
	}
	if got := errCount(); got != 1 {
		t.Fatalf("store errors after a failing store = %v, want 1", got)
	}
}

func TestKeyInstallSetsLastPeriodAndIssueNumber(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	metricsHeaderAgent(t, &faultyStore{MemWatermark: watermark.NewMemWatermark()}, reg)

	// Start period 3 with 62 evolutions: the key's last period is 64.
	got := metricOf(t, reg, "bursa_kesagent_last_period").value
	if got != 64 {
		t.Errorf("last period = %v, want 64", got)
	}
	got = metricOf(t, reg, "bursa_kesagent_opcert_issue_number").value
	if got != 7 {
		t.Errorf("opcert issue number = %v, want 7", got)
	}
}

func TestLastSignTimestampSetBySuccessfulSignOnly(t *testing.T) {
	t.Parallel()
	store := &faultyStore{MemWatermark: watermark.NewMemWatermark()}
	reg := prometheus.NewRegistry()
	a, spec := metricsHeaderAgent(t, store, reg)
	const name = "bursa_kesagent_last_sign_timestamp_seconds"
	last := func() float64 {
		return metricOf(t, reg, name).value
	}
	if got := last(); got != 0 {
		t.Fatalf("last sign before any sign = %v, want 0", got)
	}

	store.fail.Store(true)
	if _, err := a.SignHeader(5, spec.encode(t)); err == nil {
		t.Fatal("SignHeader on failing store succeeded")
	}
	if got := last(); got != 0 {
		t.Fatalf("last sign after a failed sign = %v, want 0", got)
	}

	store.fail.Store(false)
	if _, err := a.SignHeader(5, spec.encode(t)); err != nil {
		t.Fatalf("SignHeader: %v", err)
	}
	if got, want := last(), float64(atPeriod(5).Unix()); got != want {
		t.Fatalf("last sign = %v, want %v", got, want)
	}
}
