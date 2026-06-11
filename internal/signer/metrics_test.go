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
