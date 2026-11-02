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

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/armory/device"
)

func TestPinsRequestPrintsProvisioningBody(t *testing.T) {
	t.Parallel()

	vrf, meta := strings.Repeat("11", 32), strings.Repeat("22", 32)

	var out bytes.Buffer

	args := []string{
		"pins-request", "-profile", "otg@preview", "-vrf-key-hash", vrf, "-metadata-hash", meta,
		"-pledge-min", "100", "-pledge-max", "1000", "-cost-max", "500", "-margin-max", "1/10",
	}

	if err := run(args, &out); err != nil {
		t.Fatal(err)
	}

	var req device.PinsRequest

	dec := json.NewDecoder(&out)
	dec.DisallowUnknownFields()

	if err := dec.Decode(&req); err != nil {
		t.Fatal(err)
	}

	want := device.PinsRequest{
		Profile: "otg@preview", VRFKeyHash: vrf, MetadataHash: meta,
		PledgeMin: 100, PledgeMax: 1000, CostMax: 500, MarginMaxNum: 1, MarginMaxDen: 10,
	}

	if req != want {
		t.Errorf("request %+v, want %+v", req, want)
	}

	// the device accepts the printed request unchanged
	r := newRig(t)

	var resp device.PinsResponse

	body, _ := json.Marshal(want)
	body = bytes.Replace(body, []byte("otg@preview"), []byte(profile), 1)
	devicePost(t, r.srv, "/provision/pins", json.RawMessage(body), &resp)

	if resp.Pins.PledgeMax != 1000 {
		t.Errorf("device response %+v", resp)
	}
}

func TestPinsRequestRefusesBadInput(t *testing.T) {
	t.Parallel()

	ok := []string{
		"pins-request", "-profile", "p", "-vrf-key-hash", "11", "-pledge-max", "5", "-margin-max", "1/10",
	}

	if err := run(ok, &bytes.Buffer{}); err != nil {
		t.Fatalf("valid request refused: %v", err)
	}

	for name, args := range map[string][]string{
		"no margin":        {"pins-request", "-profile", "p", "-vrf-key-hash", "11"},
		"margin above one": {"pins-request", "-profile", "p", "-vrf-key-hash", "11", "-margin-max", "3/2"},
		"zero denominator": {"pins-request", "-profile", "p", "-vrf-key-hash", "11", "-margin-max", "0/0"},
		"no vrf":           {"pins-request", "-profile", "p", "-margin-max", "1/2"},
		"pledge range":     {"pins-request", "-profile", "p", "-vrf-key-hash", "11", "-margin-max", "1/2", "-pledge-min", "9", "-pledge-max", "1"},
		"extra argument":   append(append([]string{}, ok...), "x"),
	} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
