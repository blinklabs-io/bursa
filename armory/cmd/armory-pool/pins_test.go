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
	"net/http"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/armory/device"
)

func TestPinsRequestPrintsProvisioningBody(t *testing.T) {
	t.Parallel()

	vrf, meta := strings.Repeat("11", 32), strings.Repeat("22", 32)

	var out bytes.Buffer

	args := []string{
		"pins-request", "-profile", profile, "-vrf-key-hash", vrf, "-metadata-hash", meta,
		"-pledge-min", "100", "-pledge-max", "1000", "-cost-max", "500", "-margin-max", "1/10",
	}

	if err := run(args, &out); err != nil {
		t.Fatal(err)
	}

	printed := bytes.Clone(out.Bytes())

	var req device.PinsRequest

	dec := json.NewDecoder(&out)
	dec.DisallowUnknownFields()

	if err := dec.Decode(&req); err != nil {
		t.Fatal(err)
	}

	want := device.PinsRequest{
		Profile: profile, VRFKeyHash: vrf, MetadataHash: meta,
		PledgeMin: 100, PledgeMax: 1000, CostMax: 500, MarginMaxNum: 1, MarginMaxDen: 10,
	}

	if req != want {
		t.Errorf("request %+v, want %+v", req, want)
	}

	// the device accepts the printed bytes unchanged
	r := newRig(t)

	res, err := http.Post(r.srv.URL+"/provision/pins", "application/json", bytes.NewReader(printed))
	if err != nil {
		t.Fatal(err)
	}

	defer res.Body.Close()

	var resp device.PinsResponse

	if res.StatusCode != http.StatusOK {
		t.Fatalf("device refused the printed request: %s", res.Status)
	}

	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil || resp.Pins != want {
		t.Errorf("device response %+v, %v", resp, err)
	}
}

func TestPinsRequestRefusesBadInput(t *testing.T) {
	t.Parallel()

	vrf := strings.Repeat("11", 32)
	ok := []string{
		"pins-request", "-profile", "p", "-vrf-key-hash", vrf, "-pledge-max", "5", "-margin-max", "1/10",
	}

	if err := run(ok, &bytes.Buffer{}); err != nil {
		t.Fatalf("valid request refused: %v", err)
	}

	for name, args := range map[string][]string{
		"no margin":        {"pins-request", "-profile", "p", "-vrf-key-hash", vrf},
		"margin above one": {"pins-request", "-profile", "p", "-vrf-key-hash", vrf, "-margin-max", "3/2"},
		"zero denominator": {"pins-request", "-profile", "p", "-vrf-key-hash", vrf, "-margin-max", "0/0"},
		"no vrf":           {"pins-request", "-profile", "p", "-margin-max", "1/2"},
		"pledge range":     {"pins-request", "-profile", "p", "-vrf-key-hash", vrf, "-margin-max", "1/2", "-pledge-min", "9", "-pledge-max", "1"},
		"extra argument":   append(append([]string{}, ok...), "x"),
		"short vrf":        {"pins-request", "-profile", "p", "-vrf-key-hash", vrf[2:], "-margin-max", "1/2"},
		"long vrf":         {"pins-request", "-profile", "p", "-vrf-key-hash", vrf + "11", "-margin-max", "1/2"},
		"non-hex vrf":      {"pins-request", "-profile", "p", "-vrf-key-hash", strings.Repeat("zz", 32), "-margin-max", "1/2"},
		"short metadata":   append(append([]string{}, ok...), "-metadata-hash", "22"),
		"non-hex metadata": append(append([]string{}, ok...), "-metadata-hash", strings.Repeat("g2", 32)),
	} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
