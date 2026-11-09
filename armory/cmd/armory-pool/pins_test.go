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
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/armory/device"
	"github.com/blinklabs-io/bursa/armory/policy"
	"github.com/blinklabs-io/gouroboros/ledger/common"
	fxcbor "github.com/fxamacker/cbor/v2"
)

func TestPinsRequestPrintsProvisioningBody(t *testing.T) {
	t.Parallel()

	vrf, meta := strings.Repeat("11", 32), strings.Repeat("22", 32)

	var out bytes.Buffer

	args := []string{
		"pins-request", "-profile", profile, "-vrf-key-hash", vrf, "-metadata-hash", meta,
		"-pledge-min", "100", "-pledge-max", "1000", "-cost-max", "500", "-margin-max", "1/10",
		"-metadata-url", "https://example.test/p.json",
		"-relay", "1.2.3.4,[2001:db8::1]:3001", "-relay", "relay.example:3002", "-relay", "srv:_cardano._tcp.example",
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

	// the digest is the one the device computes from a registration naming
	// those relays and that URL
	digest := registrationDigest(t, []any{
		[]any{
			uint64(0),
			uint64(3001),
			[]byte{1, 2, 3, 4},
			net.ParseIP("2001:db8::1").To16(),
		},
		[]any{uint64(1), uint64(3002), "relay.example"},
		[]any{uint64(2), "_cardano._tcp.example"},
	}, "https://example.test/p.json")

	want := device.PinsRequest{
		Profile: profile, VRFKeyHash: vrf, MetadataHash: meta,
		PledgeMin: 100, PledgeMax: 1000, CostMax: 500, MarginMaxNum: 1, MarginMaxDen: 10,
		RelaysDigest: digest,
	}

	if !reflect.DeepEqual(req, want) {
		t.Errorf("request %+v, want %+v", req, want)
	}

	// the device accepts the printed bytes unchanged
	r := newRig(t)

	res, err := http.Post(
		r.srv.URL+"/provision/pins",
		"application/json",
		bytes.NewReader(printed),
	)
	if err != nil {
		t.Fatal(err)
	}

	defer res.Body.Close()

	var resp device.PinsResponse

	if res.StatusCode != http.StatusOK {
		t.Fatalf("device refused the printed request: %s", res.Status)
	}

	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil ||
		!reflect.DeepEqual(resp.Pins, want) {
		t.Errorf("device response %+v, %v", resp, err)
	}
}

// registrationDigest decodes a pool registration carrying relays and a
// metadata URL, as the device does, and returns its relays digest in hex.
func registrationDigest(t *testing.T, relays []any, url string) string {
	t.Helper()

	reward := append([]byte{0xe0}, make([]byte, 28)...)
	raw, err := fxcbor.Marshal([]any{
		uint64(3), make([]byte, 28), make([]byte, 32), uint64(1), uint64(1),
		fxcbor.Tag{Number: 30, Content: []uint64{1, 100}},
		reward, []any{make([]byte, 28)}, relays, []any{url, make([]byte, 32)},
	})
	if err != nil {
		t.Fatal(err)
	}

	var cert common.PoolRegistrationCertificate
	if err := cert.UnmarshalCBOR(raw); err != nil {
		t.Fatal(err)
	}

	d, err := policy.RelaysDigest(cert.Relays, &cert.PoolMetadata.Url)
	if err != nil {
		t.Fatal(err)
	}

	return hex.EncodeToString(d[:])
}

func TestPinsRequestRefusesBadInput(t *testing.T) {
	t.Parallel()

	vrf := strings.Repeat("11", 32)
	ok := []string{
		"pins-request", "-profile", "p", "-vrf-key-hash", vrf, "-pledge-max", "5", "-margin-max", "1/10",
	}

	withMeta := append(
		append([]string{}, ok...),
		"-metadata-hash",
		strings.Repeat("22", 32),
		"-metadata-url",
		"https://example.test/p.json",
	)

	for _, args := range [][]string{ok, withMeta, append(append([]string{}, ok...), "-relay", "[::1]:1", "-relay", "srv:x.example")} {
		if err := run(args, &bytes.Buffer{}); err != nil {
			t.Fatalf("valid request %q refused: %v", args, err)
		}
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
		"short metadata":   append(append([]string{}, ok...), "-metadata-hash", "22", "-metadata-url", "u"),
		"non-hex metadata": append(append([]string{}, ok...), "-metadata-hash", strings.Repeat("g2", 32), "-metadata-url", "u"),
		"metadata no url":  append(append([]string{}, ok...), "-metadata-hash", strings.Repeat("22", 32)),
		"url no metadata":  append(append([]string{}, ok...), "-metadata-url", "u"),
		"relay no port":    append(append([]string{}, ok...), "-relay", "relay.example"),
		"relay bad port":   append(append([]string{}, ok...), "-relay", "relay.example:65536"),
		"bare ipv6 relay":  append(append([]string{}, ok...), "-relay", "::1:3001"),
		"two ipv4 relay":   append(append([]string{}, ok...), "-relay", "1.2.3.4,5.6.7.8:1"),
		"bracketed ipv4":   append(append([]string{}, ok...), "-relay", "[1.2.3.4]:1"),
		"empty srv relay":  append(append([]string{}, ok...), "-relay", "srv:"),
	} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// -unpinned-relays prints pins without relays or metadata, which the device
// stores as such, and refuses relays or metadata given with it.
func TestPinsRequestUnpinnedRelays(t *testing.T) {
	t.Parallel()

	vrf := strings.Repeat("11", 32)
	base := []string{
		"pins-request", "-profile", profile, "-vrf-key-hash", vrf, "-unpinned-relays",
		"-pledge-max", "1000", "-cost-max", "500", "-margin-max", "1/10",
	}

	var out bytes.Buffer

	if err := run(base, &out); err != nil {
		t.Fatal(err)
	}

	printed := bytes.Clone(out.Bytes())

	var req device.PinsRequest
	if err := json.Unmarshal(printed, &req); err != nil {
		t.Fatal(err)
	}

	if req.RelaysDigest != "" || req.MetadataHash != "" {
		t.Fatalf("request %s pins relays or metadata", printed)
	}

	r := newRig(t)

	res, err := http.Post(
		r.srv.URL+"/provision/pins",
		"application/json",
		bytes.NewReader(printed),
	)
	if err != nil {
		t.Fatal(err)
	}

	res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("device refused the printed request: %s", res.Status)
	}

	for name, extra := range map[string][]string{
		"relay":         {"-relay", "relay.example:3001"},
		"metadata hash": {"-metadata-hash", strings.Repeat("22", 32), "-metadata-url", "https://example.test/p.json"},
		"metadata url":  {"-metadata-url", "https://example.test/p.json"},
	} {
		if err := run(append(append([]string{}, base...), extra...), &bytes.Buffer{}); err == nil {
			t.Errorf("%s with -unpinned-relays accepted", name)
		}
	}
}
