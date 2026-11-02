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
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/blinklabs-io/bursa/armory/device"
	"github.com/blinklabs-io/bursa/armory/policy"
	"github.com/blinklabs-io/gouroboros/ledger/common"
)

// pinsRequest parses the `pins-request` flags and prints the
// /provision/pins request body they describe. Nothing is sent: the
// provisioning image takes the request, as with host-key.
func pinsRequest(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("pins-request", flag.ContinueOnError)
	name := fs.String("profile", "", "device profile the pins belong to")
	vrf := fs.String("vrf-key-hash", "", "VRF key hash (32 bytes, hex)")
	meta := fs.String("metadata-hash", "", "pool metadata hash (32 bytes, hex); empty pins no metadata")
	pledgeMin := fs.Uint64("pledge-min", 0, "lowest pledge, in lovelace")
	pledgeMax := fs.Uint64("pledge-max", 0, "highest pledge, in lovelace")
	costMax := fs.Uint64("cost-max", 0, "highest fixed cost, in lovelace")
	marginMax := fs.String("margin-max", "", "highest margin as N/D, e.g. 1/10")
	metaURL := fs.String("metadata-url", "", "pool metadata URL; required with -metadata-hash")

	var relays []common.PoolRelay

	fs.Func("relay", "a registration relay, repeated in registration order: HOST:PORT, IPV4:PORT, [IPV6]:PORT, IPV4,[IPV6]:PORT or srv:NAME", func(v string) error {
		r, err := parseRelay(v)
		if err == nil {
			relays = append(relays, r)
		}

		return err
	})

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	num, den, ok := strings.Cut(*marginMax, "/")

	n, errN := strconv.ParseUint(num, 10, 64)
	d, errD := strconv.ParseUint(den, 10, 64)

	if !ok || errN != nil || errD != nil || d == 0 || n > d {
		return errors.New("-margin-max must be N/D with 0 <= N/D <= 1")
	}

	if *name == "" || *vrf == "" || *pledgeMax < *pledgeMin {
		return errors.New("-profile and -vrf-key-hash are required, and -pledge-max must not be below -pledge-min")
	}

	if err := checkHash32("-vrf-key-hash", *vrf); err != nil {
		return err
	}

	var url *string

	if *meta != "" {
		if err := checkHash32("-metadata-hash", *meta); err != nil {
			return err
		}

		if *metaURL == "" {
			return errors.New("-metadata-url is required with -metadata-hash")
		}

		url = metaURL
	} else if *metaURL != "" {
		return errors.New("-metadata-url needs -metadata-hash")
	}

	digest, err := policy.RelaysDigest(relays, url)
	if err != nil {
		return fmt.Errorf("relays: %w", err)
	}

	req, err := json.Marshal(device.PinsRequest{
		Profile: *name, VRFKeyHash: *vrf, MetadataHash: *meta,
		PledgeMin: *pledgeMin, PledgeMax: *pledgeMax, CostMax: *costMax,
		MarginMaxNum: n, MarginMaxDen: d, RelaysDigest: hex.EncodeToString(digest[:]),
	})
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(out, "%s\n", req)

	return err
}

// checkHash32 refuses a hash the device would refuse: anything but 32 bytes
// of hex.
func checkHash32(flagName, v string) error {
	if b, err := hex.DecodeString(v); err != nil || len(b) != 32 {
		return fmt.Errorf("%s must be 32 bytes of hex", flagName)
	}

	return nil
}

// parseRelay reads one -relay value: srv:NAME is a multi-host (DNS SRV)
// relay; otherwise the value ends in :PORT and names either one host or one
// or two addresses (an IPv4 and an IPv6, comma separated, IPv6 in brackets).
func parseRelay(v string) (common.PoolRelay, error) {
	bad := fmt.Errorf("relay %q: want HOST:PORT, IPV4:PORT, [IPV6]:PORT, IPV4,[IPV6]:PORT or srv:NAME", v)

	if srv, ok := strings.CutPrefix(v, "srv:"); ok {
		if srv == "" {
			return common.PoolRelay{}, bad
		}

		return common.PoolRelay{Type: common.PoolRelayTypeMultiHostName, Hostname: &srv}, nil
	}

	i := strings.LastIndexByte(v, ':')
	if i <= 0 {
		return common.PoolRelay{}, bad
	}

	port64, err := strconv.ParseUint(v[i+1:], 10, 16)
	if err != nil {
		return common.PoolRelay{}, bad
	}

	port := uint32(port64)
	host := v[:i]

	if !strings.ContainsAny(host, ",[]") && net.ParseIP(host) == nil {
		return common.PoolRelay{Type: common.PoolRelayTypeSingleHostName, Port: &port, Hostname: &host}, nil
	}

	r := common.PoolRelay{Type: common.PoolRelayTypeSingleHostAddress, Port: &port}

	for _, a := range strings.Split(host, ",") {
		v6, bracketed := strings.CutPrefix(a, "[")
		v6, closed := strings.CutSuffix(v6, "]")
		ip := net.ParseIP(v6)

		switch {
		case ip == nil || bracketed != closed:
			return common.PoolRelay{}, bad
		case ip.To4() != nil && !bracketed && r.Ipv4 == nil:
			r.Ipv4 = &ip
		case ip.To4() == nil && bracketed && r.Ipv6 == nil:
			r.Ipv6 = &ip
		default:
			return common.PoolRelay{}, bad
		}
	}

	return r, nil
}
