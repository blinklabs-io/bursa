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
	"strconv"
	"strings"

	"github.com/blinklabs-io/bursa/armory/device"
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

	if *meta != "" {
		if err := checkHash32("-metadata-hash", *meta); err != nil {
			return err
		}
	}

	req, err := json.Marshal(device.PinsRequest{
		Profile: *name, VRFKeyHash: *vrf, MetadataHash: *meta,
		PledgeMin: *pledgeMin, PledgeMax: *pledgeMax, CostMax: *costMax,
		MarginMaxNum: n, MarginMaxDen: d,
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
