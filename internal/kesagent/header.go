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
	"bytes"
	"errors"
	"fmt"

	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/ledger/babbage"
)

// ErrInvalidHeader is returned when a sign request is not a block header body
// matching the agent's installed key and operational certificate.
var ErrInvalidHeader = errors.New(
	"kesagent: sign request is not a matching Praos header body",
)

// checkHeaderLocked verifies that msg is a Babbage/Conway header body (the
// Praos eras) for the requested KES period whose operational certificate
// matches the active key, and returns the header's absolute slot. Caller must
// hold p.mu with p.active set.
func (p *profile) checkHeaderLocked(period uint64, msg []byte) (uint64, error) {
	var hb babbage.BabbageBlockHeaderBody
	n, err := cbor.Decode(msg, &hb)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrInvalidHeader, err)
	}
	if n != len(msg) {
		return 0, fmt.Errorf("%w: %d trailing bytes", ErrInvalidHeader, len(msg)-n)
	}
	if got := hb.Slot / p.cfg.SlotsPerKESPeriod; got != period {
		return 0, fmt.Errorf(
			"%w: slot %d is in KES period %d, requested %d",
			ErrInvalidHeader,
			hb.Slot,
			got,
			period,
		)
	}
	if !bytes.Equal(hb.IssuerVkey[:], p.cfg.ColdVKey) {
		return 0, fmt.Errorf(
			"%w: issuer key is not this pool's cold key",
			ErrInvalidHeader,
		)
	}
	oc := hb.OpCert
	if !bytes.Equal(oc.HotVkey, p.active.vkey) {
		return 0, fmt.Errorf(
			"%w: operational certificate names a different KES key",
			ErrInvalidHeader,
		)
	}
	if oc.SequenceNumber != p.active.issueNumber ||
		oc.KesPeriod != p.active.startPeriod {
		return 0, fmt.Errorf(
			"%w: operational certificate counter/period do not match the installed one",
			ErrInvalidHeader,
		)
	}
	if !bytes.Equal(oc.Signature, p.active.coldSig) {
		return 0, fmt.Errorf(
			"%w: operational certificate cold signature is not the installed one",
			ErrInvalidHeader,
		)
	}
	return hb.Slot, nil
}
