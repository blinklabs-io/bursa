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
var ErrInvalidHeader = errors.New("kesagent: sign request is not a matching Praos header body")

// checkHeaderLocked verifies that msg is a Babbage/Conway header body (the
// Praos eras) for the requested KES period whose operational certificate
// matches the active key. Caller must hold a.mu with a.active set.
func (a *Agent) checkHeaderLocked(period uint64, msg []byte) error {
	var hb babbage.BabbageBlockHeaderBody
	n, err := cbor.Decode(msg, &hb)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidHeader, err)
	}
	if n != len(msg) {
		return fmt.Errorf("%w: %d trailing bytes", ErrInvalidHeader, len(msg)-n)
	}
	if got := hb.Slot / a.cfg.SlotsPerKESPeriod; got != period {
		return fmt.Errorf("%w: slot %d is in KES period %d, requested %d", ErrInvalidHeader, hb.Slot, got, period)
	}
	if !bytes.Equal(hb.IssuerVkey[:], a.cfg.ColdVKey) {
		return fmt.Errorf("%w: issuer key is not this pool's cold key", ErrInvalidHeader)
	}
	oc := hb.OpCert
	if !bytes.Equal(oc.HotVkey, a.active.vkey) {
		return fmt.Errorf("%w: operational certificate names a different KES key", ErrInvalidHeader)
	}
	if oc.SequenceNumber != a.active.issueNumber || oc.KesPeriod != a.active.startPeriod {
		return fmt.Errorf("%w: operational certificate counter/period do not match the installed one", ErrInvalidHeader)
	}
	return nil
}
