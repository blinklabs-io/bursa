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

package operation

import (
	"encoding/hex"
	"fmt"

	"github.com/blinklabs-io/bursa"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// Cardano is the subset of the bursa toolkit the coordinator needs. It is an
// interface so the coordinator can be tested with a fake.
type Cardano interface {
	// Inspect decodes a transaction into its structured summary.
	Inspect(txCbor []byte) (*bursa.TxInspection, error)
	// TxID returns the 32-byte transaction id (the witness signing message).
	TxID(txCbor []byte) ([]byte, error)
	// Assemble merges vkey witnesses into a transaction, preserving the body.
	Assemble(txCbor []byte, wits []lcommon.VkeyWitness) ([]byte, error)
}

// BursaCardano is the production adapter backed by the bursa toolkit.
type BursaCardano struct{}

func (BursaCardano) Inspect(txCbor []byte) (*bursa.TxInspection, error) {
	return bursa.InspectTransaction(txCbor)
}

func (BursaCardano) TxID(txCbor []byte) ([]byte, error) {
	idHex, err := bursa.TransactionID(txCbor)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(idHex)
	if err != nil {
		return nil, fmt.Errorf("decode tx id: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("transaction id must be 32 bytes, got %d", len(raw))
	}
	return raw, nil
}

func (BursaCardano) Assemble(txCbor []byte, wits []lcommon.VkeyWitness) ([]byte, error) {
	return bursa.AssembleTransaction(txCbor, wits)
}
