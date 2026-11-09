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
	_ "embed"
	"encoding/hex"
	"strings"

	"github.com/blinklabs-io/gouroboros/ledger"
)

// A preview pool registration transaction (public chain data).
//
//go:embed testdata/conway-tx.hex
var selfTestTxHex string

const selfTestTxHash = "b7afc623dd5d207914afee7dd00b7835489099cf7eacf72d6506bc53e620101e"

// selfTestLedger proves transaction decoding works on the device before any
// signing policy depends on it.
func selfTestLedger(r *Report) bool {
	b, err := hex.DecodeString(strings.TrimSpace(selfTestTxHex))

	if err != nil {
		r.Logf("ledger: fixture: %v", err)
		return false
	}

	tx, err := ledger.NewTransactionFromCbor(ledger.TxTypeConway, b)

	if err != nil {
		r.Logf("ledger: decode: %v", err)
		return false
	}

	if h := tx.Hash().String(); h != selfTestTxHash {
		r.Logf("ledger: hash mismatch %s", h)
		return false
	}

	r.Logf("ledger: decoded conway tx %s", selfTestTxHash)

	return true
}
