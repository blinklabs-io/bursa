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

package txbuilder

import (
	"context"

	"github.com/blinklabs-io/bursa"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

type UTxO struct {
	Input  lcommon.TransactionInput
	Output lcommon.TransactionOutput
}

type ProtocolParametersExtra struct {
	MinFeeA                  uint64
	MinFeeB                  uint64
	KeyDeposit               uint64
	PoolDeposit              uint64
	MaxTxSize                uint64
	PoolRetirementEpochBound uint64
}

// Chain provides the node/ledger queries and submission needed to build and submit transactions.
type Chain interface {
	GetUTxOs(ctx context.Context, address string) ([]UTxO, error)
	GetProtocolParameters(ctx context.Context) (*bursa.ProtocolParams, *ProtocolParametersExtra, error)
	GetSlot(ctx context.Context) (uint64, error)
	GetPoolRegistration(ctx context.Context, poolKeyHash []byte) (bool, error)
	SubmitTx(ctx context.Context, tx []byte) error
}
