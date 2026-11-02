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
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/blinklabs-io/bursa"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/shelley"
	"github.com/blinklabs-io/plutigo/data"
	utxorpc "github.com/utxorpc/go-codegen/utxorpc/v1alpha/cardano"
)

type fakeOutput struct {
	address  lcommon.Address
	lovelace uint64
}

func (o *fakeOutput) Address() lcommon.Address                                  { return o.address }
func (o *fakeOutput) Amount() *big.Int                                          { return new(big.Int).SetUint64(o.lovelace) }
func (o *fakeOutput) Assets() *lcommon.MultiAsset[lcommon.MultiAssetTypeOutput] { return nil }
func (o *fakeOutput) Datum() *lcommon.Datum                                     { return nil }
func (o *fakeOutput) DatumHash() *lcommon.Blake2b256                            { return nil }
func (o *fakeOutput) Cbor() []byte                                              { return nil }
func (o *fakeOutput) Utxorpc() (*utxorpc.TxOutput, error)                       { return nil, nil }
func (o *fakeOutput) ScriptRef() lcommon.Script                                 { return nil }
func (o *fakeOutput) ToPlutusData() data.PlutusData                             { return nil }
func (o *fakeOutput) String() string                                            { return o.address.String() }

type FakeChain struct {
	UtxosMap           map[string][]UTxO
	PpFee              *bursa.ProtocolParams
	PpExtra            *ProtocolParametersExtra
	PpErr              error
	SlotVal            uint64
	PoolRegistered     map[string]bool
	StakeDelegDeposits map[StakeCredentialKey]uint64
	SubmitErr          error
	Submitted          [][]byte
	PoolRegistration   func(poolKeyHash []byte) (bool, error)
}

func NewFakeChain() *FakeChain {
	return &FakeChain{
		UtxosMap:           map[string][]UTxO{},
		PpFee:              &bursa.ProtocolParams{TxFeePerByte: 44, TxFeeFixed: 155381},
		PpExtra:            &ProtocolParametersExtra{MinFeeA: 44, MinFeeB: 155381, KeyDeposit: 2000000, PoolDeposit: 500000000},
		SlotVal:            1000000,
		PoolRegistered:     map[string]bool{},
		StakeDelegDeposits: map[StakeCredentialKey]uint64{},
		Submitted:          [][]byte{},
	}
}

func (f *FakeChain) GetUTxOs(ctx context.Context, address string) ([]UTxO, error) {
	return f.UtxosMap[address], nil
}

func (f *FakeChain) GetProtocolParameters(ctx context.Context) (*bursa.ProtocolParams, *ProtocolParametersExtra, error) {
	if f.PpErr != nil {
		return nil, nil, f.PpErr
	}
	return f.PpFee, f.PpExtra, nil
}

func (f *FakeChain) GetSlot(ctx context.Context) (uint64, error) {
	return f.SlotVal, nil
}

func (f *FakeChain) GetPoolRegistration(ctx context.Context, poolKeyHash []byte) (bool, error) {
	if f.PoolRegistration != nil {
		return f.PoolRegistration(poolKeyHash)
	}
	key := hex.EncodeToString(poolKeyHash)
	if v, ok := f.PoolRegistered[key]; ok {
		return v, nil
	}
	return false, nil
}

func (f *FakeChain) GetStakeDelegDeposits(ctx context.Context, creds []lcommon.Credential) (map[StakeCredentialKey]uint64, error) {
	out := make(map[StakeCredentialKey]uint64, len(creds))
	for _, c := range creds {
		key := StakeCredentialKeyFrom(c)
		if deposit, ok := f.StakeDelegDeposits[key]; ok {
			out[key] = deposit
		}
	}
	return out, nil
}

func (f *FakeChain) SubmitTx(ctx context.Context, tx []byte) error {
	if f.SubmitErr != nil {
		return f.SubmitErr
	}
	cp := make([]byte, len(tx))
	copy(cp, tx)
	f.Submitted = append(f.Submitted, cp)
	return nil
}

func MakeUTxO(addr string, txHashHex string, idx uint32, lovelace uint64) UTxO {
	var txID lcommon.Blake2b256
	b, _ := hex.DecodeString(txHashHex)
	copy(txID[:], b)
	input := shelley.ShelleyTransactionInput{TxId: txID, OutputIndex: idx}
	a, _ := lcommon.NewAddress(addr)
	return UTxO{
		Input:  input,
		Output: &fakeOutput{address: a, lovelace: lovelace},
	}
}

var _ Chain = (*FakeChain)(nil)
var _ = errors.New
