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
	"errors"
	"strconv"
	"strings"

	"github.com/blinklabs-io/bursa"
	ouroboros "github.com/blinklabs-io/gouroboros"
	"github.com/blinklabs-io/gouroboros/ledger"
	"github.com/blinklabs-io/gouroboros/ledger/babbage"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/conway"
	"github.com/blinklabs-io/gouroboros/ledger/dijkstra"
	"github.com/blinklabs-io/gouroboros/ledger/shelley"
)

type N2CChain struct {
	socketPath string
	network    string
	conn       *ouroboros.Connection
	era        uint16 // store era if needed
}

func NewN2C(socketPath, network string) *N2CChain {
	return &N2CChain{socketPath: socketPath, network: network}
}

func (n *N2CChain) networkMagic() (uint32, error) {
	const mainnetMagic = 764824073
	if n.network == "" {
		return mainnetMagic, nil
	}
	if m, err := strconv.ParseUint(n.network, 10, 32); err == nil {
		return uint32(m), nil
	}
	if netw, ok := ouroboros.NetworkByName(n.network); ok {
		return netw.NetworkMagic, nil
	}
	if strings.EqualFold(n.network, "testnet") || n.network == "preprod" || n.network == "preview" || n.network == "sanchonet" {
		if netw, ok := ouroboros.NetworkByName(n.network); ok {
			return netw.NetworkMagic, nil
		}
		// Try common names
	}
	// Unknown network name is an error, never default to mainnet
	return 0, errors.New("unknown network")
}

func (n *N2CChain) dial(ctx context.Context) (*ouroboros.Connection, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	magic, err := n.networkMagic()
	if err != nil {
		return nil, err
	}
	conn, err := ouroboros.NewConnection(
		ouroboros.WithNetworkMagic(magic),
		ouroboros.WithNodeToNode(false),
	)
	if err != nil {
		return nil, err
	}
	var dialErr error
	done := make(chan error, 1)
	go func() {
		// socketPath may be a UNIX socket path (contains "/") or a host:port for a proxy.
		if strings.Contains(n.socketPath, "/") {
			dialErr = conn.Dial("unix", n.socketPath)
		} else if strings.Contains(n.socketPath, ":") {
			dialErr = conn.Dial("tcp", n.socketPath)
		} else {
			dialErr = conn.Dial("unix", n.socketPath)
		}
		done <- dialErr
	}()
	select {
	case <-ctx.Done():
		_ = conn.Close()
		return nil, ctx.Err()
	case err := <-done:
		if err != nil {
			return nil, err
		}
	}
	return conn, nil
}

func (n *N2CChain) GetUTxOs(ctx context.Context, address string) ([]UTxO, error) {
	conn, err := n.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	addr, err := lcommon.NewAddress(address)
	if err != nil {
		return nil, err
	}
	res, err := conn.LocalStateQuery().Client.GetUTxOByAddress([]lcommon.Address{addr})
	if err != nil {
		return nil, err
	}
	if res == nil {
		return []UTxO{}, nil
	}
	result := make([]UTxO, 0, len(res.Results))
	for id, out := range res.Results {
		input := shelley.ShelleyTransactionInput{
			TxId:        id.Hash,
			OutputIndex: uint32(id.Idx),
		}
		result = append(result, UTxO{
			Input:  input,
			Output: out,
		})
	}
	return result, nil
}

func (n *N2CChain) GetProtocolParameters(ctx context.Context) (*bursa.ProtocolParams, *ProtocolParametersExtra, error) {
	conn, err := n.dial(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	pp, err := conn.LocalStateQuery().Client.GetCurrentProtocolParams()
	if err != nil {
		return nil, nil, err
	}

	switch p := pp.(type) {
	case *conway.ConwayProtocolParameters:
		feeA := uint64(p.MinFeeA)
		feeB := uint64(p.MinFeeB)
		extra := &ProtocolParametersExtra{
			MinFeeA:          feeA,
			MinFeeB:          feeB,
			KeyDeposit:       uint64(p.KeyDeposit),
			PoolDeposit:      uint64(p.PoolDeposit),
			MaxTxSize:        uint64(p.MaxTxSize),
			CoinsPerUTxOByte: p.AdaPerUtxoByte,
		}
		return &bursa.ProtocolParams{
			TxFeePerByte: feeA,
			TxFeeFixed:   feeB,
		}, extra, nil
	case *dijkstra.DijkstraProtocolParameters:
		feeA := uint64(p.MinFeeA)
		feeB := uint64(p.MinFeeB)
		extra := &ProtocolParametersExtra{
			MinFeeA:          feeA,
			MinFeeB:          feeB,
			KeyDeposit:       uint64(p.KeyDeposit),
			PoolDeposit:      uint64(p.PoolDeposit),
			MaxTxSize:        uint64(p.MaxTxSize),
			CoinsPerUTxOByte: p.AdaPerUtxoByte,
		}
		return &bursa.ProtocolParams{
			TxFeePerByte: feeA,
			TxFeeFixed:   feeB,
		}, extra, nil
	case *babbage.BabbageProtocolParameters:
		feeA := uint64(p.MinFeeA)
		feeB := uint64(p.MinFeeB)
		extra := &ProtocolParametersExtra{
			MinFeeA:          feeA,
			MinFeeB:          feeB,
			KeyDeposit:       uint64(p.KeyDeposit),
			PoolDeposit:      uint64(p.PoolDeposit),
			MaxTxSize:        uint64(p.MaxTxSize),
			CoinsPerUTxOByte: p.AdaPerUtxoByte,
		}
		return &bursa.ProtocolParams{TxFeePerByte: feeA, TxFeeFixed: feeB}, extra, nil
	}
	return nil, nil, errors.New("unsupported protocol parameters era")
}

func (n *N2CChain) GetSlot(ctx context.Context) (uint64, error) {
	conn, err := n.dial(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	pt, err := conn.LocalStateQuery().Client.GetChainPoint()
	if err != nil {
		return 0, err
	}
	if pt == nil {
		return 0, errors.New("no chain point")
	}
	return pt.Slot, nil
}

func (n *N2CChain) GetPoolRegistration(ctx context.Context, poolKeyHash []byte) (bool, error) {
	conn, err := n.dial(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	poolId := lcommon.PoolId(poolKeyHash)
	params, err := conn.LocalStateQuery().Client.GetStakePoolParams([]lcommon.PoolId{poolId})
	if err != nil {
		return false, err
	}
	if params != nil {
		if _, ok := params.Results[poolId]; ok {
			return true, nil
		}
	}
	return false, nil
}

func (n *N2CChain) SubmitTx(ctx context.Context, tx []byte) error {
	conn, err := n.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.LocalTxSubmission().Client.SubmitTx(uint16(ledger.TxTypeConway), tx); err != nil {
		return err
	}
	return nil
}
