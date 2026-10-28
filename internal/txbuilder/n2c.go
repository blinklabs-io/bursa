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
	"fmt"
	"strconv"
	"strings"

	"github.com/blinklabs-io/bursa"
	ouroboros "github.com/blinklabs-io/gouroboros"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/conway"
	"github.com/blinklabs-io/gouroboros/ledger/shelley"
)

// N2CChain queries and submits through a node's local socket. Between Open
// and Close every query shares one connection, whose local state query
// client stays acquired on one ledger state, so a build sees UTxOs, protocol
// parameters, pool registrations and the slot from the same tip.
type N2CChain struct {
	socketPath string
	network    string
	conn       *ouroboros.Connection
	stop       func() bool
}

func NewN2C(socketPath, network string) *N2CChain {
	return &N2CChain{socketPath: socketPath, network: network}
}

// Open dials the node and keeps the connection for the following queries.
// The connection is closed when ctx ends, which unblocks a query the node
// never answers.
func (n *N2CChain) Open(ctx context.Context) error {
	if n.conn != nil {
		return errors.New("n2c: already open")
	}
	conn, err := n.dial(ctx)
	if err != nil {
		return err
	}
	n.conn = conn
	n.stop = context.AfterFunc(ctx, func() { _ = conn.Close() })
	return nil
}

// Close closes a connection made by Open.
func (n *N2CChain) Close() error {
	if n.conn == nil {
		return nil
	}
	n.stop()
	err := n.conn.Close()
	n.conn, n.stop = nil, nil
	return err
}

// session returns the open connection, or dials one for a single call when
// Open was not used.
func (n *N2CChain) session(ctx context.Context) (*ouroboros.Connection, func(), error) {
	if n.conn != nil {
		return n.conn, func() {}, nil
	}
	conn, err := n.dial(ctx)
	if err != nil {
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	return conn, func() { stop(); _ = conn.Close() }, nil
}

func (n *N2CChain) networkMagic() (uint32, error) {
	return networkMagic(n.network)
}

// networkMagic resolves a network name or a numeric magic. There is no
// default: a missing or unknown network is an error.
func networkMagic(network string) (uint32, error) {
	if network == "" {
		return 0, errors.New("network required")
	}
	if m, err := strconv.ParseUint(network, 10, 32); err == nil {
		return uint32(m), nil
	}
	if netw, ok := ouroboros.NetworkByName(network); ok {
		return netw.NetworkMagic, nil
	}
	return 0, fmt.Errorf("unknown network %q", network)
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
		// socketPath is a UNIX socket path, or host:port for a socket proxy.
		if strings.Contains(n.socketPath, ":") && !strings.Contains(n.socketPath, "/") {
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
	conn, release, err := n.session(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

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
	conn, release, err := n.session(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer release()

	pp, err := conn.LocalStateQuery().Client.GetCurrentProtocolParams()
	if err != nil {
		return nil, nil, err
	}
	return conwayParams(pp)
}

// conwayParams converts the node's current protocol parameters. Build only
// produces Conway transactions, so a node in any other era is an error.
func conwayParams(pp any) (*bursa.ProtocolParams, *ProtocolParametersExtra, error) {
	p, ok := pp.(*conway.ConwayProtocolParameters)
	if !ok {
		return nil, nil, fmt.Errorf("node is not in the Conway era (protocol parameters %T)", pp)
	}
	feeA := uint64(p.MinFeeA)
	feeB := uint64(p.MinFeeB)
	return &bursa.ProtocolParams{TxFeePerByte: feeA, TxFeeFixed: feeB},
		&ProtocolParametersExtra{
			MinFeeA:          feeA,
			MinFeeB:          feeB,
			KeyDeposit:       uint64(p.KeyDeposit),
			PoolDeposit:      uint64(p.PoolDeposit),
			MaxTxSize:        uint64(p.MaxTxSize),
			CoinsPerUTxOByte: p.AdaPerUtxoByte,
		}, nil
}

func (n *N2CChain) GetSlot(ctx context.Context) (uint64, error) {
	conn, release, err := n.session(ctx)
	if err != nil {
		return 0, err
	}
	defer release()
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
	conn, release, err := n.session(ctx)
	if err != nil {
		return false, err
	}
	defer release()
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
	conn, release, err := n.session(ctx)
	if err != nil {
		return err
	}
	defer release()
	if err := conn.LocalTxSubmission().Client.SubmitTx(conway.EraIdConway, tx); err != nil {
		return err
	}
	return nil
}
