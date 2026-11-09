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

	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/protocol/localstatequery"
)

// QueryPool queries pool information. The result is assembled by
// poolQueryFromState; this method only runs the queries.
func (n *N2CChain) QueryPool(
	ctx context.Context,
	poolID lcommon.PoolId,
	network string,
) (*PoolQueryResult, error) {
	conn, release, err := n.session(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	client := conn.LocalStateQuery().Client
	poolState, err := client.GetPoolState([]any{poolID})
	if err != nil {
		return nil, err
	}
	counters, err := client.GetOpCertCounters()
	if err != nil {
		return nil, err
	}
	chainPoint, err := client.GetChainPoint()
	if err != nil {
		return nil, err
	}
	if chainPoint == nil {
		return nil, errors.New("no chain point")
	}
	genesisConfig, err := client.GetGenesisConfig()
	if err != nil {
		return nil, err
	}
	if genesisConfig == nil {
		return nil, errors.New("no genesis config")
	}
	epoch, err := client.GetEpochNo()
	if err != nil {
		return nil, err
	}
	return poolQueryFromState(
		poolID,
		poolState,
		counters,
		chainPoint.Slot,
		genesisConfig.SlotsPerKESPeriod,
		genesisConfig.MaxKESEvolutions,
		epoch,
		network,
	)
}

// QueryStakeAddress queries stake address information. Only reward (stake)
// addresses are accepted: a payment address would silently answer for its
// stake part.
func (n *N2CChain) QueryStakeAddress(
	ctx context.Context,
	address string,
	network string,
) (*StakeAddressQueryResult, error) {
	addr, err := ParseRewardAddress(address, network)
	if err != nil {
		return nil, err
	}
	cred, err := addr.RewardAccountCredential()
	if err != nil {
		return nil, err
	}
	conn, release, err := n.session(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	client := conn.LocalStateQuery().Client
	lsCred := stakeCredentialFrom(cred)
	deposits, err := client.GetStakeDelegDeposits(
		[]localstatequery.StakeCredential{lsCred},
	)
	if err != nil {
		return nil, err
	}
	delegRewards, err := client.GetFilteredDelegationsAndRewardAccounts(
		[]localstatequery.StakeCredential{lsCred},
	)
	if err != nil {
		return nil, err
	}
	drepDelegs, err := client.GetFilteredVoteDelegatees(
		[]lcommon.Credential{cred},
	)
	if err != nil {
		return nil, err
	}
	return stakeQueryFrom(lsCred, deposits, delegRewards, drepDelegs), nil
}

// QueryUTxOs queries UTxOs for an address, sorted by tx id then index.
func (n *N2CChain) QueryUTxOs(
	ctx context.Context,
	address string,
) ([]UTxOQueryResult, error) {
	addr, err := lcommon.NewAddress(address)
	if err != nil {
		return nil, err
	}
	conn, release, err := n.session(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	res, err := conn.LocalStateQuery().Client.GetUTxOByAddress(
		[]lcommon.Address{addr},
	)
	if err != nil {
		return nil, err
	}
	return utxoQueryFrom(res)
}

// QueryTip queries chain tip information.
func (n *N2CChain) QueryTip(ctx context.Context) (*TipQueryResult, error) {
	conn, release, err := n.session(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	client := conn.LocalStateQuery().Client
	chainPoint, err := client.GetChainPoint()
	if err != nil {
		return nil, err
	}
	if chainPoint == nil {
		return nil, errors.New("no chain point")
	}
	epoch, err := client.GetEpochNo()
	if err != nil {
		return nil, err
	}
	blockNumber, err := client.GetChainBlockNo()
	if err != nil {
		return nil, err
	}
	eraID, err := client.GetCurrentEra()
	if err != nil {
		return nil, err
	}
	genesisConfig, err := client.GetGenesisConfig()
	if err != nil {
		return nil, err
	}
	if genesisConfig == nil {
		return nil, errors.New("no genesis config")
	}
	return tipQueryFrom(
		eraID,
		epoch,
		blockNumber,
		chainPoint.Slot,
		genesisConfig.SlotsPerKESPeriod,
	)
}
