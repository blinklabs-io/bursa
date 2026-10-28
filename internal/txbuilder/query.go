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
	"fmt"
	"sort"

	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/protocol/localstatequery"
)

// QueryPool queries pool information
func (n *N2CChain) QueryPool(ctx context.Context, poolID string, network string) (*PoolQueryResult, error) {
	conn, release, err := n.session(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	// Parse pool ID
	var poolKeyHash lcommon.Blake2b224
	if len(poolID) == 56 {
		// hex
		h, err := hex.DecodeString(poolID)
		if err != nil {
			return nil, err
		}
		if len(h) != 28 {
			return nil, fmt.Errorf("invalid pool id length")
		}
		copy(poolKeyHash[:], h)
	} else if len(poolID) > 5 && poolID[:5] == "pool1" {
		pid, err := lcommon.NewPoolIdFromBech32(poolID)
		if err != nil {
			return nil, err
		}
		copy(poolKeyHash[:], pid[:])
	} else {
		return nil, fmt.Errorf("invalid pool id")
	}

	poolId := lcommon.PoolId(poolKeyHash)

	// Get stake pool params
	paramsResult, err := conn.LocalStateQuery().Client.GetStakePoolParams([]lcommon.PoolId{poolId})
	if err != nil {
		return nil, err
	}

	// Get pool state
	poolStateResult, err := conn.LocalStateQuery().Client.GetPoolState([]any{poolId})
	if err != nil {
		return nil, err
	}

	// Get op cert counters
	opCertCounters, err := conn.LocalStateQuery().Client.GetOpCertCounters()
	if err != nil {
		return nil, err
	}

	// Get chain point
	chainPoint, err := conn.LocalStateQuery().Client.GetChainPoint()
	if err != nil {
		return nil, err
	}

	// Get genesis config
	genesisConfig, err := conn.LocalStateQuery().Client.GetGenesisConfig()
	if err != nil {
		return nil, err
	}

	// Get epoch
	epoch, err := conn.LocalStateQuery().Client.GetEpochNo()
	if err != nil {
		return nil, err
	}

	result := &PoolQueryResult{
		Epoch:         epoch,
		OpCert:        OpCertInfo{OnChainCounter: nil, NextCounter: 0},
		PendingParams: nil,
		RetiringEpoch: nil,
	}

	// Check if registered
	registered := false
	var currentParams *localstatequery.PoolStateParams
	// Also check pool state
	if poolStateResult != nil {
		if p, ok := poolStateResult.PState[poolKeyHash]; ok && p != nil {
			registered = true
			currentParams = p
		}
		// pending params from FState
		if fp, ok := poolStateResult.FState[poolKeyHash]; ok && fp != nil {
			pendingParams, err := convertPoolParams(fp, network)
			if err != nil {
				return nil, err
			}
			result.PendingParams = pendingParams
		}
		// retiring
		if r, ok := poolStateResult.Retiring[poolKeyHash]; ok {
			result.RetiringEpoch = &r
		}
		// deposit
		if d, ok := poolStateResult.Deposits[poolKeyHash]; ok {
			result.Deposit = d
		} else {
			_, ppExtra, _ := n.GetProtocolParameters(ctx)
			if ppExtra != nil {
				result.Deposit = ppExtra.PoolDeposit
			}
		}
	}

	result.Registered = registered
	if currentParams != nil {
		cp, err := convertPoolParams(currentParams, network)
		if err != nil {
			return nil, err
		}
		result.Params = cp
	} else if paramsResult != nil {
		// Try to get from GetStakePoolParams result
		if pr, ok := paramsResult.Results[poolId]; ok {
			registered = true
			// Convert from StakePoolParamsResult format
			currentParams2 := &localstatequery.PoolStateParams{
				Operator:      pr.Operator,
				VrfKeyHash:    pr.VrfKeyHash,
				Pledge:        uint64(pr.Pledge),
				Cost:          uint64(pr.FixedCost),
				Margin:        pr.Margin,
				RewardAccount: pr.RewardAccount,
				PoolOwners:    pr.PoolOwners,
				Relays:        pr.Relays,
			}
			if pr.PoolMetadata != nil {
				currentParams2.PoolMetadata = &struct {
					cbor.StructAsArray
					Url          string
					MetadataHash lcommon.PoolMetadataHash
				}{
					Url:          pr.PoolMetadata.Url,
					MetadataHash: pr.PoolMetadata.MetadataHash,
				}
			}
			cp, err := convertPoolParams(currentParams2, network)
			if err != nil {
				return nil, err
			}
			result.Params = cp
		}
	}

	// OpCert info
	var onChainCounter *uint64
	if opCertCounters != nil {
		if c, ok := opCertCounters[poolKeyHash]; ok {
			onChainCounter = &c
		}
		// If pool has not forged, absent -> null (never 0)
	}
	nextCounter := uint64(0)
	if onChainCounter != nil {
		nextCounter = *onChainCounter + 1
	} else {
		nextCounter = 0
	}
	result.OpCert = OpCertInfo{
		OnChainCounter: onChainCounter,
		NextCounter:    nextCounter,
	}

	// KES info
	var currentSlot uint64
	if chainPoint != nil {
		currentSlot = chainPoint.Slot
	} else {
		s, err := n.GetSlot(ctx)
		if err == nil {
			currentSlot = s
		}
	}
	slotsPerKESPeriod := genesisConfig.SlotsPerKESPeriod
	maxKESEvolutions := genesisConfig.MaxKESEvolutions
	currentKESPeriod := calculateKESPeriod(currentSlot, slotsPerKESPeriod)
	result.KES = KESInfo{
		CurrentSlot:       currentSlot,
		SlotsPerKESPeriod: slotsPerKESPeriod,
		MaxKESEvolutions:  maxKESEvolutions,
		CurrentKESPeriod:  currentKESPeriod,
	}

	return result, nil
}

// QueryStakeAddress queries stake address information
func (n *N2CChain) QueryStakeAddress(ctx context.Context, address string) (*StakeAddressQueryResult, error) {
	conn, release, err := n.session(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	addr, err := lcommon.NewAddress(address)
	if err != nil {
		return nil, err
	}

	// Get stake credential
	stakeCred, ok := addr.StakeCredential()
	if !ok {
		// Try as reward account?
		stakeCred, err = addr.RewardAccountCredential()
		if err != nil {
			return nil, err
		}
	}

	// Convert to localstatequery.StakeCredential
	lsCred := localstatequery.StakeCredential{
		Tag:   uint64(stakeCred.CredType), // 0 for key hash, 1 for script hash in their format?
		Bytes: stakeCred.Credential,
	}
	// Check - in gouroboros, StakeCredential.Tag is uint64, Bytes is Blake2b224

	// Get stake deleg deposits
	deposits, err := conn.LocalStateQuery().Client.GetStakeDelegDeposits([]localstatequery.StakeCredential{lsCred})
	if err != nil {
		return nil, err
	}

	// Get filtered delegations and reward accounts
	delegRewards, err := conn.LocalStateQuery().Client.GetFilteredDelegationsAndRewardAccounts([]localstatequery.StakeCredential{lsCred})
	if err != nil {
		return nil, err
	}

	result := &StakeAddressQueryResult{
		DelegatedPool:  nil,
		DRepDelegation: nil,
	}

	// Check if registered
	registered := false
	if deposits != nil {
		if _, ok := (*deposits)[lsCred]; ok {
			registered = true
		}
	}
	result.Registered = registered

	// Get deposit
	if registered && deposits != nil {
		if d, ok := (*deposits)[lsCred]; ok {
			result.Deposit = d
		}
	}

	// Get delegations and rewards
	if delegRewards != nil {
		if pool, ok := delegRewards.Delegations[lsCred]; ok {
			// pool is Blake2b224 (PoolId)
			poolBech32 := lcommon.PoolId(pool).String()
			result.DelegatedPool = &poolBech32
		}
		if r, ok := delegRewards.Rewards[lsCred]; ok {
			result.Rewards = r
		}
	}

	// Get DRep delegation
	tryDRep := true
	drepDelegs, err := conn.LocalStateQuery().Client.GetFilteredVoteDelegatees([]lcommon.Credential{stakeCred})
	if err != nil {
		tryDRep = false
	}
	if tryDRep && drepDelegs != nil {
		if drep, ok := (*drepDelegs)[lsCred]; ok {
			// Format DRep
			drepStr := formatDRep(drep)
			result.DRepDelegation = &drepStr
		}
	}

	return result, nil
}

func formatDRep(drep lcommon.Drep) string {
	switch drep.Type {
	case lcommon.DrepTypeAbstain:
		return "abstain"
	case lcommon.DrepTypeNoConfidence:
		return "no-confidence"
	case lcommon.DrepTypeAddrKeyHash:
		if len(drep.Credential) == 28 {
			return hex.EncodeToString(drep.Credential)
		}
		return hex.EncodeToString(drep.Credential)
	case lcommon.DrepTypeScriptHash:
		if len(drep.Credential) == 28 {
			return hex.EncodeToString(drep.Credential)
		}
		return hex.EncodeToString(drep.Credential)
	default:
		return hex.EncodeToString(drep.Credential)
	}
}

// QueryUTxOs queries UTxOs for an address
func (n *N2CChain) QueryUTxOs(ctx context.Context, address string) ([]UTxOQueryResult, error) {
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

	results := make([]UTxOQueryResult, 0)
	if res == nil || res.Results == nil {
		return results, nil
	}

	type utxoKey struct {
		txID  string
		index uint32
	}
	var items []struct {
		key    utxoKey
		result UTxOQueryResult
	}

	for id, out := range res.Results {
		if id.Idx < 0 {
			continue
		}
		idx := uint32(id.Idx)
		txID := hex.EncodeToString(id.Hash[:])
		lovelace := uint64(0)
		if out.Amount() != nil {
			lovelace = out.Amount().Uint64()
		}

		assets := make(map[string]map[string]string)
		if ma := out.Assets(); ma != nil {
			for _, policy := range ma.Policies() {
				policyHex := hex.EncodeToString(policy[:])
				assets[policyHex] = make(map[string]string)
				for _, assetName := range ma.Assets(policy) {
					assetHex := hex.EncodeToString(assetName)
					amount := ma.Asset(policy, assetName)
					if amount != nil {
						assets[policyHex][assetHex] = amount.String()
					}
				}
			}
		}

		items = append(items, struct {
			key    utxoKey
			result UTxOQueryResult
		}{
			key: utxoKey{txID: txID, index: idx},
			result: UTxOQueryResult{
				TxID:     txID,
				Index:    idx,
				Lovelace: lovelace,
				Assets:   assets,
			},
		})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].key.txID != items[j].key.txID {
			return items[i].key.txID < items[j].key.txID
		}
		return items[i].key.index < items[j].key.index
	})

	for _, item := range items {
		results = append(results, item.result)
	}
	return results, nil
}

// QueryTip queries chain tip information
func (n *N2CChain) QueryTip(ctx context.Context) (*TipQueryResult, error) {
	conn, release, err := n.session(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	chainPoint, err := conn.LocalStateQuery().Client.GetChainPoint()
	if err != nil {
		return nil, err
	}

	epoch, err := conn.LocalStateQuery().Client.GetEpochNo()
	if err != nil {
		return nil, err
	}

	blockNo, err := conn.LocalStateQuery().Client.GetChainBlockNo()
	if err != nil {
		return nil, err
	}

	currentEra, err := conn.LocalStateQuery().Client.GetCurrentEra()
	if err != nil {
		// try to get era differently
	}

	genesisConfig, err := conn.LocalStateQuery().Client.GetGenesisConfig()
	if err != nil {
		return nil, err
	}

	var slot uint64
	if chainPoint != nil {
		slot = chainPoint.Slot
	}
	slotsPerKESPeriod := genesisConfig.SlotsPerKESPeriod
	kesPeriod := calculateKESPeriod(slot, slotsPerKESPeriod)

	era := ""
	if currentEra >= 0 {
		era = fmt.Sprintf("%d", currentEra)
		// Try to map era
		switch currentEra {
		case 0:
			era = "byron"
		case 1:
			era = "shelley"
		case 2:
			era = "allegra"
		case 3:
			era = "mary"
		case 4:
			era = "alonzo"
		case 5:
			era = "babbage"
		case 6:
			era = "conway"
		}
	}

	return &TipQueryResult{
		Era:         era,
		Epoch:       epoch,
		Slot:        slot,
		BlockNumber: blockNo,
		KESPeriod:   kesPeriod,
	}, nil
}
