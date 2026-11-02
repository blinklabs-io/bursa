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
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"

	ouroboros "github.com/blinklabs-io/gouroboros"
	"github.com/blinklabs-io/gouroboros/ledger"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/protocol/localstatequery"
)

// poolQueryFromState builds the pool query result from the local-state-query
// replies. The pool state is the registration source: PState holds the
// current parameters, FState a registered update that takes effect at the
// next epoch boundary, and Retiring a scheduled retirement epoch.
func poolQueryFromState(
	poolID lcommon.PoolId,
	ps *localstatequery.PoolStateResult,
	counters map[lcommon.Blake2b224]uint64,
	slot uint64,
	slotsPerKESPeriod int,
	maxKESEvolutions int,
	epoch int,
	network string,
) (*PoolQueryResult, error) {
	keyHash := lcommon.Blake2b224(poolID)
	kesPeriod, err := calculateKESPeriod(slot, slotsPerKESPeriod)
	if err != nil {
		return nil, err
	}
	result := &PoolQueryResult{
		Epoch: epoch,
		KES: KESInfo{
			CurrentSlot:       slot,
			SlotsPerKESPeriod: slotsPerKESPeriod,
			MaxKESEvolutions:  maxKESEvolutions,
			CurrentKESPeriod:  kesPeriod,
		},
	}
	if ps != nil {
		if p, ok := ps.PState[keyHash]; ok && p != nil {
			result.Registered = true
			params, err := poolParamsFromState(p, network)
			if err != nil {
				return nil, err
			}
			result.Params = params
		}
		if fp, ok := ps.FState[keyHash]; ok && fp != nil {
			pending, err := poolParamsFromState(fp, network)
			if err != nil {
				return nil, err
			}
			result.PendingParams = pending
		}
		if retiring, ok := ps.Retiring[keyHash]; ok {
			result.RetiringEpoch = &retiring
		}
		// An unregistered pool has no locked deposit; the map miss is 0.
		result.Deposit = ps.Deposits[keyHash]
	}
	if counter, ok := counters[keyHash]; ok {
		// A pool that has not forged has no on-chain counter: it stays
		// null, never 0, and the first certificate uses counter 0.
		result.OpCert = OpCertInfo{
			OnChainCounter: &counter,
			NextCounter:    counter + 1,
		}
	}
	return result, nil
}

// poolParamsFromState converts pool registration parameters to the query
// result. The reward account is rebuilt for the requested network rather
// than re-encoded as stored, so the bech32 prefix (stake1 or stake_test1)
// follows --network.
func poolParamsFromState(
	params *localstatequery.PoolStateParams,
	network string,
) (*PoolParams, error) {
	cred, err := params.RewardAccount.RewardAccountCredential()
	if err != nil {
		return nil, fmt.Errorf("pool reward account: %w", err)
	}
	networkID, err := networkAddressId(network)
	if err != nil {
		return nil, err
	}
	addrType := uint8(lcommon.AddressTypeNoneKey)
	if cred.CredType == lcommon.CredentialTypeScriptHash {
		addrType = lcommon.AddressTypeNoneScript
	}
	rewardAccount, err := lcommon.NewAddressFromParts(
		addrType,
		networkID,
		nil,
		cred.Credential[:],
	)
	if err != nil {
		return nil, fmt.Errorf("pool reward account: %w", err)
	}
	if params.Margin == nil || params.Margin.Rat == nil {
		return nil, errors.New("pool parameters have no margin")
	}
	owners := make([]string, 0, len(params.PoolOwners))
	for _, owner := range params.PoolOwners {
		owners = append(owners, hex.EncodeToString(owner[:]))
	}
	relays := make([]lcommon.PoolRelay, 0, len(params.Relays))
	relays = append(relays, params.Relays...)
	result := &PoolParams{
		Operator:      hex.EncodeToString(params.Operator[:]),
		VrfKeyHash:    hex.EncodeToString(params.VrfKeyHash[:]),
		Pledge:        params.Pledge,
		Cost:          params.Cost,
		Margin:        formatMarginDecimal(params.Margin.Rat),
		MarginRatio:   params.Margin.String(),
		RewardAccount: rewardAccount.String(),
		Owners:        owners,
		Relays:        relays,
	}
	if params.PoolMetadata != nil {
		result.MetadataURL = params.PoolMetadata.Url
		result.MetadataHash = hex.EncodeToString(params.PoolMetadata.MetadataHash)
	}
	return result, nil
}

// maxMarginDecimals bounds formatMarginDecimal's expansion of rationals
// whose decimal form does not terminate.
const maxMarginDecimals = 20

// formatMarginDecimal renders a margin rational as a decimal string by long
// division, without a float: 1/20 is "0.05" and 3/8 is "0.375". Expansions
// that do not terminate are truncated at maxMarginDecimals fractional
// digits, so 1/3 is "0.33333333333333333333".
func formatMarginDecimal(rat *big.Rat) string {
	if rat == nil || rat.Sign() == 0 {
		return "0"
	}
	num := new(big.Int).Set(rat.Num())
	den := rat.Denom()
	var sb strings.Builder
	if rat.Sign() < 0 {
		sb.WriteByte('-')
		num.Abs(num)
	}
	integer, rem := new(big.Int).QuoRem(num, den, new(big.Int))
	sb.WriteString(integer.String())
	if rem.Sign() == 0 {
		return sb.String()
	}
	digits := make([]byte, 0, maxMarginDecimals)
	ten := big.NewInt(10)
	for range maxMarginDecimals {
		if rem.Sign() == 0 {
			break
		}
		rem.Mul(rem, ten)
		var digit *big.Int
		digit, rem = new(big.Int).QuoRem(rem, den, new(big.Int))
		// rem < den, so the digit is 0 to 9 and AppendInt writes one
		// ASCII character.
		digits = strconv.AppendInt(digits, digit.Int64(), 10)
	}
	for len(digits) > 0 && digits[len(digits)-1] == '0' {
		digits = digits[:len(digits)-1]
	}
	if len(digits) > 0 {
		sb.WriteByte('.')
		sb.Write(digits)
	}
	return sb.String()
}

// calculateKESPeriod returns the KES period containing currentSlot. A
// nonpositive slots-per-period is an error rather than a plausible period 0.
func calculateKESPeriod(currentSlot uint64, slotsPerKESPeriod int) (uint64, error) {
	if slotsPerKESPeriod <= 0 {
		return 0, fmt.Errorf("invalid slots per KES period %d", slotsPerKESPeriod)
	}
	return currentSlot / uint64(slotsPerKESPeriod), nil
}

// stakeCredentialFrom converts a ledger credential to the local-state-query
// key: tag 0 for a key hash, 1 for a script hash, as the node encodes it.
func stakeCredentialFrom(cred lcommon.Credential) localstatequery.StakeCredential {
	return localstatequery.StakeCredential{
		Tag:   uint64(cred.CredType),
		Bytes: cred.Credential,
	}
}

// stakeQueryFrom builds the stake address query result from the
// local-state-query replies for one credential.
func stakeQueryFrom(
	cred localstatequery.StakeCredential,
	deposits *localstatequery.StakeDelegDepositsResult,
	delegRewards *localstatequery.FilteredDelegationsAndRewardAccountsResult,
	drepDelegs *localstatequery.FilteredVoteDelegateesResult,
) *StakeAddressQueryResult {
	result := &StakeAddressQueryResult{}
	if deposits != nil {
		if deposit, ok := (*deposits)[cred]; ok {
			result.Registered = true
			result.Deposit = deposit
		}
	}
	if delegRewards != nil {
		if pool, ok := delegRewards.Delegations[cred]; ok {
			delegated := lcommon.PoolId(pool).String()
			result.DelegatedPool = &delegated
		}
		if rewards, ok := delegRewards.Rewards[cred]; ok {
			result.Rewards = rewards
		}
	}
	if drepDelegs != nil {
		if drep, ok := (*drepDelegs)[cred]; ok {
			// Drep.String is CIP-129 bech32 for credential DReps and
			// drep_abstain / drep_no_confidence for the predefined ones.
			delegation := drep.String()
			result.DRepDelegation = &delegation
		}
	}
	return result
}

// utxoQueryFrom converts the UTxO query result and sorts it by transaction
// id, then output index.
func utxoQueryFrom(res *localstatequery.UTxOsResult) ([]UTxOQueryResult, error) {
	results := []UTxOQueryResult{}
	if res == nil {
		return results, nil
	}
	for id, out := range res.Results {
		if id.Idx < 0 || id.Idx > math.MaxUint32 {
			return nil, fmt.Errorf("utxo index %d out of range", id.Idx)
		}
		entry := UTxOQueryResult{
			TxID:   hex.EncodeToString(id.Hash[:]),
			Index:  uint32(id.Idx),
			Assets: map[string]map[string]string{},
		}
		if amount := out.Amount(); amount != nil {
			entry.Lovelace = amount.Uint64()
		}
		if assets := out.Assets(); assets != nil {
			for _, policy := range assets.Policies() {
				policyHex := hex.EncodeToString(policy[:])
				entry.Assets[policyHex] = map[string]string{}
				for _, name := range assets.Assets(policy) {
					amount := assets.Asset(policy, name)
					if amount == nil {
						continue
					}
					entry.Assets[policyHex][hex.EncodeToString(name)] = amount.String()
				}
			}
		}
		results = append(results, entry)
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].TxID != results[j].TxID {
			return results[i].TxID < results[j].TxID
		}
		return results[i].Index < results[j].Index
	})
	return results, nil
}

// tipQueryFrom builds the tip query result. The era id is mapped through
// the gouroboros era registry; an id the registry does not know is an
// error rather than a wrong name.
func tipQueryFrom(
	eraID int,
	epoch int,
	blockNumber int64,
	slot uint64,
	slotsPerKESPeriod int,
) (*TipQueryResult, error) {
	if eraID < 0 || eraID > math.MaxUint8 {
		return nil, fmt.Errorf("unknown era id %d", eraID)
	}
	era := ledger.GetEraById(uint8(eraID))
	if era == lcommon.EraInvalid {
		return nil, fmt.Errorf("unknown era id %d", eraID)
	}
	kesPeriod, err := calculateKESPeriod(slot, slotsPerKESPeriod)
	if err != nil {
		return nil, err
	}
	return &TipQueryResult{
		Era:         era.Name,
		Epoch:       epoch,
		Slot:        slot,
		BlockNumber: blockNumber,
		KESPeriod:   kesPeriod,
	}, nil
}

// networkAddressId resolves the CIP-0019 address network id for a network
// name or magic: mainnet is 1, everything else is a testnet (0).
func networkAddressId(network string) (uint8, error) {
	if netw, ok := ouroboros.NetworkByName(network); ok {
		return netw.Id, nil
	}
	magic, err := networkMagic(network)
	if err != nil {
		return 0, err
	}
	if magic == ouroboros.NetworkCardanoMainnet.NetworkMagic {
		return lcommon.AddressNetworkMainnet, nil
	}
	return lcommon.AddressNetworkTestnet, nil
}

// ParseRewardAddress parses a bech32 reward (stake) address and checks it
// belongs to network. Anything else, including a payment address whose
// stake part would silently answer the wrong query, is an error.
func ParseRewardAddress(address, network string) (lcommon.Address, error) {
	addr, err := lcommon.NewAddress(address)
	if err != nil {
		return lcommon.Address{}, fmt.Errorf("invalid stake address: %w", err)
	}
	if _, err := addr.RewardAccountCredential(); err != nil {
		return lcommon.Address{}, errors.New(
			"address is not a stake (reward) address",
		)
	}
	networkID, err := networkAddressId(network)
	if err != nil {
		return lcommon.Address{}, err
	}
	if addr.NetworkId() != uint(networkID) {
		return lcommon.Address{}, fmt.Errorf(
			"stake address network id %d does not match network %q (id %d)",
			addr.NetworkId(),
			network,
			networkID,
		)
	}
	return addr, nil
}

// ParsePaymentAddress parses an address that can hold UTxOs and checks it
// belongs to network. A reward (stake) address holds none and is an error.
func ParsePaymentAddress(address, network string) (lcommon.Address, error) {
	addr, err := lcommon.NewAddress(address)
	if err != nil {
		return lcommon.Address{}, fmt.Errorf("invalid address: %w", err)
	}
	if _, err := addr.RewardAccountCredential(); err == nil {
		return lcommon.Address{}, errors.New(
			"address is a stake (reward) address, which holds no UTxOs",
		)
	}
	networkID, err := networkAddressId(network)
	if err != nil {
		return lcommon.Address{}, err
	}
	if addr.NetworkId() != uint(networkID) {
		return lcommon.Address{}, fmt.Errorf(
			"address network id %d does not match network %q (id %d)",
			addr.NetworkId(),
			network,
			networkID,
		)
	}
	return addr, nil
}
