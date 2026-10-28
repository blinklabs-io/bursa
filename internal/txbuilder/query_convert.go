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
	"math/big"
	"strings"

	"github.com/blinklabs-io/gouroboros/protocol/localstatequery"
)

// convertPoolParams converts pool params from gouroboros format
func convertPoolParams(params *localstatequery.PoolStateParams, network string) (*PoolParams, error) {
	if params == nil {
		return nil, nil
	}
	// Get reward account bech32 per network
	rewardAccount := params.RewardAccount.String()

	// Format margin as decimal string
	marginStr := "0"
	if params.Margin != nil && params.Margin.Rat != nil {
		marginStr = formatMarginDecimal(params.Margin.Rat)
	}

	owners := make([]string, 0, len(params.PoolOwners))
	for _, o := range params.PoolOwners {
		owners = append(owners, hex.EncodeToString(o[:]))
	}

	relays := make([]interface{}, 0, len(params.Relays))
	for _, r := range params.Relays {
		relays = append(relays, r)
	}

	result := &PoolParams{
		Operator:      hex.EncodeToString(params.Operator[:]),
		VrfKeyHash:    hex.EncodeToString(params.VrfKeyHash[:]),
		Pledge:        params.Pledge,
		Cost:          params.Cost,
		Margin:        marginStr,
		RewardAccount: rewardAccount,
		Owners:        owners,
		Relays:        relays,
	}
	if params.PoolMetadata != nil {
		result.MetadataURL = params.PoolMetadata.Url
		result.MetadataHash = hex.EncodeToString(params.PoolMetadata.MetadataHash[:])
	}
	return result, nil
}

func formatMarginDecimal(rat *big.Rat) string {
	if rat == nil {
		return "0"
	}
	if rat.Sign() == 0 {
		return "0"
	}
	// Use big.Float for formatting
	f := new(big.Float).SetRat(rat)
	s := f.Text('f', -1)
	// Trim trailing zeros and decimal point if needed
	// For Cardano, margin is typically like 0.05
	s = strings.TrimRight(s, "0")
	s = strings.TrimRight(s, ".")
	if s == "" || s == "-" || s == "-." {
		return "0"
	}
	if s == "-0" {
		return "0"
	}
	// If it starts with "." add "0"
	if strings.HasPrefix(s, ".") {
		s = "0" + s
	}
	if strings.HasPrefix(s, "-.") {
		s = "-0" + s[1:]
	}
	return s
}

// calculateKESPeriod calculates current KES period
func calculateKESPeriod(currentSlot uint64, slotsPerKESPeriod int) uint64 {
	if slotsPerKESPeriod == 0 {
		return 0
	}
	return currentSlot / uint64(slotsPerKESPeriod)
}
