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
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// PoolQueryResult is the result of querying pool information
type PoolQueryResult struct {
	Registered    bool        `json:"registered"`
	Params        *PoolParams `json:"params"`
	PendingParams *PoolParams `json:"pending_params,omitempty"`
	RetiringEpoch *uint64     `json:"retiring_epoch,omitempty"`
	Deposit       uint64      `json:"deposit"`
	OpCert        OpCertInfo  `json:"opcert"`
	KES           KESInfo     `json:"kes"`
	Epoch         int         `json:"epoch"`
}

// PoolParams contains stake pool parameters
type PoolParams struct {
	Operator      string              `json:"operator"`
	VrfKeyHash    string              `json:"vrf_key_hash"`
	Pledge        uint64              `json:"pledge"`
	Cost          uint64              `json:"cost"`
	Margin        string              `json:"margin"`
	MarginRatio   string              `json:"margin_ratio"`
	RewardAccount string              `json:"reward_account"`
	Owners        []string            `json:"owners"`
	Relays        []lcommon.PoolRelay `json:"relays"`
	MetadataURL   string              `json:"metadata_url,omitempty"`
	MetadataHash  string              `json:"metadata_hash,omitempty"`
}

// OpCertInfo contains operational certificate information
type OpCertInfo struct {
	OnChainCounter *uint64 `json:"on_chain_counter"`
	NextCounter    uint64  `json:"next_counter"`
}

// KESInfo contains KES information
type KESInfo struct {
	CurrentSlot       uint64 `json:"current_slot"`
	SlotsPerKESPeriod int    `json:"slots_per_kes_period"`
	MaxKESEvolutions  int    `json:"max_kes_evolutions"`
	CurrentKESPeriod  uint64 `json:"current_kes_period"`
}

// StakeAddressQueryResult is the result of querying stake address information
type StakeAddressQueryResult struct {
	Registered     bool    `json:"registered"`
	Deposit        uint64  `json:"deposit"`
	DelegatedPool  *string `json:"delegated_pool"`
	Rewards        uint64  `json:"rewards"`
	DRepDelegation *string `json:"drep_delegation"`
}

// UTxOQueryResult contains UTxO information
type UTxOQueryResult struct {
	TxID     string                       `json:"tx_id"`
	Index    uint32                       `json:"index"`
	Lovelace uint64                       `json:"lovelace"`
	Assets   map[string]map[string]string `json:"assets"`
}

// TipQueryResult contains tip information
type TipQueryResult struct {
	Era         string `json:"era"`
	Epoch       int    `json:"epoch"`
	Slot        uint64 `json:"slot"`
	BlockNumber int64  `json:"block_number"`
	KESPeriod   uint64 `json:"kes_period"`
}
