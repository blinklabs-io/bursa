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

package network

import (
	"strconv"

	ouroboros "github.com/blinklabs-io/gouroboros"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// AddressID resolves a registry network name, the testnet alias, or a decimal
// network magic to the network ID used in addresses. An unregistered magic
// selects testnet, matching cardano-cli's --testnet-magic behavior.
func AddressID(name string) (uint8, bool) {
	if name == "testnet" {
		return lcommon.AddressNetworkTestnet, true
	}
	if network, ok := ouroboros.NetworkByName(name); ok {
		return network.Id, true
	}
	magic, err := strconv.ParseUint(name, 10, 32)
	if err != nil {
		return 0, false
	}
	if network, ok := ouroboros.NetworkByNetworkMagic(uint32(magic)); ok {
		return network.Id, true
	}
	return lcommon.AddressNetworkTestnet, true
}
