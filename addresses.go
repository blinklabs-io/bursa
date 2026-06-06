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

package bursa

import (
	"errors"
	"fmt"
)

const maxAddressDerivationIndex = 0x7fffffff

// EnumeratedAddress is a single derived address with its derivation index.
type EnumeratedAddress struct {
	Index   uint32 `json:"index"`
	Address string `json:"address"`
}

// EnumerateAddresses derives `count` consecutive base addresses for a wallet,
// starting at `start`, for the given account and network. password may be empty.
// It reuses the existing single-address derivation; it does not reimplement it.
func EnumerateAddresses(mnemonic, password, network string, account, start, count uint32) ([]EnumeratedAddress, error) {
	if count == 0 {
		return nil, errors.New("count must be greater than zero")
	}
	if count > 1000 {
		return nil, fmt.Errorf("count %d exceeds maximum of 1000", count)
	}
	if start > maxAddressDerivationIndex ||
		count-1 > maxAddressDerivationIndex-start {
		return nil, fmt.Errorf("address index range exceeds maximum derivation index %d: start=%d count=%d", maxAddressDerivationIndex, start, count)
	}
	rootKey, err := GetRootKeyFromMnemonic(mnemonic, password)
	if err != nil {
		return nil, err
	}
	accountKey, err := GetAccountKey(rootKey, account)
	if err != nil {
		return nil, err
	}
	out := make([]EnumeratedAddress, 0, count)
	for i := uint32(0); i < count; i++ {
		idx := start + i
		addr, err := GetAddress(accountKey, network, idx)
		if err != nil {
			return nil, fmt.Errorf("failed to derive address at index %d: %w", idx, err)
		}
		out = append(out, EnumeratedAddress{Index: idx, Address: addr.String()})
	}
	return out, nil
}
