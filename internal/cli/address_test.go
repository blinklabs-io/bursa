// Copyright 2025 Blink Labs Software
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

package cli

import (
	"testing"

	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/stretchr/testify/assert"
)

func TestGetAddressTypeInfo(t *testing.T) {
	tests := []struct {
		addrType    uint8
		wantName    string
		wantDescSub string // substring to check in description
	}{
		{lcommon.AddressTypeKeyKey, "Base", "payment key"},
		{lcommon.AddressTypeScriptKey, "Base", "payment script"},
		{lcommon.AddressTypeKeyNone, "Enterprise", "payment key only"},
		{lcommon.AddressTypeScriptNone, "Enterprise", "payment script"},
		{lcommon.AddressTypeNoneKey, "Reward", "stake key"},
		{lcommon.AddressTypeNoneScript, "Reward", "stake script"},
		{lcommon.AddressTypeKeyPointer, "Pointer", "payment key"},
		{lcommon.AddressTypeByron, "Byron", "legacy"},
	}

	for _, tt := range tests {
		t.Run(tt.wantName, func(t *testing.T) {
			name, desc := getAddressTypeInfo(tt.addrType)
			assert.Equal(t, tt.wantName, name)
			assert.Contains(t, desc, tt.wantDescSub)
		})
	}
}

func TestFormatPaymentCredential(t *testing.T) {
	// 28-byte test hash
	hash := lcommon.Blake2b224{}
	copy(hash[:], []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c,
	})

	// Test key hash
	bech32Str, hexStr, err := formatPaymentCredential(hash, false)
	assert.NoError(t, err)
	assert.Contains(t, bech32Str, "addr_vkh")
	assert.Equal(
		t,
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
		hexStr,
	)

	// Test script hash (CIP-0005: script hashes use "script" prefix)
	bech32Str, _, err = formatPaymentCredential(hash, true)
	assert.NoError(t, err)
	assert.Contains(t, bech32Str, "script")
}

func TestFormatStakeCredential(t *testing.T) {
	hash := lcommon.Blake2b224{}
	copy(hash[:], []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c,
	})

	// Test key hash
	bech32Str, hexStr, err := formatStakeCredential(hash, false)
	assert.NoError(t, err)
	assert.Contains(t, bech32Str, "stake_vkh")
	assert.Equal(
		t,
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
		hexStr,
	)

	// Test script hash (CIP-0005: script hashes use "script" prefix)
	bech32Str, _, err = formatStakeCredential(hash, true)
	assert.NoError(t, err)
	assert.Contains(t, bech32Str, "script")
}

func TestRunAddressInfo_InvalidAddress(t *testing.T) {
	err := RunAddressInfo("invalid")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid address")
}
