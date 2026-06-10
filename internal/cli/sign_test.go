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

package cli

import (
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/bip32"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

func TestReadPayloadRejectsConflictingInputs(t *testing.T) {
	if _, err := readPayload("text", "74657874"); err == nil {
		t.Fatalf("expected error when both payload inputs are provided")
	}
}

func TestRunVerifyDataAllowsMissingPayload(t *testing.T) {
	root := bip32.FromBip39Entropy(make([]byte, 32), nil)
	lk := &bursa.LoadedKey{SKey: []byte(root), VKey: bip32.XPrv(root).PublicKey()}
	keyHash := lcommon.Blake2b224Hash(lk.VKey)
	addr, err := lcommon.NewAddressFromParts(
		lcommon.AddressTypeKeyNone,
		lcommon.AddressNetworkTestnet,
		keyHash[:],
		nil,
	)
	if err != nil {
		t.Fatalf("NewAddressFromParts: %v", err)
	}
	addrBytes, err := addr.Bytes()
	if err != nil {
		t.Fatalf("Address.Bytes: %v", err)
	}
	sig, key, err := bursa.SignData(addrBytes, []byte("payload"), lk)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}

	if err := RunVerifyData(sig, key, "", ""); err != nil {
		t.Fatalf("RunVerifyData: %v", err)
	}
}
