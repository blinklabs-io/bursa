// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package multisig

import (
	"context"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/spend"
)

// The api layer refuses to sign, cosign or submit a multisig transaction whose
// spend.DecodeTx summary fails ValidateForSigning. Transactions this service
// builds itself, and their cosigned forms, must pass that gate: script-address
// inputs, the attached native script, and time-lock validity bounds are all
// effects the summary accounts for.
func TestBuiltTransactionsPassSpendEffectGate(t *testing.T) {
	before := uint64(1234)
	after := uint64(5678)
	cases := []struct {
		name          string
		invalidBefore *uint64
		invalidAfter  *uint64
	}{
		{name: "threshold"},
		{name: "timelocked", invalidBefore: &before, invalidAfter: &after},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fc := newFakeChain()
			ks := newTestKeystore(t, mnemonicA)
			svc := NewService(fc, ks, &memAccounts{})
			mk, err := svc.MyKey("test-password-123")
			if err != nil {
				t.Fatalf("MyKey: %v", err)
			}
			_, khB, _ := multiSigKeyHash(t, mnemonicB)
			acct, err := createForTest(svc, CreateRequest{
				Label:   tc.name,
				Network: "preview",
				Policy: Policy{
					Threshold:     1,
					Participants:  []Participant{{KeyHashHex: mk.KeyHashHex}, {KeyHashHex: khB}},
					InvalidBefore: tc.invalidBefore,
					InvalidAfter:  tc.invalidAfter,
				},
			})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			fc.addUTxO(acct.ScriptAddress, strings.Repeat("77", 32), 0, 10_000_000)

			built, err := svc.Build(context.Background(), acct.ID, BuildRequest{To: externalAddr(t), Lovelace: "1000000"})
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			cosigned, err := svc.CosignImported(built.UnsignedTxCBOR, "test-password-123")
			if err != nil {
				t.Fatalf("CosignImported: %v", err)
			}

			sp := spend.NewService(fc, nil, nil)
			for label, txCbor := range map[string]string{
				"built":    built.UnsignedTxCBOR,
				"cosigned": cosigned.TxCBOR,
			} {
				summary, err := sp.DecodeTx(context.Background(), txCbor)
				if err != nil {
					t.Fatalf("%s: DecodeTx: %v", label, err)
				}
				if err := summary.ValidateForSigning(); err != nil {
					t.Errorf("%s: ValidateForSigning rejected a service-built transaction: %v", label, err)
				}
				if len(summary.Inputs) == 0 {
					t.Errorf("%s: summary has no inputs", label)
				}
			}
		})
	}
}
