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

package signer

import (
	"context"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/policy"
	"github.com/blinklabs-io/gouroboros/ledger"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// eraRecordingCardano records the era each Cardano call receives.
type eraRecordingCardano struct {
	fakeCardano
	eras map[string]uint
}

func (c *eraRecordingCardano) Inspect(tx []byte, txType uint) (*bursa.TxInspection, error) {
	c.eras["Inspect"] = txType
	return c.fakeCardano.Inspect(tx, txType)
}

func (c *eraRecordingCardano) Operations(tx []byte, txType uint) (policy.TxOps, error) {
	c.eras["Operations"] = txType
	return c.fakeCardano.Operations(tx, txType)
}

func (c *eraRecordingCardano) TxID(tx []byte, txType uint) ([]byte, error) {
	c.eras["TxID"] = txType
	return c.fakeCardano.TxID(tx, txType)
}

func (c *eraRecordingCardano) Assemble(tx []byte, txType uint, wits []lcommon.VkeyWitness) ([]byte, error) {
	c.eras["Assemble"] = txType
	return c.fakeCardano.Assemble(tx, txType, wits)
}

// TestSignTx_DecodesResolvedEra confirms inspection, policy operations, the
// signed transaction id and assembly all use the era resolved from the request.
func TestSignTx_DecodesResolvedEra(t *testing.T) {
	tests := []struct {
		name string
		cbor string
		era  string
		want uint
	}{
		{name: "explicit babbage", cbor: testTxCbor, era: "babbage", want: ledger.TxTypeBabbage},
		{name: "explicit alonzo", cbor: testTxCbor, era: "alonzo", want: ledger.TxTypeAlonzo},
		{
			name: "conway envelope",
			cbor: `{"type":"Tx ConwayEra","description":"","cborHex":"` + testTxCbor + `"}`,
			want: ledger.TxTypeConway,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := newFakeKey(t)
			eng, err := policy.NewEngine([]policy.KeyPolicy{{
				Hash:            k.hash.String(),
				AllowedRequests: []string{"tx"},
				Tx:              &policy.TxPolicy{},
			}})
			if err != nil {
				t.Fatalf("NewEngine: %v", err)
			}
			card := &eraRecordingCardano{
				fakeCardano: fakeCardano{
					insp:      &bursa.TxInspection{TxId: "abc"},
					txid:      make([]byte, 32),
					assembled: []byte{0x01},
				},
				eras: map[string]uint{},
			}
			c := New(Deps{
				Resolver: backend.NewResolver(fakeBackend{key: k}),
				Policy:   eng,
				Cardano:  card,
			})
			res, perr, err := c.SignTx(context.Background(), []byte(tt.cbor), tt.era, []string{k.hash.String()})
			if err != nil {
				t.Fatalf("SignTx: %v", err)
			}
			if len(perr) != 0 || len(res.Witnesses) != 1 {
				t.Fatalf("expected 1 witness, no errors; got perr=%+v wits=%d", perr, len(res.Witnesses))
			}
			for _, call := range []string{"Inspect", "Operations", "TxID", "Assemble"} {
				got, ok := card.eras[call]
				if !ok {
					t.Fatalf("%s was not called", call)
				}
				if got != tt.want {
					t.Errorf("%s era = %d, want %d", call, got, tt.want)
				}
			}
		})
	}
}
