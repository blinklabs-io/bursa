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
	"errors"
	"fmt"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/ledger/babbage"
	"github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/conway"
	"github.com/blinklabs-io/gouroboros/ledger/mary"
	"github.com/blinklabs-io/gouroboros/ledger/shelley"
)

type BuildOptions struct {
	ChangeAddress    string
	CertificateFiles []string
	WitnessCount     uint
	TTL              uint64
}

type BuiltTx struct {
	TxCBOR         []byte
	TxEnvelopeType string // e.g. "Unwitnessed Tx ConwayEra"
}

func (b *BuiltTx) Enveloped() (string, error) {
	return bursa.WriteCborEnvelope(b.TxEnvelopeType, "Unwitnessed Tx", b.TxCBOR, "")
}

func computeDeposits(certs [][]byte, chain Chain, ctx context.Context, pp *ProtocolParametersExtra) (uint64, error) {
	var total uint64
	for _, c := range certs {
		var wrapper common.CertificateWrapper
		if _, err := cbor.Decode(c, &wrapper); err != nil {
			return 0, fmt.Errorf("decode certificate: %w", err)
		}
		switch cert := wrapper.Certificate.(type) {
		case *common.StakeRegistrationCertificate:
			if pp != nil {
				total += pp.KeyDeposit
			}
		case *common.RegistrationCertificate:
			total += cert.Amount
		case *common.StakeRegistrationDelegationCertificate:
			total += cert.Amount
		case *common.VoteRegistrationDelegationCertificate:
			total += cert.Amount
		case *common.StakeVoteRegistrationDelegationCertificate:
			total += cert.Amount
		case *common.RegistrationDrepCertificate:
			total += cert.Amount
		case *common.PoolRegistrationCertificate:
			poolId := cert.Operator.Bytes()
			registered, err := chain.GetPoolRegistration(ctx, poolId)
			if err != nil {
				return 0, err
			}
			if !registered && pp != nil {
				total += pp.PoolDeposit
			}
		case *common.PoolRetirementCertificate:
		case *common.StakeDeregistrationCertificate:
		case *common.DeregistrationCertificate:
		default:
		}
	}
	return total, nil
}

func Build(ctx context.Context, chain Chain, opts BuildOptions) (*BuiltTx, error) {
	if opts.ChangeAddress == "" {
		return nil, errors.New("change address required")
	}
	ppFee, ppExtra, err := chain.GetProtocolParameters(ctx)
	if err != nil {
		return nil, err
	}
	if ppFee == nil {
		return nil, errors.New("protocol parameters missing")
	}
	certBytesList, err := ParseCertificates(opts.CertificateFiles)
	if err != nil {
		return nil, err
	}

	var ppConv *ProtocolParametersExtra
	if ppExtra != nil {
		ppConv = ppExtra
	} else {
		ppConv = &ProtocolParametersExtra{}
	}
	deposits, err := computeDeposits(certBytesList, chain, ctx, ppConv)
	if err != nil {
		return nil, err
	}

	utxos, err := chain.GetUTxOs(ctx, opts.ChangeAddress)
	if err != nil {
		return nil, err
	}
	if len(utxos) == 0 {
		return nil, errors.New("insufficient funds")
	}

	changeAddr, err := common.NewAddress(opts.ChangeAddress)
	if err != nil {
		return nil, err
	}

	// Filter to ada-only UTxOs for coin selection. Assets are not needed
	// for pool operations and would require multi-asset change handling.
	var filtered []UTxO
	for _, u := range utxos {
		if assets := u.Output.Assets(); assets != nil && len(assets.Policies()) > 0 {
			continue
		}
		filtered = append(filtered, u)
	}
	if len(filtered) == 0 {
		return nil, errors.New("insufficient funds: no ada-only UTxOs")
	}
	utxos = filtered

	baseBody := &conway.ConwayTransactionBody{
		TxInputs:       conway.NewConwayTransactionInputSet([]shelley.ShelleyTransactionInput{}),
		TxOutputs:      []babbage.BabbageTransactionOutput{},
		TxCertificates: []common.CertificateWrapper{},
		TxWithdrawals:  map[*common.Address]uint64{},
	}

	var inputSum uint64
	inputs := []shelley.ShelleyTransactionInput{}
	for _, u := range utxos {
		inputs = append(inputs, shelley.ShelleyTransactionInput{
			TxId:        u.Input.Id(),
			OutputIndex: u.Input.Index(),
		})
		if v := u.Output.Amount(); v != nil {
			inputSum += v.Uint64()
		}
	}
	baseBody.TxInputs = conway.NewConwayTransactionInputSet(inputs)

	for _, c := range certBytesList {
		var wrapper common.CertificateWrapper
		if _, err := cbor.Decode(c, &wrapper); err != nil {
			return nil, fmt.Errorf("decode certificate: %w", err)
		}
		baseBody.TxCertificates = append(baseBody.TxCertificates, wrapper)
	}

	ttl := opts.TTL
	if ttl == 0 {
		slot, err := chain.GetSlot(ctx)
		if err != nil {
			return nil, err
		}
		ttl = slot + 3600
	}
	baseBody.Ttl = ttl

	witnessCount := opts.WitnessCount
	if witnessCount == 0 {
		witnessCount = 1
	}

	fee := uint64(200000)
	for i := 0; i < 10; i++ {
		if inputSum < fee+deposits {
			return nil, errors.New("insufficient funds")
		}
		change := inputSum - fee - deposits
		txBody := *baseBody
		txBody.TxFee = fee
		txBody.TxOutputs = []babbage.BabbageTransactionOutput{
			{
				OutputAddress: changeAddr,
				OutputAmount:  mary.MaryTransactionOutputValue{Amount: change},
			},
		}
		draftTx := conway.ConwayTransaction{
			Body:       txBody,
			WitnessSet: conway.ConwayTransactionWitnessSet{},
			TxIsValid:  true,
		}
		draftCbor, err := draftTx.MarshalCBOR()
		if err != nil {
			draftCbor = draftTx.Cbor()
		}
		if len(draftCbor) == 0 {
			return nil, errors.New("failed to marshal transaction")
		}
		estSize, err := bursa.EstimateWitnessedTxSize(draftCbor, witnessCount, 0)
		if err != nil {
			return nil, err
		}
		minFee, err := bursa.MinFee(estSize, *ppFee)
		if err != nil {
			return nil, err
		}
		if minFee <= fee {
			// Fee is sufficient
			txBody.TxFee = minFee
			// Recompute change with actual min fee
			if inputSum < minFee+deposits {
				return nil, errors.New("insufficient funds")
			}
			change = inputSum - minFee - deposits
			txBody.TxOutputs = []babbage.BabbageTransactionOutput{
				{
					OutputAddress: changeAddr,
					OutputAmount:  mary.MaryTransactionOutputValue{Amount: change},
				},
			}
			finalTx := conway.ConwayTransaction{
				Body:       txBody,
				WitnessSet: conway.ConwayTransactionWitnessSet{},
				TxIsValid:  true,
			}
			finalCbor, err := finalTx.MarshalCBOR()
			if err != nil {
				finalCbor = finalTx.Cbor()
			}
			if len(finalCbor) == 0 {
				return nil, errors.New("failed to marshal transaction")
			}
			return &BuiltTx{
				TxCBOR:         finalCbor,
				TxEnvelopeType: "Unwitnessed Tx ConwayEra",
			}, nil
		}
		fee = minFee
	}
	return nil, errors.New("failed to build transaction")
}
