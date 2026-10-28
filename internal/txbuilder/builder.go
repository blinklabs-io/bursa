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
	"sort"
)

type BuildOptions struct {
	ChangeAddress    string
	CertificateFiles []string
	WitnessCount     uint
	TTL              uint64
	TTLMargin        uint64 // if not set, CLI will provide; builder may use default if needed? but requirement says CLI adds --ttl-margin default 3600
}

type BuiltTx struct {
	TxCBOR         []byte
	TxEnvelopeType string // e.g. "Unwitnessed Tx ConwayEra"
}

func (b *BuiltTx) Enveloped() (string, error) {
	return bursa.WriteCborEnvelope(b.TxEnvelopeType, "Unwitnessed Tx", b.TxCBOR, "")
}

func computeDeposits(certs [][]byte, chain Chain, ctx context.Context, pp *ProtocolParametersExtra) (uint64, uint64, error) {
	var deposits uint64
	var refunds uint64
	for _, c := range certs {
		var wrapper common.CertificateWrapper
		if _, err := cbor.Decode(c, &wrapper); err != nil {
			return 0, 0, fmt.Errorf("decode certificate: %w", err)
		}
		switch cert := wrapper.Certificate.(type) {
		case *common.StakeRegistrationCertificate:
			if pp != nil {
				deposits += pp.KeyDeposit
			}
		case *common.RegistrationCertificate:
			deposits += cert.Amount
		case *common.StakeRegistrationDelegationCertificate:
			deposits += cert.Amount
		case *common.VoteRegistrationDelegationCertificate:
			deposits += cert.Amount
		case *common.StakeVoteRegistrationDelegationCertificate:
			deposits += cert.Amount
		case *common.RegistrationDrepCertificate:
			deposits += cert.Amount
		case *common.PoolRegistrationCertificate:
			poolId := cert.Operator.Bytes()
			registered, err := chain.GetPoolRegistration(ctx, poolId)
			if err != nil {
				return 0, 0, err
			}
			if !registered && pp != nil {
				deposits += pp.PoolDeposit
			}
		case *common.PoolRetirementCertificate:
			// Pool retirement refunds nothing in the tx
		case *common.StakeDeregistrationCertificate:
			if pp != nil {
				refunds += pp.KeyDeposit
			}
		case *common.DeregistrationCertificate:
			refunds += cert.Amount
		default:
		}
	}
	return deposits, refunds, nil
}

func minUTxOForOutput(out babbage.BabbageTransactionOutput, pp *ProtocolParametersExtra) uint64 {
	if pp == nil || pp.CoinsPerUTxOByte == 0 {
		return 0
	}
	// Try to serialize the output
	var cborBytes []byte
	if out.Cbor() != nil && len(out.Cbor()) > 0 {
		cborBytes = out.Cbor()
	} else {
		if b, err := cbor.Encode(out); err == nil {
			cborBytes = b
		}
	}
	if len(cborBytes) == 0 {
		return 0
	}
	// Babbage rule: (160 + serialized output size) * CoinsPerUTxOByte
	size := uint64(160 + len(cborBytes))
	return size * pp.CoinsPerUTxOByte
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
	deposits, refunds, err := computeDeposits(certBytesList, chain, ctx, ppConv)
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

	// Sort ada-only UTxOs deterministically (largest first, ties by tx id then index)
	sort.Slice(utxos, func(i, j int) bool {
		ai := uint64(0)
		aj := uint64(0)
		if v := utxos[i].Output.Amount(); v != nil {
			ai = v.Uint64()
		}
		if v := utxos[j].Output.Amount(); v != nil {
			aj = v.Uint64()
		}
		if ai != aj {
			return ai > aj
		}
		idI := utxos[i].Input.Id()
		idJ := utxos[j].Input.Id()
		if string(idI[:]) != string(idJ[:]) {
			if string(idI[:]) < string(idJ[:]) {
				return true
			}
			if string(idI[:]) > string(idJ[:]) {
				return false
			}
		}
		return utxos[i].Input.Index() < utxos[j].Input.Index()
	})

	baseBody := &conway.ConwayTransactionBody{
		TxInputs:       conway.NewConwayTransactionInputSet([]shelley.ShelleyTransactionInput{}),
		TxOutputs:      []babbage.BabbageTransactionOutput{},
		TxCertificates: []common.CertificateWrapper{},
		TxWithdrawals:  map[*common.Address]uint64{},
	}

	witnessCount := opts.WitnessCount
	if witnessCount == 0 {
		witnessCount = 1
	}

	ttl := opts.TTL
	if ttl == 0 {
		slot, err := chain.GetSlot(ctx)
		if err != nil {
			return nil, err
		}
		margin := uint64(3600)
		if opts.TTLMargin != 0 {
			margin = opts.TTLMargin
		}
		ttl = slot + margin
	}
	baseBody.Ttl = ttl

	// Add certificates
	for _, c := range certBytesList {
		var wrapper common.CertificateWrapper
		if _, err := cbor.Decode(c, &wrapper); err != nil {
			return nil, fmt.Errorf("decode certificate: %w", err)
		}
		baseBody.TxCertificates = append(baseBody.TxCertificates, wrapper)
	}

	// If no withdrawals, leave empty map or nil - must not emit empty withdrawals maps/sets in a bad form
	// But we need to be careful about what the body encoder emits; tests say "body without withdrawals has no withdrawals key"
	// We'll keep it nil/empty but let us see - in gouroboros, better to not set if empty? Initialize as nil is fine if we don't add.
	baseBody.TxWithdrawals = nil

	fee := uint64(200000)
	// Coin selection: take smallest prefix that covers outputs + fee + deposits - refunds
	// Try to build with increasing inputs
	selected := make([]shelley.ShelleyTransactionInput, 0, len(utxos))
	var inputSum uint64
	for i := 0; i < len(utxos); i++ {
		u := utxos[i]
		selected = append(selected, shelley.ShelleyTransactionInput{
			TxId:        u.Input.Id(),
			OutputIndex: u.Input.Index(),
		})
		if v := u.Output.Amount(); v != nil {
			inputSum += v.Uint64()
		}
		baseBody.TxInputs = conway.NewConwayTransactionInputSet(selected)

		// Estimate fee with current inputs
		for j := 0; j < 20; j++ {
			if inputSum < fee+deposits-refunds && !(deposits < refunds) { // handle case where refunds cover deposits? balance: inputs + refunds = outputs + fee + deposits
				break // need more inputs
			}
			// check balance with this fee
			if inputSum+refunds < fee+deposits {
				break
			}
			change := inputSum + refunds - fee - deposits
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
				return nil, err
			}
			if len(draftCbor) == 0 {
				return nil, errors.New("failed to marshal transaction")
			}
			estSize, err := bursa.EstimateWitnessedTxSize(draftCbor, witnessCount, 0)
			if err != nil {
				return nil, err
			}
			if ppConv != nil && ppConv.MaxTxSize > 0 && uint64(estSize) > ppConv.MaxTxSize {
				return nil, errors.New("transaction too large")
			}
			minFee, err := bursa.MinFee(estSize, *ppFee)
			if err != nil {
				return nil, err
			}
			if minFee <= fee {
				// Fee is sufficient
				txBody.TxFee = minFee
				if inputSum+refunds < minFee+deposits {
					break // need more inputs
				}
				change = inputSum + refunds - minFee - deposits
				// Check min-UTxO for change
				changeOut := babbage.BabbageTransactionOutput{
					OutputAddress: changeAddr,
					OutputAmount:  mary.MaryTransactionOutputValue{Amount: change},
				}
				minChange := minUTxOForOutput(changeOut, ppConv)
				if minChange > 0 && change < minChange {
					return nil, errors.New("change below minimum UTxO: output amount too small")
				}
				txBody.TxOutputs = []babbage.BabbageTransactionOutput{changeOut}
				finalTx := conway.ConwayTransaction{
					Body:       txBody,
					WitnessSet: conway.ConwayTransactionWitnessSet{},
					TxIsValid:  true,
				}
				finalCbor, err := finalTx.MarshalCBOR()
				if err != nil {
					return nil, err
				}
				if len(finalCbor) == 0 {
					return nil, errors.New("failed to marshal transaction")
				}
				// Re-encode and re-estimate; loop until the fee is stable and fee >= minFeeA * witnessedSize + minFeeB for the FINAL body
				// Do one more check
				estSizeFinal, err := bursa.EstimateWitnessedTxSize(finalCbor, witnessCount, 0)
				if err != nil {
					return nil, err
				}
				if ppConv != nil && ppConv.MaxTxSize > 0 && uint64(estSizeFinal) > ppConv.MaxTxSize {
					return nil, errors.New("transaction too large")
				}
				minFeeFinal, err := bursa.MinFee(estSizeFinal, *ppFee)
				if err != nil {
					return nil, err
				}
				if minFeeFinal != minFee {
					fee = minFeeFinal
					continue // loop again
				}
				// Ensure fee >= minFeeA * witnessedSize + minFeeB for the FINAL body
				if ppConv != nil {
					computed := ppConv.MinFeeA*uint64(estSizeFinal) + ppConv.MinFeeB
					if minFeeFinal < computed {
						minFeeFinal = computed
						// redo once
					}
				}
				if minFeeFinal > minFee {
					fee = minFeeFinal
					continue
				}
				if minFeeFinal < minFee {
					// should not happen
				}
				// Set final fee
				txBody.TxFee = minFeeFinal
				if inputSum+refunds < minFeeFinal+deposits {
					break
				}
				change = inputSum + refunds - minFeeFinal - deposits
				changeOut = babbage.BabbageTransactionOutput{
					OutputAddress: changeAddr,
					OutputAmount:  mary.MaryTransactionOutputValue{Amount: change},
				}
				minChange = minUTxOForOutput(changeOut, ppConv)
				if minChange > 0 && change < minChange {
					return nil, errors.New("change below minimum UTxO: output amount too small")
				}
				txBody.TxOutputs = []babbage.BabbageTransactionOutput{changeOut}
				finalTx = conway.ConwayTransaction{
					Body:       txBody,
					WitnessSet: conway.ConwayTransactionWitnessSet{},
					TxIsValid:  true,
				}
				finalCbor, err = finalTx.MarshalCBOR()
				if err != nil {
					return nil, err
				}
				if len(finalCbor) == 0 {
					return nil, errors.New("failed to marshal transaction")
				}
				// One more stability check
				estSizeFinal2, err := bursa.EstimateWitnessedTxSize(finalCbor, witnessCount, 0)
				if err != nil {
					return nil, err
				}
				if ppConv != nil && ppConv.MaxTxSize > 0 && uint64(estSizeFinal2) > ppConv.MaxTxSize {
					return nil, errors.New("transaction too large")
				}
				minFeeFinal2, err := bursa.MinFee(estSizeFinal2, *ppFee)
				if err != nil {
					return nil, err
				}
				if minFeeFinal2 != minFeeFinal {
					fee = minFeeFinal2
					continue
				}
				if ppConv != nil {
					computed := ppConv.MinFeeA*uint64(estSizeFinal2) + ppConv.MinFeeB
					if minFeeFinal2 < computed {
						fee = computed
						continue
					}
				}
				if minFeeFinal2 > minFeeFinal {
					fee = minFeeFinal2
					continue
				}
				return &BuiltTx{
					TxCBOR:         finalCbor,
					TxEnvelopeType: "Unwitnessed Tx ConwayEra",
				}, nil
			}
			fee = minFee
		}
		// If we broke because need more inputs, continue to add next
		if inputSum+refunds < fee+deposits {
			continue
		}
	}
	if inputSum+refunds < fee+deposits {
		return nil, errors.New("insufficient funds")
	}
	return nil, errors.New("failed to build transaction")
}
