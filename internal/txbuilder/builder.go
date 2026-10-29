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
	"sort"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/ledger/babbage"
	"github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/conway"
	"github.com/blinklabs-io/gouroboros/ledger/mary"
	"github.com/blinklabs-io/gouroboros/ledger/shelley"
)

// DefaultTTLMargin is the number of slots a transaction stays valid for when
// BuildOptions sets neither TTL nor TTLMargin.
const DefaultTTLMargin = 3600

// PoolVote represents a stake pool governance vote.
type PoolVote struct {
	PoolKeyHash [28]byte
	ActionTxId  [32]byte
	ActionIndex uint32
	Vote        uint8
	Anchor      *common.GovAnchor
}

type BuildOptions struct {
	ChangeAddress    string
	CertificateFiles []string
	WitnessCount     uint
	TTL              uint64
	TTLMargin        uint64 // slots added to the current slot when TTL is 0
	Vote             *PoolVote
}

type BuiltTx struct {
	TxCBOR            []byte
	TxEnvelopeType    string // e.g. "Unwitnessed Tx ConwayEra"
	RequiredWitnesses []RequiredWitness
}

func (b *BuiltTx) Enveloped() (string, error) {
	return bursa.WriteCborEnvelope(b.TxEnvelopeType, "Unwitnessed Tx", b.TxCBOR, "")
}

func computeDeposits(certs [][]byte, chain Chain, ctx context.Context, pp *ProtocolParametersExtra) (uint64, uint64, error) {
	wrappers := make([]common.CertificateWrapper, 0, len(certs))
	for _, c := range certs {
		var wrapper common.CertificateWrapper
		if _, err := cbor.Decode(c, &wrapper); err != nil {
			return 0, 0, fmt.Errorf("decode certificate: %w", err)
		}
		wrappers = append(wrappers, wrapper)
	}

	// A credential registered in this transaction pays the current
	// protocol deposit, so a legacy deregistration of it refunds that.
	registered := map[StakeCredentialKey]bool{}
	for _, wrapper := range wrappers {
		switch cert := wrapper.Certificate.(type) {
		case *common.StakeRegistrationCertificate:
			registered[StakeCredentialKeyFrom(cert.StakeCredential)] = true
		case *common.RegistrationCertificate:
			registered[StakeCredentialKeyFrom(cert.StakeCredential)] = true
		case *common.StakeRegistrationDelegationCertificate:
			registered[StakeCredentialKeyFrom(cert.StakeCredential)] = true
		case *common.VoteRegistrationDelegationCertificate:
			registered[StakeCredentialKeyFrom(cert.StakeCredential)] = true
		case *common.StakeVoteRegistrationDelegationCertificate:
			registered[StakeCredentialKeyFrom(cert.StakeCredential)] = true
		}
	}

	// A legacy deregistration refunds the deposit recorded when the
	// credential registered, not the current protocol parameter.
	var legacyDeregCreds []common.Credential
	for _, wrapper := range wrappers {
		if cert, ok := wrapper.Certificate.(*common.StakeDeregistrationCertificate); ok {
			if !registered[StakeCredentialKeyFrom(cert.StakeCredential)] {
				legacyDeregCreds = append(legacyDeregCreds, cert.StakeCredential)
			}
		}
	}
	recordedDeposits := map[StakeCredentialKey]uint64{}
	if len(legacyDeregCreds) > 0 {
		var err error
		recordedDeposits, err = chain.GetStakeDelegDeposits(ctx, legacyDeregCreds)
		if err != nil {
			return 0, 0, err
		}
	}

	seenPools := map[string]bool{}
	var deposits uint64
	var refunds uint64
	for _, wrapper := range wrappers {
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
			poolRegistered, err := chain.GetPoolRegistration(ctx, poolId)
			if err != nil {
				return 0, 0, err
			}
			key := string(poolId)
			if !poolRegistered && !seenPools[key] && pp != nil {
				deposits += pp.PoolDeposit
			}
			seenPools[key] = true
		case *common.PoolRetirementCertificate:
			// Pool retirement refunds nothing in the tx
		case *common.StakeDeregistrationCertificate:
			key := StakeCredentialKeyFrom(cert.StakeCredential)
			if registered[key] {
				if pp != nil {
					refunds += pp.KeyDeposit
				}
			} else {
				refunds += recordedDeposits[key]
			}
		case *common.DeregistrationCertificate:
			refunds += cert.Amount
		case *common.DeregistrationDrepCertificate:
			// UnRegDRepTxCert carries its refund explicitly; it
			// counts on the consumed side like a stake
			// deregistration refund.
			refunds += cert.Amount
		case *common.GenesisKeyDelegationCertificate:
			return 0, 0, errors.New("certificate type 5 (genesis key delegation) is no longer supported")
		case *common.MoveInstantaneousRewardsCertificate:
			return 0, 0, errors.New("certificate type 6 (move instantaneous rewards) is no longer supported")
		default:
		}
	}
	return deposits, refunds, nil
}

// minUTxO is the Babbage minimum for an output:
// (160 + serialized output size) * coinsPerUTxOByte.
func minUTxO(out babbage.BabbageTransactionOutput, pp *ProtocolParametersExtra) (uint64, error) {
	if pp == nil || pp.CoinsPerUTxOByte == 0 {
		return 0, nil
	}
	b, err := cbor.Encode(&out)
	if err != nil {
		return 0, fmt.Errorf("encode change output: %w", err)
	}
	return uint64(160+len(b)) * pp.CoinsPerUTxOByte, nil
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
	if _, ok := changeAddr.PayloadPayload().(common.AddressPayloadScriptHash); ok {
		return nil, errors.New("change address payment credential must be a key, not a script")
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

	ttl := opts.TTL
	if ttl == 0 {
		margin := opts.TTLMargin
		if margin == 0 {
			margin = DefaultTTLMargin
		}
		slot, err := chain.GetSlot(ctx)
		if err != nil {
			return nil, err
		}
		if margin > ^uint64(0)-slot {
			return nil, errors.New("ttl margin overflows slot + margin")
		}
		ttl = slot + margin
	}

	body := conway.ConwayTransactionBody{Ttl: ttl}
	for _, c := range certBytesList {
		var wrapper common.CertificateWrapper
		if _, err := cbor.Decode(c, &wrapper); err != nil {
			return nil, fmt.Errorf("decode certificate: %w", err)
		}
		body.TxCertificates = append(body.TxCertificates, wrapper)
	}
	if opts.Vote != nil {
		voter := common.Voter{
			Type: common.VoterTypeStakingPoolKeyHash,
			Hash: common.Blake2b224(opts.Vote.PoolKeyHash),
		}
		actionId := common.GovActionId{
			TransactionId: common.Blake2b256(opts.Vote.ActionTxId),
			GovActionIdx:  opts.Vote.ActionIndex,
		}
		procedure := common.VotingProcedure{
			Vote: opts.Vote.Vote,
		}
		if opts.Vote.Anchor != nil {
			procedure.Anchor = opts.Vote.Anchor
		}
		body.TxVotingProcedures = common.VotingProcedures{
			&voter: {
				&actionId: procedure,
			},
		}
	}

	// Add inputs largest first until one balances with a change output at
	// or above the minimum UTxO.
	b := balancer{
		body:         body,
		changeAddr:   changeAddr,
		witnessCount: opts.WitnessCount,
		pp:           ppFee,
		extra:        ppConv,
		need:         deposits,
		refunds:      refunds,
	}
	lastErr := errNeedMoreInput
	var selected []UTxO
	for _, u := range utxos {
		b.inputs = append(b.inputs, shelley.ShelleyTransactionInput{
			TxId:        u.Input.Id(),
			OutputIndex: u.Input.Index(),
		})
		if v := u.Output.Amount(); v != nil {
			b.inputSum += v.Uint64()
		}
		selected = append(selected, u)
		// The witness count sizes the fee, so it depends on the inputs
		// selected so far. Recompute it for each candidate set.
		required := requiredWitnessSet(body, selected)
		if opts.WitnessCount > 0 && opts.WitnessCount < uint(len(required)) {
			return nil, fmt.Errorf(
				"--witness-count %d is below the %d required witnesses",
				opts.WitnessCount,
				len(required),
			)
		}
		if opts.WitnessCount > 0 {
			b.witnessCount = opts.WitnessCount
		} else {
			b.witnessCount = uint(len(required))
		}
		txCbor, err := b.balance()
		if err == nil {
			return &BuiltTx{
				TxCBOR:            txCbor,
				TxEnvelopeType:    "Unwitnessed Tx ConwayEra",
				RequiredWitnesses: required,
			}, nil
		}
		if !errors.Is(err, errNeedMoreInput) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

var errNeedMoreInput = errors.New("insufficient funds")

// balancer sets the fee and change for a fixed set of inputs.
type balancer struct {
	body         conway.ConwayTransactionBody
	changeAddr   common.Address
	witnessCount uint
	pp           *bursa.ProtocolParams
	extra        *ProtocolParametersExtra
	inputs       []shelley.ShelleyTransactionInput
	inputSum     uint64
	need         uint64 // deposits
	refunds      uint64
}

// balance returns the encoded transaction once its fee covers the minimum
// fee of that exact encoding with its witnesses added. The fee only grows,
// so the loop ends when an encoding needs no more than the fee it carries.
func (b *balancer) balance() ([]byte, error) {
	var fee uint64
	for range 10 {
		available := b.inputSum + b.refunds
		if available < fee+b.need {
			return nil, errNeedMoreInput
		}
		change := babbage.BabbageTransactionOutput{
			OutputAddress: b.changeAddr,
			OutputAmount: mary.MaryTransactionOutputValue{
				Amount: available - fee - b.need,
			},
		}
		minChange, err := minUTxO(change, b.extra)
		if err != nil {
			return nil, err
		}
		if change.OutputAmount.Amount < minChange {
			return nil, fmt.Errorf(
				"%w: change %d is below the minimum UTxO %d",
				errNeedMoreInput, change.OutputAmount.Amount, minChange,
			)
		}
		body := b.body
		body.TxInputs = conway.NewConwayTransactionInputSet(b.inputs)
		body.TxOutputs = []babbage.BabbageTransactionOutput{change}
		body.TxFee = fee
		tx := conway.ConwayTransaction{Body: body, TxIsValid: true}
		txCbor, err := tx.MarshalCBOR()
		if err != nil {
			return nil, fmt.Errorf("encode transaction: %w", err)
		}
		size, err := bursa.EstimateWitnessedTxSize(txCbor, b.witnessCount, 0)
		if err != nil {
			return nil, err
		}
		if size < 0 {
			return nil, fmt.Errorf("invalid transaction size %d", size)
		}
		if b.extra.MaxTxSize > 0 && uint64(size) > b.extra.MaxTxSize {
			return nil, fmt.Errorf(
				"transaction size %d exceeds the maximum %d",
				size, b.extra.MaxTxSize,
			)
		}
		minFee, err := bursa.MinFee(size, *b.pp)
		if err != nil {
			return nil, err
		}
		if minFee <= fee {
			return txCbor, nil
		}
		fee = minFee
	}
	return nil, errors.New("fee did not converge")
}
