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

package survey_test

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/Salvionied/apollo/v2/backend"
	"github.com/blinklabs-io/bursa/ui/internal/chain"
	"github.com/blinklabs-io/bursa/ui/internal/keystore"
	"github.com/blinklabs-io/bursa/ui/internal/spend"
	"github.com/blinklabs-io/bursa/ui/internal/survey"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/ledger"
	"github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/shelley"
	"github.com/blinklabs-io/plutigo/data"
	utxorpc "github.com/utxorpc/go-codegen/utxorpc/v1alpha/cardano"
)

const flowMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// flowChain accepts locally signed transactions, then exposes their label-17
// metadata through the same read interface the survey service uses. It keeps
// the test on the real builder, codec, witness, submit, discovery and tally
// path without depending on a funded public wallet.
type flowChain struct {
	utxos   map[string][]common.Utxo
	labels  []chain.LabelMetadata
	txs     map[string]chain.TxInfo
	signers map[string][]string
	height  uint64
	params  backend.ProtocolParameters
}

func newFlowChain(t *testing.T, address string) *flowChain {
	t.Helper()
	addr, err := common.NewAddress(address)
	if err != nil {
		t.Fatal(err)
	}
	var txID common.Blake2b256
	copy(txID[:], []byte("fund-survey-flow-integration-test"))
	input := shelley.ShelleyTransactionInput{TxId: txID, OutputIndex: 0}
	out := &flowOutput{address: addr, lovelace: 50_000_000}
	return &flowChain{
		utxos: map[string][]common.Utxo{address: {{Id: input, Output: out}}},
		txs:   make(map[string]chain.TxInfo), signers: make(map[string][]string), height: 100,
		params: backend.ProtocolParameters{
			MinFeeConstant: 155381, MinFeeCoefficient: 44, MaxTxSize: 16384,
			CoinsPerUtxoByte: "4310", KeyDeposits: "2000000", PoolDeposits: "500000000",
		},
	}
}

type flowOutput struct {
	address  common.Address
	lovelace uint64
}

func (o *flowOutput) Address() common.Address                                 { return o.address }
func (o *flowOutput) Amount() *big.Int                                        { return new(big.Int).SetUint64(o.lovelace) }
func (o *flowOutput) Assets() *common.MultiAsset[common.MultiAssetTypeOutput] { return nil }
func (o *flowOutput) Datum() *common.Datum                                    { return nil }
func (o *flowOutput) DatumHash() *common.Blake2b256                           { return nil }
func (o *flowOutput) Cbor() []byte                                            { return nil }
func (o *flowOutput) Utxorpc() (*utxorpc.TxOutput, error)                     { return nil, nil }
func (o *flowOutput) ScriptRef() common.Script                                { return nil }
func (o *flowOutput) ToPlutusData() data.PlutusData                           { return nil }
func (o *flowOutput) String() string                                          { return o.address.String() }

func (f *flowChain) ProtocolParams() (backend.ProtocolParameters, error) { return f.params, nil }
func (f *flowChain) GenesisParams() (backend.GenesisParameters, error) {
	return backend.GenesisParameters{ActiveSlotsCoefficient: 0.05, EpochLength: 432000, SlotLength: 1, NetworkMagic: 1}, nil
}
func (f *flowChain) NetworkId() uint8              { return 0 }
func (f *flowChain) CurrentEpoch() (uint64, error) { return 50, nil }
func (f *flowChain) MaxTxFee() (uint64, error)     { return backend.ComputeMaxTxFee(f.params) }
func (f *flowChain) Tip() (uint64, error)          { return 10_000_000, nil }
func (f *flowChain) Utxos(address common.Address) ([]common.Utxo, error) {
	return f.utxos[address.String()], nil
}
func (f *flowChain) EvaluateTx([]byte, []common.Utxo) (map[common.RedeemerKey]common.ExUnits, error) {
	return nil, nil
}
func (f *flowChain) UtxoByRef(hash common.Blake2b256, index uint32) (*common.Utxo, error) {
	for _, list := range f.utxos {
		for _, u := range list {
			if u.Id.Id() == hash && u.Id.Index() == index {
				copy := u
				return &copy, nil
			}
		}
	}
	return nil, nil
}
func (f *flowChain) ScriptCbor(common.Blake2b224) ([]byte, error) { return nil, nil }

func (f *flowChain) SubmitTx(raw []byte) (common.Blake2b256, error) {
	tx, err := ledger.NewConwayTransactionFromCbor(raw)
	if err != nil {
		return common.Blake2b256{}, err
	}
	metadata, ok := tx.Metadata().(common.MetaMap)
	if !ok {
		return common.Blake2b256{}, errors.New("submitted transaction has no metadata map")
	}
	var labelValue common.TransactionMetadatum
	for _, pair := range metadata.Pairs {
		key, ok := pair.Key.(common.MetaInt)
		if ok && key.Value != nil && key.Value.IsUint64() && key.Value.Uint64() == survey.Label {
			labelValue = pair.Value
			break
		}
	}
	if labelValue == nil {
		return common.Blake2b256{}, errors.New("submitted transaction has no label-17 value")
	}
	labelCBOR, err := cbor.Encode(labelValue)
	if err != nil {
		return common.Blake2b256{}, err
	}
	hash := tx.Id()
	hashHex := hex.EncodeToString(hash[:])
	f.labels = append(f.labels, chain.LabelMetadata{TxHash: hashHex, CBOR: labelCBOR})
	f.height++
	f.txs[hashHex] = chain.TxInfo{Hash: hashHex, BlockHeight: f.height, Index: 0, BlockTime: time.Now().Unix()}
	for _, signer := range tx.RequiredSigners() {
		f.signers[hashHex] = append(f.signers[hashHex], hex.EncodeToString(signer[:]))
	}
	return hash, nil
}

func (f *flowChain) MetadataByLabelPage(_ context.Context, label uint64, page int) ([]chain.LabelMetadata, error) {
	if label != survey.Label || page < 1 {
		return nil, errors.New("unexpected metadata page request")
	}
	start := min((page-1)*chain.LabelPageSize, len(f.labels))
	end := min(start+chain.LabelPageSize, len(f.labels))
	return append([]chain.LabelMetadata(nil), f.labels[start:end]...), nil
}
func (f *flowChain) Transaction(_ context.Context, hash string) (chain.TxInfo, error) {
	tx, ok := f.txs[hash]
	if !ok {
		return chain.TxInfo{}, chain.ErrNotFound
	}
	return tx, nil
}
func (f *flowChain) RequiredSigners(_ context.Context, hash string) ([]string, error) {
	return append([]string(nil), f.signers[hash]...), nil
}
func (f *flowChain) LatestEpoch(context.Context) (chain.EpochInfo, error) {
	now := time.Now().Unix()
	return chain.EpochInfo{Epoch: 50, StartTime: now - 50, EndTime: now + 50}, nil
}
func (f *flowChain) Genesis(context.Context) (chain.Genesis, error) {
	return chain.Genesis{EpochLength: 100, SlotLength: 1}, nil
}
func (f *flowChain) DRep(context.Context, string) (chain.DRepInfo, error) {
	return chain.DRepInfo{}, chain.ErrNotFound
}
func (f *flowChain) Pool(context.Context, string) (chain.PoolInfo, error) {
	return chain.PoolInfo{}, chain.ErrNotFound
}
func (f *flowChain) Account(context.Context, string) (chain.AccountInfo, error) {
	return chain.AccountInfo{}, chain.ErrNotFound
}
func (f *flowChain) GovernanceAnchorDocuments(context.Context) ([]chain.AnchorDocument, error) {
	return nil, nil
}

// SurveyRoleSnapshot matches the live role lookups above: no credential holds
// a governance role, and keyholder claims need no ledger state.
func (f *flowChain) SurveyRoleSnapshot(
	_ context.Context,
	_ uint64,
	claims []chain.SurveyRoleClaim,
) (map[chain.SurveyRoleClaim]bool, error) {
	ret := make(map[chain.SurveyRoleClaim]bool, len(claims))
	for _, claim := range claims {
		ret[claim] = claim.Role == chain.SurveyRoleKeyholder
	}
	return ret, nil
}

func TestCreateRespondCancelRoundTripsThroughSignedTransactions(t *testing.T) {
	ctx := context.Background()
	password := "integration-password"
	account, err := wallet.Derive(flowMnemonic, "preview", 2)
	if err != nil {
		t.Fatal(err)
	}
	node := newFlowChain(t, account.ReceiveAddresses[0])
	spends := spend.NewService(node, keystore.New(filepath.Join(t.TempDir(), "wallet.json")), nil)
	if _, err := spends.SetWallet(flowMnemonic, "preview", password); err != nil {
		t.Fatal(err)
	}
	surveys := survey.NewService(node, "preview")
	surveys.SetBuilder(spends)

	questions := []survey.Question{
		{Kind: survey.KindCustom, Prompt: "Method", Anchor: &survey.Anchor{URI: "ipfs://schema", Hash: [32]byte{1}}},
		{Kind: survey.KindSingleChoice, Prompt: "Pick", Options: []string{"a", "b"}},
		{Kind: survey.KindMultiSelect, Prompt: "Select", Options: []string{"a", "b"}, Min: 0, Max: 2},
		{Kind: survey.KindRanking, Prompt: "Rank", Options: []string{"a", "b"}, Min: 1, Max: 2},
		{Kind: survey.KindNumericRange, Prompt: "Number", Range: &survey.Range{Min: 1, Max: 9}},
		{Kind: survey.KindPointsAllocation, Prompt: "Points", Options: []string{"a", "b"}, Budget: 10},
		{Kind: survey.KindRating, Prompt: "Rate", Options: []string{"a", "b"}, Scale: &survey.RatingScale{Levels: 5}},
	}
	preview, err := surveys.Create(ctx, survey.CreateRequest{Title: "All kinds", Roles: []survey.Role{survey.RoleKeyholder}, EndEpoch: 60, Questions: questions})
	if err != nil {
		t.Fatal(err)
	}
	created, err := spends.Confirm(ctx, preview.PendingID, password)
	if err != nil {
		t.Fatal(err)
	}
	id := created.TxHash + ":0"
	detail, err := surveys.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(detail.Definition.Questions) != 7 || !detail.Owned {
		t.Fatalf("discovered definition = %+v", detail)
	}

	custom, err := common.DecodeMetadatumRaw([]byte{0x82, 0x61, 0x78, 0x18, 0x2a})
	if err != nil {
		t.Fatal(err)
	}
	answers := []survey.Answer{
		{Kind: survey.KindCustom, Question: 0, Custom: custom},
		{Kind: survey.KindSingleChoice, Question: 1, Choice: 1},
		{Kind: survey.KindMultiSelect, Question: 2, Indices: []uint64{}},
		{Kind: survey.KindRanking, Question: 3, Indices: []uint64{1, 0}},
		{Kind: survey.KindNumericRange, Question: 4, Number: 5},
		{Kind: survey.KindPointsAllocation, Question: 5, Pairs: []survey.Pair{{Option: 0, Value: 4}, {Option: 1, Value: 6}}},
		{Kind: survey.KindRating, Question: 6, Pairs: []survey.Pair{{Option: 0, Value: 3}}},
	}
	preview, err = surveys.Respond(ctx, survey.RespondRequest{Survey: id, Role: survey.RoleKeyholder, Answers: answers})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spends.Confirm(ctx, preview.PendingID, password); err != nil {
		t.Fatal(err)
	}
	detail, err = surveys.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Tally == nil || len(detail.Tally.Roles) != 1 || detail.Tally.Roles[0].Responses != 1 {
		t.Fatalf("tally = %+v", detail.Tally)
	}
	for i, question := range detail.Tally.Roles[0].Questions {
		if question.Answered != 1 || question.Abstained != 0 {
			t.Fatalf("question %d tally = %+v", i, question)
		}
	}

	preview, err = surveys.Cancel(ctx, survey.CancelRequest{Survey: id})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spends.Confirm(ctx, preview.PendingID, password); err != nil {
		t.Fatal(err)
	}
	detail, err = surveys.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Status != "cancelled" || detail.Tally != nil {
		t.Fatalf("cancelled detail = %+v", detail)
	}
}
