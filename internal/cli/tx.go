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
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/blinklabs-io/bursa"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// readTxFile reads a transaction file and resolves its era from era (the
// --era flag), its envelope type, or unambiguous CBOR.
func readTxFile(path, era string) ([]byte, uint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read %q: %w", path, err)
	}
	txBytes, txType, err := bursa.ReadTxInput(data, era)
	if errors.Is(err, bursa.ErrAmbiguousTxEra) {
		return nil, 0, fmt.Errorf("%w; pass --era or an era-typed envelope such as \"Tx ConwayEra\"", err)
	}
	return txBytes, txType, err
}

func RunTxSign(txFile string, signingKeyFiles []string, outFile, era string) error {
	txBytes, txType, err := readTxFile(txFile, era)
	if err != nil {
		return err
	}
	if len(signingKeyFiles) == 0 {
		return errors.New("at least one --signing-key-file is required")
	}
	signers := make([]*bursa.LoadedKey, 0, len(signingKeyFiles))
	for _, p := range signingKeyFiles {
		lk, err := bursa.LoadSecretKeyFromFile(p)
		if err != nil {
			return err
		}
		signers = append(signers, lk)
	}
	signed, err := bursa.SignTransactionForEra(txBytes, txType, signers)
	if err != nil {
		return err
	}
	envType, _ := bursa.TxEnvelopeTypes(txType)
	out, err := bursa.WriteCborEnvelope(envType, "Signed transaction", signed, outFile)
	if err != nil {
		return err
	}
	if outFile == "" {
		fmt.Print(out)
	}
	return nil
}

func RunTxWitness(txFile, signingKeyFile, outFile, era string) error {
	txBytes, txType, err := readTxFile(txFile, era)
	if err != nil {
		return err
	}
	lk, err := bursa.LoadSecretKeyFromFile(signingKeyFile)
	if err != nil {
		return err
	}
	wit, err := bursa.WitnessTransaction(txBytes, lk)
	if err != nil {
		return err
	}
	witCbor, err := bursa.EncodeWitness(wit)
	if err != nil {
		return err
	}
	_, envType := bursa.TxEnvelopeTypes(txType)
	out, err := bursa.WriteCborEnvelope(envType, "Detached vkey witness", witCbor, outFile)
	if err != nil {
		return err
	}
	if outFile == "" {
		fmt.Print(out)
	}
	return nil
}

func RunTxAssemble(txFile string, witnessFiles []string, outFile, era string) error {
	txBytes, txType, err := readTxFile(txFile, era)
	if err != nil {
		return err
	}
	if len(witnessFiles) == 0 {
		return errors.New("at least one --witness-file is required")
	}
	wits := make([]lcommon.VkeyWitness, 0, len(witnessFiles))
	for _, p := range witnessFiles {
		raw, err := bursa.ReadCborInputFile(p)
		if err != nil {
			return err
		}
		w, err := bursa.DecodeWitness(raw)
		if err != nil {
			return err
		}
		wits = append(wits, w)
	}
	signed, err := bursa.AssembleTransactionForEra(txBytes, txType, wits)
	if err != nil {
		return err
	}
	envType, _ := bursa.TxEnvelopeTypes(txType)
	out, err := bursa.WriteCborEnvelope(envType, "Assembled signed transaction", signed, outFile)
	if err != nil {
		return err
	}
	if outFile == "" {
		fmt.Print(out)
	}
	return nil
}

func RunTxId(txFile string) error {
	txBytes, err := bursa.ReadCborInputFile(txFile)
	if err != nil {
		return err
	}
	id, err := bursa.TransactionID(txBytes)
	if err != nil {
		return err
	}
	fmt.Println(id)
	return nil
}

// Per-witness estimates include per-element witness-set framing in addition to
// the encoded witness itself (101 bytes for vkey and 136 bytes for bootstrap).
const (
	vkeyWitnessSizeEstimate      = 102
	bootstrapWitnessSizeEstimate = 139
)

func estimateMinFeeSize(sizeBytes int, witnessCount, byronWitnessCount uint) (int, error) {
	if sizeBytes < 0 {
		return 0, fmt.Errorf("negative transaction size %d", sizeBytes)
	}
	maxInt := uint64(^uint(0) >> 1)
	estimated := uint64(sizeBytes) //nolint:gosec // checked non-negative
	for _, adjustment := range []struct {
		name  string
		count uint
		size  uint64
	}{
		{name: "vkey", count: witnessCount, size: vkeyWitnessSizeEstimate},
		{name: "bootstrap", count: byronWitnessCount, size: bootstrapWitnessSizeEstimate},
	} {
		count := uint64(adjustment.count)
		if count > (maxInt-estimated)/adjustment.size {
			return 0, fmt.Errorf("%s witness count %d overflows transaction size", adjustment.name, adjustment.count)
		}
		estimated += count * adjustment.size
	}
	return int(estimated), nil //nolint:gosec // bounded by maxInt above
}

func RunTxDecode(txFile, protocolParamsFile string, witnessCount, byronWitnessCount uint) error {
	txBytes, err := bursa.ReadCborInputFile(txFile)
	if err != nil {
		return err
	}
	insp, err := bursa.InspectTransaction(txBytes)
	if err != nil {
		return err
	}
	type decodeOut struct {
		*bursa.TxInspection
		MinFee     *uint64 `json:"min_fee,omitempty"`
		MinFeeNote string  `json:"min_fee_note,omitempty"`
	}
	out := decodeOut{TxInspection: insp}
	if protocolParamsFile != "" {
		raw, err := os.ReadFile(protocolParamsFile)
		if err != nil {
			return err
		}
		params, err := bursa.ParseProtocolParams(raw)
		if err != nil {
			return err
		}
		estimatedSize, err := estimateMinFeeSize(insp.SizeBytes, witnessCount, byronWitnessCount)
		if err != nil {
			return fmt.Errorf("calculate minimum fee: %w", err)
		}
		fee, err := bursa.MinFee(estimatedSize, params)
		if err != nil {
			return fmt.Errorf("calculate minimum fee: %w", err)
		}
		out.MinFee = &fee
		out.MinFeeNote = "Minimum fee for the transaction as decoded."
		if witnessCount > 0 || byronWitnessCount > 0 {
			out.MinFeeNote = fmt.Sprintf(
				"Minimum fee for the transaction as decoded, adjusted for %d additional vkey witnesses and %d additional bootstrap witnesses.",
				witnessCount,
				byronWitnessCount,
			)
		}
	}
	enc, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(enc))
	return nil
}
