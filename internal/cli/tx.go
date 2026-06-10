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

func RunTxSign(txFile string, signingKeyFiles []string, outFile string) error {
	txBytes, err := bursa.ReadCborInputFile(txFile)
	if err != nil {
		return err
	}
	if len(signingKeyFiles) == 0 {
		return errors.New("at least one --signing-key-file is required")
	}
	signers := make([]*bursa.LoadedKey, 0, len(signingKeyFiles))
	for _, p := range signingKeyFiles {
		lk, err := bursa.LoadKeyFromFile(p)
		if err != nil {
			return err
		}
		signers = append(signers, lk)
	}
	signed, err := bursa.SignTransaction(txBytes, signers)
	if err != nil {
		return err
	}
	out, err := bursa.WriteCborEnvelope("Tx", "Signed transaction", signed, outFile)
	if err != nil {
		return err
	}
	if outFile == "" {
		fmt.Print(out)
	}
	return nil
}

func RunTxWitness(txFile, signingKeyFile, outFile string) error {
	txBytes, err := bursa.ReadCborInputFile(txFile)
	if err != nil {
		return err
	}
	lk, err := bursa.LoadKeyFromFile(signingKeyFile)
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
	out, err := bursa.WriteCborEnvelope("TxWitness", "Detached vkey witness", witCbor, outFile)
	if err != nil {
		return err
	}
	if outFile == "" {
		fmt.Print(out)
	}
	return nil
}

func RunTxAssemble(txFile string, witnessFiles []string, outFile string) error {
	txBytes, err := bursa.ReadCborInputFile(txFile)
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
	signed, err := bursa.AssembleTransaction(txBytes, wits)
	if err != nil {
		return err
	}
	out, err := bursa.WriteCborEnvelope("Tx", "Assembled signed transaction", signed, outFile)
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

func RunTxDecode(txFile, protocolParamsFile string) error {
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
		MinFee *uint64 `json:"min_fee,omitempty"`
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
		fee := bursa.MinFee(insp.SizeBytes, params)
		out.MinFee = &fee
	}
	enc, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(enc))
	return nil
}
