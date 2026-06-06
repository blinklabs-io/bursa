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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/blinklabs-io/bursa"
)

func readPayload(text, hexStr string) ([]byte, error) {
	switch {
	case text != "" && hexStr != "":
		return nil, errors.New("provide only one of --payload or --payload-hex")
	case hexStr != "":
		return hex.DecodeString(hexStr)
	case text != "":
		return []byte(text), nil
	default:
		return nil, errors.New("provide --payload or --payload-hex")
	}
}

func readOptionalPayload(text, hexStr string) ([]byte, error) {
	switch {
	case text != "" && hexStr != "":
		return nil, errors.New("provide only one of --payload or --payload-hex")
	case hexStr != "":
		return hex.DecodeString(hexStr)
	case text != "":
		return []byte(text), nil
	default:
		return nil, nil
	}
}

func RunSignData(addressHex, payloadText, payloadHex, signingKeyFile string) error {
	addr, err := hex.DecodeString(addressHex)
	if err != nil {
		return fmt.Errorf("invalid --address hex: %w", err)
	}
	payload, err := readPayload(payloadText, payloadHex)
	if err != nil {
		return err
	}
	lk, err := bursa.LoadKeyFromFile(signingKeyFile)
	if err != nil {
		return err
	}
	sig, key, err := bursa.SignData(addr, payload, lk)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(map[string]string{"signature": sig, "key": key}, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal signature output: %w", err)
	}
	fmt.Println(string(out))
	return nil
}

func RunVerifyData(signatureHex, keyHex, payloadText, payloadHex string) error {
	payload, err := readOptionalPayload(payloadText, payloadHex)
	if err != nil {
		return err
	}
	ok, err := bursa.VerifyData(signatureHex, keyHex, payload)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("signature is INVALID")
	}
	fmt.Println("VALID")
	return nil
}
