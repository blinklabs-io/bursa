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

package bursa

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// CborEnvelope is the cardano-cli-compatible JSON text envelope.
type CborEnvelope struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	CborHex     string `json:"cborHex"`
}

// ReadCborInput accepts either raw hex-encoded CBOR or a JSON text envelope
// and returns the decoded CBOR bytes.
func ReadCborInput(data []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var env CborEnvelope
		if err := json.Unmarshal(trimmed, &env); err != nil {
			return nil, fmt.Errorf("failed to parse JSON envelope: %w", err)
		}
		raw, err := hex.DecodeString(strings.TrimSpace(env.CborHex))
		if err != nil {
			return nil, fmt.Errorf("failed to decode cborHex: %w", err)
		}
		return raw, nil
	}
	raw, err := hex.DecodeString(string(bytes.TrimSpace(trimmed)))
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex CBOR: %w", err)
	}
	return raw, nil
}

// ReadCborInputFile reads a file and returns its decoded CBOR bytes.
func ReadCborInputFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %w", path, err)
	}
	return ReadCborInput(data)
}

// WriteCborEnvelope writes CBOR data as a JSON text envelope to outputFile,
// or returns the JSON string (and writes nothing) when outputFile is empty.
func WriteCborEnvelope(envType, description string, cborData []byte, outputFile string) (string, error) {
	env := CborEnvelope{
		Type:        envType,
		Description: description,
		CborHex:     hex.EncodeToString(cborData),
	}
	out, err := json.MarshalIndent(env, "", "    ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal envelope: %w", err)
	}
	out = append(out, '\n')
	if outputFile == "" {
		return string(out), nil
	}
	if err := os.WriteFile(outputFile, out, 0o600); err != nil {
		return "", fmt.Errorf("failed to write %q: %w", outputFile, err)
	}
	return string(out), nil
}
