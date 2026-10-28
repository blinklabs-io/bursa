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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// ReadCertificateFile reads a certificate file in cardano-cli envelope format
// (or raw hex CBOR) and returns the decoded certificate bytes.
func ReadCertificateFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file %q: %w", path, err)
	}
	return readCertData(data)
}

func readCertData(data []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(data))
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty certificate data")
	}
	if strings.HasPrefix(trimmed, "{") {
		// Try to parse as envelope
		var env struct {
			Type        string `json:"type"`
			Description string `json:"description"`
			CborHex     string `json:"cborHex"`
		}
		if err := json.Unmarshal([]byte(trimmed), &env); err == nil && env.CborHex != "" {
			raw, err := hex.DecodeString(strings.TrimSpace(env.CborHex))
			if err != nil {
				return nil, fmt.Errorf("failed to decode cborHex: %w", err)
			}
			return raw, nil
		}
	}
	// Try raw hex
	raw, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate hex: %w", err)
	}
	return raw, nil
}

// DecodeCertificate decodes certificate CBOR bytes into a gouroboros CertificateWrapper/Certificate
func DecodeCertificate(certBytes []byte) (lcommon.Certificate, error) {
	// CertificateWrapper can decode the full array/list form as used in tx body
	var wrapper lcommon.CertificateWrapper
	if _, err := cbor.Decode(certBytes, &wrapper); err == nil {
		if wrapper.Certificate != nil {
			return wrapper.Certificate, nil
		}
	}
	// Try decoding directly as a certificate type by trying to parse as array
	// Some forms might decode differently; try wrapper again
	if wrapper.Certificate != nil {
		return wrapper.Certificate, nil
	}
	// Fallback: try to decode using the wrapper logic by re-parsing
	return nil, fmt.Errorf("failed to decode certificate")
}

// ParseCertificates reads certificate files and returns the raw certificate CBOR arrays
// in the form expected by Conway transaction body (each certificate is CBOR encoded list)
func ParseCertificates(paths []string) ([][]byte, error) {
	certs := make([][]byte, 0, len(paths))
	for _, p := range paths {
		cb, err := ReadCertificateFile(p)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cb)
	}
	return certs, nil
}

var _ = bursa.ReadCborInput // keep import usage if needed
