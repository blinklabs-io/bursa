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

package kesagent

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/kes"
	"github.com/blinklabs-io/gouroboros/ledger"
)

// decodedOpCert holds the fields decoded from a canonical node operational
// certificate CBOR envelope.
type decodedOpCert struct {
	kesVkey     []byte
	issueNumber uint64
	kesPeriod   uint64
	coldSig     []byte
	coldVkey    []byte
}

// decodeOpCert decodes a node operational certificate from CBOR.
//
// Wire format (matches bursa / cardano-node):
//
//	[[kes_vkey, issue_number, kes_period, cold_signature], cold_vkey]
//
// This mirrors bursa's own decodeOpCert; it is duplicated here to keep the
// agent package self-contained (the root helper is unexported).
func decodeOpCert(certBytes []byte) (*decodedOpCert, error) {
	var outer []any
	if _, err := cbor.Decode(certBytes, &outer); err != nil {
		return nil, fmt.Errorf("failed to unmarshal OpCert CBOR: %w", err)
	}
	if len(outer) != 2 {
		return nil, fmt.Errorf(
			"invalid OpCert: expected 2-element outer array, got %d",
			len(outer),
		)
	}
	cert, ok := outer[0].([]any)
	if !ok {
		return nil, errors.New("invalid OpCert: first element is not an array")
	}
	if len(cert) != 4 {
		return nil, fmt.Errorf(
			"invalid OpCert: expected 4-element cert array, got %d",
			len(cert),
		)
	}
	coldVkey, ok := outer[1].([]byte)
	if !ok {
		return nil, errors.New("invalid OpCert: cold_vkey is not bytes")
	}
	if len(coldVkey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(
			"invalid OpCert: cold_vkey expected %d bytes, got %d",
			ed25519.PublicKeySize, len(coldVkey),
		)
	}
	kesVkey, ok := cert[0].([]byte)
	if !ok {
		return nil, errors.New("invalid OpCert: kes_vkey is not bytes")
	}
	if len(kesVkey) != kes.PublicKeySize {
		return nil, fmt.Errorf(
			"invalid OpCert: kes_vkey expected %d bytes, got %d",
			kes.PublicKeySize, len(kesVkey),
		)
	}
	issueNumber, err := asUint64(cert[1], "issue_number")
	if err != nil {
		return nil, err
	}
	kesPeriod, err := asUint64(cert[2], "kes_period")
	if err != nil {
		return nil, err
	}
	coldSig, ok := cert[3].([]byte)
	if !ok {
		return nil, errors.New("invalid OpCert: cold_signature is not bytes")
	}
	if len(coldSig) != ed25519.SignatureSize {
		return nil, fmt.Errorf(
			"invalid OpCert: cold_signature expected %d bytes, got %d",
			ed25519.SignatureSize, len(coldSig),
		)
	}
	return &decodedOpCert{
		kesVkey:     kesVkey,
		issueNumber: issueNumber,
		kesPeriod:   kesPeriod,
		coldSig:     coldSig,
		coldVkey:    coldVkey,
	}, nil
}

func asUint64(v any, field string) (uint64, error) {
	switch n := v.(type) {
	case uint64:
		return n, nil
	case int64:
		if n < 0 {
			return 0, fmt.Errorf("invalid OpCert: %s cannot be negative, got %d", field, n)
		}
		return uint64(n), nil
	default:
		return 0, fmt.Errorf("invalid OpCert: %s has unexpected type %T", field, v)
	}
}

// ledgerOpCert converts to the gouroboros ledger.OpCert for signature checks.
func (d *decodedOpCert) ledgerOpCert() *ledger.OpCert {
	return &ledger.OpCert{
		KesVkey:       d.kesVkey,
		IssueNumber:   d.issueNumber,
		KesPeriod:     d.kesPeriod,
		ColdSignature: d.coldSig,
	}
}
