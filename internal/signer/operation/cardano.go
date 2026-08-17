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

package operation

import (
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/signer/policy"
	"github.com/blinklabs-io/gouroboros/ledger"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// Cardano is the subset of the bursa toolkit the coordinator needs. It is an
// interface so the coordinator can be tested with a fake.
type Cardano interface {
	// Inspect decodes a transaction into its structured summary (counts/booleans).
	Inspect(txCbor []byte) (*bursa.TxInspection, error)
	// Operations decodes the operation TYPES present in a transaction — the
	// certificate kinds and governance voters — for per-kind policy gating.
	Operations(txCbor []byte) (policy.TxOps, error)
	// TxID returns the 32-byte transaction id (the witness signing message).
	TxID(txCbor []byte) ([]byte, error)
	// Assemble merges vkey witnesses into a transaction, preserving the body.
	Assemble(txCbor []byte, wits []lcommon.VkeyWitness) ([]byte, error)
}

// BursaCardano is the production adapter backed by the bursa toolkit.
type BursaCardano struct{}

func (BursaCardano) Inspect(txCbor []byte) (*bursa.TxInspection, error) {
	return bursa.InspectTransaction(txCbor)
}

// Operations decodes the certificate kinds and governance voter identities from
// a transaction. Certificate kinds are returned in transaction order; voters
// are sorted (by kind then id) for deterministic output. Voter DRep credential
// ids are hex-encoded.
func (BursaCardano) Operations(txCbor []byte) (policy.TxOps, error) {
	txType, err := ledger.DetermineTransactionType(txCbor)
	if err != nil {
		return policy.TxOps{}, fmt.Errorf("failed to determine transaction era: %w", err)
	}
	tx, err := ledger.NewTransactionFromCbor(txType, txCbor)
	if err != nil {
		return policy.TxOps{}, fmt.Errorf("failed to decode transaction: %w", err)
	}
	var ops policy.TxOps
	for _, cert := range tx.Certificates() {
		ops.Certificates = append(ops.Certificates, policy.CertificateKindName(cert.Type()))
	}
	for voter := range tx.VotingProcedures() {
		if voter == nil {
			continue
		}
		kind := policy.VoterKindName(voter.Type)
		vi := policy.VoterInfo{Kind: kind}
		if policy.IsDrepVoterKind(kind) {
			vi.DrepId = hex.EncodeToString(voter.Hash[:])
		}
		ops.Voters = append(ops.Voters, vi)
	}
	sort.Slice(ops.Voters, func(i, j int) bool {
		if ops.Voters[i].Kind != ops.Voters[j].Kind {
			return ops.Voters[i].Kind < ops.Voters[j].Kind
		}
		return ops.Voters[i].DrepId < ops.Voters[j].DrepId
	})
	return ops, nil
}

func (BursaCardano) TxID(txCbor []byte) ([]byte, error) {
	idHex, err := bursa.TransactionID(txCbor)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(idHex)
	if err != nil {
		return nil, fmt.Errorf("decode tx id: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("transaction id must be 32 bytes, got %d", len(raw))
	}
	return raw, nil
}

func (BursaCardano) Assemble(txCbor []byte, wits []lcommon.VkeyWitness) ([]byte, error) {
	return bursa.AssembleTransaction(txCbor, wits)
}
