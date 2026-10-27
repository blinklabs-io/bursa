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

package signer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/signer/policy"
)

// HookOutput is one transaction output in an OperationSummary.
type HookOutput struct {
	Address   string `json:"address"`
	Lovelace  string `json:"lovelace"`
	HasAssets bool   `json:"has_assets,omitempty"`
}

// HookVoter identifies one governance voter in an OperationSummary.
type HookVoter struct {
	Kind   string `json:"kind"`
	DrepID string `json:"drep_id,omitempty"`
}

// OperationSummary is the parsed request sent to an external policy hook. It
// contains no secrets — only the caller, the signing key, and the decoded
// operation types/amounts/destinations.
type OperationSummary struct {
	Type                   string          `json:"type"` // "tx"
	Caller                 string          `json:"caller"`
	Key                    string          `json:"key"`
	TxID                   string          `json:"tx_id"`
	Fee                    string          `json:"fee,omitempty"`
	TTL                    uint64          `json:"ttl,omitempty"`
	Outputs                []HookOutput    `json:"outputs,omitempty"`
	CertificateCount       int             `json:"certificate_count,omitempty"`
	Certificates           []string        `json:"certificates,omitempty"`
	HasMint                bool            `json:"has_mint,omitempty"`
	WithdrawalCount        int             `json:"withdrawal_count,omitempty"`
	VotingProcedureCount   int             `json:"voting_procedure_count,omitempty"`
	Voters                 []HookVoter     `json:"voters,omitempty"`
	ProposalProcedureCount int             `json:"proposal_procedure_count,omitempty"`
	HasTreasuryDonation    bool            `json:"has_treasury_donation,omitempty"`
	CollateralInputs       []bursa.TxInput `json:"collateral_inputs,omitempty"`
	CollateralReturn       *HookOutput     `json:"collateral_return,omitempty"`
	TotalCollateral        string          `json:"total_collateral,omitempty"`
	// VoterKinds and DrepIds preserve the original flattened hook fields.
	VoterKinds []string `json:"voter_kinds,omitempty"`
	DrepIds    []string `json:"drep_ids,omitempty"`
}

// PolicyHook is an optional external authorization step consulted after the
// static policy allows a request. Authorize must return nil to permit signing;
// any error denies it. Implementations MUST fail closed (deny on transport,
// timeout, or malformed response).
type PolicyHook interface {
	Authorize(ctx context.Context, sum OperationSummary) error
}

// summarizeTx builds an OperationSummary for a tx-signing decision.
func summarizeTx(caller, key string, insp *bursa.TxInspection, ops policy.TxOps) (OperationSummary, error) {
	if insp == nil {
		return OperationSummary{}, errors.New("policy hook: transaction inspection is unavailable")
	}
	if len(ops.Certificates) != insp.CertificateCount {
		return OperationSummary{}, fmt.Errorf(
			"policy hook: certificate details incomplete: got %d of %d",
			len(ops.Certificates), insp.CertificateCount,
		)
	}
	if len(ops.Voters) != insp.VotingProcedureCount {
		return OperationSummary{}, fmt.Errorf(
			"policy hook: voter details incomplete: got %d of %d",
			len(ops.Voters), insp.VotingProcedureCount,
		)
	}
	sum := OperationSummary{
		Type:                   "tx",
		Caller:                 caller,
		Key:                    key,
		TxID:                   insp.TxId,
		Fee:                    insp.Fee,
		TTL:                    insp.TTL,
		CertificateCount:       insp.CertificateCount,
		Certificates:           ops.Certificates,
		HasMint:                insp.HasMint,
		WithdrawalCount:        insp.WithdrawalCount,
		VotingProcedureCount:   insp.VotingProcedureCount,
		ProposalProcedureCount: insp.ProposalProcedureCount,
		HasTreasuryDonation:    insp.HasTreasuryDonation,
	}
	for _, o := range insp.Outputs {
		sum.Outputs = append(sum.Outputs, HookOutput{
			Address:   o.Address,
			Lovelace:  o.Lovelace,
			HasAssets: o.HasAssets,
		})
	}
	sum.CollateralInputs = insp.CollateralInputs
	sum.TotalCollateral = insp.TotalCollateral
	if insp.CollateralReturn != nil {
		sum.CollateralReturn = &HookOutput{
			Address:   insp.CollateralReturn.Address,
			Lovelace:  insp.CollateralReturn.Lovelace,
			HasAssets: insp.CollateralReturn.HasAssets,
		}
	}
	for _, v := range ops.Voters {
		if v.Kind == "" {
			return OperationSummary{}, errors.New("policy hook: voter kind is unavailable")
		}
		if policy.IsDrepVoterKind(v.Kind) && v.DrepId == "" {
			return OperationSummary{}, errors.New("policy hook: DRep voter id is unavailable")
		}
		sum.Voters = append(sum.Voters, HookVoter{Kind: v.Kind, DrepID: v.DrepId})
		sum.VoterKinds = append(sum.VoterKinds, v.Kind)
		if v.DrepId != "" {
			sum.DrepIds = append(sum.DrepIds, v.DrepId)
		}
	}
	return sum, nil
}

// HTTPPolicyHook POSTs the operation summary as JSON to a configured HTTPS URL
// signs only on an explicit allow. The endpoint must return HTTP 200 with a
// JSON body {"allow": true}; any other status, a non-allow body, or a
// transport/timeout error denies (fail closed).
type HTTPPolicyHook struct {
	url    string
	client *http.Client
}

// NewHTTPPolicyHook builds an HTTPS policy hook. The server certificate is
// verified against the system trust store, and redirects are refused. A
// non-positive timeout defaults to 5 seconds.
func NewHTTPPolicyHook(rawURL string, timeout time.Duration) (*HTTPPolicyHook, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid policy hook URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, errors.New("policy hook URL must use HTTPS")
	}
	if u.Hostname() == "" {
		return nil, errors.New("policy hook URL has no host")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &HTTPPolicyHook{
		url: rawURL,
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (h *HTTPPolicyHook) Authorize(ctx context.Context, sum OperationSummary) error {
	body, err := json.Marshal(sum)
	if err != nil {
		return fmt.Errorf("policy hook: marshal summary: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("policy hook: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("policy hook: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("policy hook: denied (status %d)", resp.StatusCode)
	}
	var decision struct {
		Allow  bool   `json:"allow"`
		Reason string `json:"reason"`
	}
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&decision); err != nil {
		return fmt.Errorf("policy hook: unreadable response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("policy hook: response contains trailing data")
	}
	if !decision.Allow {
		if decision.Reason != "" {
			return fmt.Errorf("policy hook denied: %s", decision.Reason)
		}
		return errors.New("policy hook denied")
	}
	return nil
}
