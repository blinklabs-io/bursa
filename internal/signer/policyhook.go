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
	"net/http"
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

// OperationSummary is the parsed request sent to an external policy hook. It
// contains no secrets — only the caller, the signing key, and the decoded
// operation types/amounts/destinations.
type OperationSummary struct {
	Type         string       `json:"type"` // "tx"
	Caller       string       `json:"caller"`
	Key          string       `json:"key"`
	TxID         string       `json:"tx_id"`
	Fee          string       `json:"fee,omitempty"`
	Outputs      []HookOutput `json:"outputs,omitempty"`
	Certificates []string     `json:"certificates,omitempty"`
	VoterKinds   []string     `json:"voter_kinds,omitempty"`
	DrepIds      []string     `json:"drep_ids,omitempty"`
}

// PolicyHook is an optional external authorization step consulted after the
// static policy allows a request. Authorize must return nil to permit signing;
// any error denies it. Implementations MUST fail closed (deny on transport,
// timeout, or malformed response).
type PolicyHook interface {
	Authorize(ctx context.Context, sum OperationSummary) error
}

// summarizeTx builds an OperationSummary for a tx-signing decision.
func summarizeTx(caller, key string, insp *bursa.TxInspection, ops policy.TxOps) OperationSummary {
	sum := OperationSummary{
		Type:         "tx",
		Caller:       caller,
		Key:          key,
		Certificates: ops.Certificates,
	}
	if insp != nil {
		sum.TxID = insp.TxId
		sum.Fee = insp.Fee
		for _, o := range insp.Outputs {
			sum.Outputs = append(sum.Outputs, HookOutput{
				Address:   o.Address,
				Lovelace:  o.Lovelace,
				HasAssets: o.HasAssets,
			})
		}
	}
	for _, v := range ops.Voters {
		sum.VoterKinds = append(sum.VoterKinds, v.Kind)
		if v.DrepId != "" {
			sum.DrepIds = append(sum.DrepIds, v.DrepId)
		}
	}
	return sum
}

// HTTPPolicyHook POSTs the operation summary as JSON to a configured URL and
// signs only on an explicit allow. The endpoint must return HTTP 200 with a
// JSON body {"allow": true}; any other status, a non-allow body, or a
// transport/timeout error denies (fail closed).
type HTTPPolicyHook struct {
	url    string
	client *http.Client
}

// NewHTTPPolicyHook builds an HTTP policy hook. A non-positive timeout defaults
// to 5 seconds.
func NewHTTPPolicyHook(url string, timeout time.Duration) *HTTPPolicyHook {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &HTTPPolicyHook{url: url, client: &http.Client{Timeout: timeout}}
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
	if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
		return fmt.Errorf("policy hook: unreadable response: %w", err)
	}
	if !decision.Allow {
		if decision.Reason != "" {
			return fmt.Errorf("policy hook denied: %s", decision.Reason)
		}
		return errors.New("policy hook denied")
	}
	return nil
}
