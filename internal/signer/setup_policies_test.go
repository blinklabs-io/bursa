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
	"testing"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

const testKeyHash = "00000000000000000000000000000000000000000000000000000001"

func TestBuildCallerPolicies(t *testing.T) {
	cfg := map[string]map[string]map[string]any{
		"alice": {
			testKeyHash: {
				"max_fee_ada":         float64(2),
				"forbid_certificates": true,
				"allowed_voter_kinds": []any{"drep_key"},
			},
		},
	}
	out, err := BuildCallerPolicies(cfg)
	if err != nil {
		t.Fatalf("BuildCallerPolicies: %v", err)
	}
	h, _ := backend.ParseKeyHash(testKeyHash)
	ov := out["alice"][h]
	if ov == nil {
		t.Fatalf("missing override for alice/%s", testKeyHash)
	}
	if ov.MaxFeeAda != 2 || !ov.ForbidCertificates || len(ov.AllowedVoterKinds) != 1 {
		t.Fatalf("override not mapped correctly: %+v", ov)
	}
}

func TestBuildCallerPolicies_Empty(t *testing.T) {
	out, err := BuildCallerPolicies(nil)
	if err != nil || out != nil {
		t.Fatalf("expected nil,nil for empty config; got %v,%v", out, err)
	}
}

func TestBuildCallerPolicies_BadHash(t *testing.T) {
	cfg := map[string]map[string]map[string]any{
		"alice": {"not-a-hash": {"max_fee_ada": float64(1)}},
	}
	if _, err := BuildCallerPolicies(cfg); err == nil {
		t.Fatalf("expected error for invalid key hash")
	}
}

func TestBuildCallerPolicies_UnknownField(t *testing.T) {
	cfg := map[string]map[string]map[string]any{
		"alice": {testKeyHash: {"bogus_field": true}},
	}
	if _, err := BuildCallerPolicies(cfg); err == nil {
		t.Fatalf("expected error for unknown override field")
	}
}

func TestBuildPolicyHook(t *testing.T) {
	if h := BuildPolicyHook(config.SignerConfig{}); h != nil {
		t.Fatalf("expected nil hook when policy_hook_url unset")
	}
	h := BuildPolicyHook(config.SignerConfig{PolicyHookURL: "http://localhost:9/decide", PolicyHookTimeoutMs: 250})
	if h == nil {
		t.Fatalf("expected a hook when policy_hook_url is set")
	}
}
