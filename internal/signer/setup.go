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
	"os"
	"path/filepath"
	"strings"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/policy"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
)

// BuildPolicies maps config key entries (with map-typed tx/cip8 policy) into
// typed policy.KeyPolicy values, via a JSON round-trip keyed on the json tags
// (which mirror the yaml tags on TxPolicy/CIP8Policy).
func BuildPolicies(keys []config.SignerKeyConfig) ([]policy.KeyPolicy, error) {
	out := make([]policy.KeyPolicy, 0, len(keys))
	for _, k := range keys {
		p := policy.KeyPolicy{
			Hash:            k.Hash,
			Backend:         k.Backend,
			AllowedRequests: k.AllowedRequests,
		}
		if k.TxPolicy != nil {
			var tp policy.TxPolicy
			if err := remap(k.TxPolicy, &tp); err != nil {
				return nil, fmt.Errorf("tx_policy for %s: %w", k.Hash, err)
			}
			p.Tx = &tp
		}
		if k.CIP8Policy != nil {
			var cp policy.CIP8Policy
			if err := remap(k.CIP8Policy, &cp); err != nil {
				return nil, fmt.Errorf("cip8_policy for %s: %w", k.Hash, err)
			}
			p.CIP8 = &cp
		}
		out = append(out, p)
	}
	return out, nil
}

// remap converts a decoded map into a typed struct via a JSON round-trip.
// The policy structs carry both yaml and json tags (same names), so map keys
// from YAML decode bind correctly through JSON.
// DisallowUnknownFields is set so that a typo'd policy key (e.g.
// max_output_lovelace) fails at boot instead of silently being ignored.
func remap(src map[string]any, dst any) error {
	b, err := json.Marshal(src)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

// keyTypeFromEnvelope maps a cardano-cli key envelope Type string to the
// backend.KeyType used by the signer. Only signing key (.skey) types are
// expected here; verification keys are filtered before this is called.
func keyTypeFromEnvelope(envelopeType string) backend.KeyType {
	switch {
	case strings.HasPrefix(envelopeType, "Payment"):
		return backend.KeyTypePayment
	case strings.HasPrefix(envelopeType, "StakePool"):
		return backend.KeyTypePool
	case strings.HasPrefix(envelopeType, "Stake"):
		return backend.KeyTypeStake
	case strings.HasPrefix(envelopeType, "DRep"):
		return backend.KeyTypeDRep
	case strings.HasPrefix(envelopeType, "CommitteeHot"):
		return backend.KeyTypeCCHot
	case strings.HasPrefix(envelopeType, "CommitteeCold"):
		return backend.KeyTypeCCCold
	case strings.HasPrefix(envelopeType, "Policy"),
		strings.HasPrefix(envelopeType, "Calidus"):
		return backend.KeyTypePolicy
	default:
		return backend.KeyTypePayment
	}
}

// BuildBackends constructs configured backends. Software backends load only
// *.skey files from their configured directory; other files (.vkey, README,
// etc.) are skipped silently. SOPS and Vault backend wiring are deliberate
// staged follow-ups; they return explicit errors rather than silently no-oping.
func BuildBackends(ctx context.Context, cfgs []config.SignerBackendConfig) ([]backend.Backend, error) {
	var backends []backend.Backend
	for _, c := range cfgs {
		switch c.Type {
		case "software":
			b := backend.NewSoftwareBackend(c.Name)
			entries, err := os.ReadDir(c.Path)
			if err != nil {
				return nil, fmt.Errorf("read key dir %q: %w", c.Path, err)
			}
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				// Only load signing key files; skip .vkey, README, etc.
				if !strings.HasSuffix(e.Name(), ".skey") {
					continue
				}
				path := filepath.Join(c.Path, e.Name())
				lk, err := bursa.LoadKeyFromFile(path)
				if err != nil {
					return nil, fmt.Errorf("load key %q: %w", e.Name(), err)
				}
				kt := keyTypeFromEnvelope(lk.Type)
				if _, err := b.AddKey(lk, kt); err != nil {
					return nil, fmt.Errorf("add key %q: %w", e.Name(), err)
				}
			}
			backends = append(backends, b)
		case "sops":
			// Production wiring: implement a SecretSource over GCP Secret Manager /
			// sops.Decrypt. Register secrets discovered under SecretPrefix.
			// This is a deliberate staged follow-up.
			return nil, errors.New("sops backend wiring is not yet implemented (tracked follow-up)")
		case "vault":
			// Production wiring: implement a Vault Transit sign func and register
			// keys discovered under TransitMount.
			// This is a deliberate staged follow-up.
			return nil, errors.New("vault backend wiring is not yet implemented (tracked follow-up)")
		default:
			return nil, fmt.Errorf("unknown backend type %q", c.Type)
		}
	}
	return backends, nil
}

// BuildWatermark constructs the configured watermark store and mode.
func BuildWatermark(c config.SignerWatermarkConfig) (watermark.Watermark, watermark.Mode, error) {
	mode := watermark.Mode(c.Mode)
	if mode == "" {
		mode = watermark.ModeEnforce
	}
	switch c.Type {
	case "", "mem":
		return watermark.NewMemWatermark(), mode, nil
	case "file":
		if c.Path == "" {
			return nil, mode, fmt.Errorf("watermark type %q requires a non-empty path", c.Type)
		}
		wm, err := watermark.NewSqliteWatermark(c.Path)
		return wm, mode, err
	default:
		return nil, mode, fmt.Errorf("unknown watermark type %q", c.Type)
	}
}
