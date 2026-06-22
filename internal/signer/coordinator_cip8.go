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
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// SignCIP8 produces a CIP-8/CIP-30 COSE_Sign1 signature for payload bound to
// address, using the key referenced by keyID. Only software/SOPS keys (which
// expose a LoadedKey) are supported in Phase 1; remote keys return CodeUnsupported.
//
// Every decision (allow or deny) is emitted as a structured audit-log line.
// Secrets (private key material, raw payload) are never logged.
func (c *Coordinator) SignCIP8(ctx context.Context, payload []byte, address, keyID string) (*CIP8Result, ErrorCode, error) {
	hash, err := backend.ParseKeyHash(keyID)
	if err != nil {
		c.deps.Logger.Info("sign", "type", "cip8", "caller-key", keyID, "address", address, "result", "denied", "reason", "invalid key id")
		c.deps.Metrics.observe("cip8", string(CodeBadRequest))
		c.deps.Metrics.observeDeny(string(CodeBadRequest))
		return nil, CodeBadRequest, fmt.Errorf("invalid key id: %w", err)
	}
	ref, err := c.deps.Resolver.Resolve(ctx, hash)
	if errors.Is(err, backend.ErrKeyNotFound) {
		c.deps.Logger.Info("sign", "type", "cip8", "caller-key", hash.String(), "address", address, "result", "denied", "reason", "key not found")
		c.deps.Metrics.observe("cip8", string(CodeNotFound))
		c.deps.Metrics.observeDeny(string(CodeNotFound))
		return nil, CodeNotFound, errors.New("key not found")
	}
	if err != nil {
		c.deps.Logger.Info("sign", "type", "cip8", "caller-key", hash.String(), "address", address, "result", "error", "reason", err.Error())
		c.deps.Metrics.observe("cip8", string(CodeBackend))
		c.deps.Metrics.observeBackendError("resolver")
		return nil, CodeBackend, err
	}

	// Gate on LoadedKeyProvider before parsing the address: remote-custody keys
	// cannot perform CIP-8 signing regardless of address validity, so we fail
	// fast here rather than returning a misleading bad_request for the address.
	provider, ok := ref.(backend.LoadedKeyProvider)
	if !ok {
		c.deps.Logger.Info("sign", "type", "cip8", "caller-key", hash.String(), "address", address, "result", "denied", "reason", "unsupported backend for CIP-8")
		c.deps.Metrics.observe("cip8", string(CodeUnsupported))
		c.deps.Metrics.observeDeny(string(CodeUnsupported))
		return nil, CodeUnsupported, fmt.Errorf("CIP-8 signing is not supported for keys held in the %q backend", ref.Backend())
	}
	lk := provider.LoadedKey()

	addr, err := lcommon.NewAddress(address)
	if err != nil {
		c.deps.Logger.Info("sign", "type", "cip8", "caller-key", hash.String(), "address", address, "result", "denied", "reason", "invalid address")
		c.deps.Metrics.observe("cip8", string(CodeBadRequest))
		c.deps.Metrics.observeDeny(string(CodeBadRequest))
		return nil, CodeBadRequest, fmt.Errorf("invalid address: %w", err)
	}
	// Mirror message.go validateAddressForVKey: payment-key addresses use
	// PaymentKeyHash; stake-only addresses (AddressTypeNoneKey, e.g. stake1…)
	// use StakeKeyHash. If neither credential is a key hash the address cannot
	// match any key (script/pointer addresses), so addressMatches=false.
	var addressMatches bool
	if pkh := addr.PaymentKeyHash(); pkh != (lcommon.Blake2b224{}) {
		var addrKeyHash backend.KeyHash
		copy(addrKeyHash[:], pkh[:])
		addressMatches = addrKeyHash == ref.Hash()
	} else if skh := addr.StakeKeyHash(); skh != (lcommon.Blake2b224{}) {
		var addrKeyHash backend.KeyHash
		copy(addrKeyHash[:], skh[:])
		addressMatches = addrKeyHash == ref.Hash()
	}

	if dec := c.deps.Policy.EvaluateCIP8(hash, len(payload), addressMatches); !dec.Allow {
		c.deps.Logger.Info("sign", "type", "cip8", "caller-key", hash.String(), "address", address, "result", "denied", "reason", dec.Reason)
		c.deps.Metrics.observe("cip8", string(CodeDenied))
		c.deps.Metrics.observeDeny(string(CodeDenied))
		return nil, CodeDenied, fmt.Errorf("%s", dec.Reason)
	}

	// addr.Bytes() returns ([]byte, error) — the raw address bytes CIP-8 binds
	// into the protected headers.
	addrBytes, err := addr.Bytes()
	if err != nil {
		c.deps.Logger.Info("sign", "type", "cip8", "caller-key", hash.String(), "address", address, "result", "error", "reason", "address bytes encoding failed")
		c.deps.Metrics.observe("cip8", string(CodeInternal))
		return nil, CodeInternal, fmt.Errorf("address bytes: %w", err)
	}

	signStart := time.Now()
	sigHex, keyHex, err := bursa.SignData(addrBytes, payload, lk)
	// Attempt latency, including failures — not successful-sign latency.
	c.deps.Metrics.observeSignDuration(ref.Backend(), time.Since(signStart).Seconds())
	if err != nil {
		c.deps.Logger.Info("sign", "type", "cip8", "caller-key", hash.String(), "address", address, "result", "error", "reason", err.Error())
		c.deps.Metrics.observe("cip8", string(CodeBackend))
		c.deps.Metrics.observeBackendError(ref.Backend())
		return nil, CodeBackend, fmt.Errorf("cip8 sign: %w", err)
	}

	c.deps.Logger.Info("sign", "type", "cip8", "caller-key", hash.String(), "address", address, "result", "signed")
	c.deps.Metrics.observe("cip8", "signed")
	return &CIP8Result{SignatureHex: sigHex, KeyHex: keyHex}, "", nil
}
