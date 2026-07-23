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
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// kesVkeySize is the length in bytes of a KES verification key (Ed25519-sized).
const kesVkeySize = 32

// OpCertResult is the outcome of an operational-certificate cold-signing request.
type OpCertResult struct {
	// SignatureHex is the 64-byte Ed25519 cold-key signature over the
	// OCertSignable bytes, hex-encoded.
	SignatureHex string
	// ColdVKeyHex is the 32-byte cold verification key, hex-encoded. It is the
	// value that goes in the cold_vkey slot of the opcert envelope so the caller
	// can assemble [[kes_vkey, counter, period, sig], cold_vkey].
	ColdVKeyHex string
	// KeyHex is the blake2b-224 hash (hex) of the cold key that produced the
	// signature.
	KeyHex string
}

// SignOpCert produces the pool COLD-key Ed25519 signature over the canonical
// OCertSignable bytes (kesVkey || issueCounter || kesPeriod, cardano-ledger
// getSignableRepresentation) using the cold key identified by keyID. The cold
// key never leaves its custody backend: the request carries only the KES
// verification key plus the counter/period, and the backend performs the
// signature.
//
// Every decision (allow or deny) is emitted as a structured audit-log line.
// Secrets (private key material) are never logged.
func (c *Coordinator) SignOpCert(ctx context.Context, kesVkey []byte, issueCounter, kesPeriod uint64, keyID string) (*OpCertResult, ErrorCode, error) {
	if len(kesVkey) != kesVkeySize {
		c.deps.Logger.Info("sign", "type", "opcert", "caller-key", keyID, "result", "denied", "reason", "invalid KES vkey length")
		c.deps.Metrics.observe("opcert", string(CodeBadRequest))
		c.deps.Metrics.observeDeny(string(CodeBadRequest))
		return nil, CodeBadRequest, fmt.Errorf("KES vkey must be %d bytes, got %d", kesVkeySize, len(kesVkey))
	}
	hash, err := backend.ParseKeyHash(keyID)
	if err != nil {
		c.deps.Logger.Info("sign", "type", "opcert", "caller-key", keyID, "result", "denied", "reason", "invalid key id")
		c.deps.Metrics.observe("opcert", string(CodeBadRequest))
		c.deps.Metrics.observeDeny(string(CodeBadRequest))
		return nil, CodeBadRequest, fmt.Errorf("invalid key id: %w", err)
	}
	ref, err := c.deps.Resolver.Resolve(ctx, hash)
	if errors.Is(err, backend.ErrKeyNotFound) {
		c.deps.Logger.Info("sign", "type", "opcert", "caller-key", hash.String(), "result", "denied", "reason", "key not found")
		c.deps.Metrics.observe("opcert", string(CodeNotFound))
		c.deps.Metrics.observeDeny(string(CodeNotFound))
		return nil, CodeNotFound, errors.New("key not found")
	}
	if err != nil {
		c.deps.Logger.Info("sign", "type", "opcert", "caller-key", hash.String(), "result", "error", "reason", err.Error())
		c.deps.Metrics.observe("opcert", string(CodeBackend))
		c.deps.Metrics.observeBackendError("resolver")
		return nil, CodeBackend, err
	}

	if dec := c.deps.Policy.EvaluateOpCert(hash); !dec.Allow {
		c.deps.Logger.Info("sign", "type", "opcert", "caller-key", hash.String(), "result", "denied", "reason", dec.Reason)
		c.deps.Metrics.observe("opcert", string(CodeDenied))
		c.deps.Metrics.observeDeny(string(CodeDenied))
		return nil, CodeDenied, fmt.Errorf("%s", dec.Reason)
	}

	// The cold key signs the raw OCertSignable bytes directly (this is NOT a
	// CBOR encoding). Building it via gouroboros keeps the byte layout identical
	// to cardano-node / cardano-ledger and to Part A's canonical envelope.
	signable := lcommon.OpCertSignableBytes(kesVkey, issueCounter, kesPeriod)

	signStart := time.Now()
	sig, err := ref.Sign(ctx, signable)
	// Attempt latency, including failures — not successful-sign latency.
	c.deps.Metrics.observeSignDuration(ref.Backend(), time.Since(signStart).Seconds())
	if err != nil {
		code := CodeBackend
		if errors.Is(err, backend.ErrUnsupportedExtended) {
			code = CodeUnsupported
		}
		c.deps.Logger.Info("sign", "type", "opcert", "caller-key", hash.String(), "result", "error", "reason", err.Error())
		c.deps.Metrics.observe("opcert", string(code))
		if code == CodeBackend {
			c.deps.Metrics.observeBackendError(ref.Backend())
		} else {
			c.deps.Metrics.observeDeny(string(code))
		}
		return nil, code, fmt.Errorf("opcert sign: %w", err)
	}

	pub := ref.PublicKey()
	if len(pub) != ed25519.PublicKeySize {
		c.deps.Logger.Error("sign", "type", "opcert", "caller-key", hash.String(), "result", "internal-error", "reason", "malformed public key from backend")
		c.deps.Metrics.observe("opcert", string(CodeInternal))
		return nil, CodeInternal, errors.New("backend returned malformed public key")
	}
	if !ed25519.Verify(pub, signable, sig) {
		c.deps.Logger.Error("sign", "type", "opcert", "caller-key", hash.String(), "result", "internal-error", "reason", "produced signature failed ed25519 verification")
		c.deps.Metrics.observe("opcert", string(CodeInternal))
		return nil, CodeInternal, errors.New("produced signature failed verification")
	}

	c.deps.Logger.Info("sign", "type", "opcert", "caller-key", hash.String(), "result", "signed")
	c.deps.Metrics.observe("opcert", "signed")
	return &OpCertResult{
		SignatureHex: hex.EncodeToString(sig),
		ColdVKeyHex:  hex.EncodeToString(pub),
		KeyHex:       hash.String(),
	}, "", nil
}
