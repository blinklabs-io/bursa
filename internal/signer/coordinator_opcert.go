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
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// kesVkeySize is the length in bytes of a KES verification key (Ed25519-sized).
const kesVkeySize = 32

// opcertCounterScope namespaces the monotonic issue-counter watermark. The
// record key already embeds the cold-key hash, so this scope only separates
// opcert-counter records from tx/cip8 payload watermarks for the same key.
const opcertCounterScope = "opcert-counter"

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

	// Operational certificates are signed only by stake-pool COLD keys. Guard
	// against a misconfigured policy granting opcert to a key of any other role
	// (payment, stake, committee, etc.); such a key must never produce an opcert
	// signature regardless of what the ACL permits.
	if ref.Type() != backend.KeyTypePool {
		c.deps.Logger.Info("sign", "type", "opcert", "caller-key", hash.String(), "result", "denied", "reason", "key is not a stake-pool cold key")
		c.deps.Metrics.observe("opcert", string(CodeBadRequest))
		c.deps.Metrics.observeDeny(string(CodeBadRequest))
		return nil, CodeBadRequest, fmt.Errorf("opcert signing requires a %q key, got %q", backend.KeyTypePool, ref.Type())
	}

	// Anti-double-sign: the operational-certificate issue counter must strictly
	// increase per cold key. A stale or duplicate counter is refused before the
	// cold key ever signs, so a compromised or buggy caller cannot re-issue an
	// opcert for a counter already used.
	var counterWM watermark.CounterWatermark
	if c.deps.WMMode != watermark.ModeOff {
		cw, ok := c.deps.Watermark.(watermark.CounterWatermark)
		if !ok {
			c.deps.Logger.Error("sign", "type", "opcert", "caller-key", hash.String(), "result", "internal-error", "reason", "watermark store does not support monotonic counters")
			c.deps.Metrics.observe("opcert", string(CodeInternal))
			return nil, CodeInternal, errors.New("watermark store does not support opcert issue counters")
		}
		counterWM = cw
		stored, exists, cerr := cw.CounterFor(ctx, hash, opcertCounterScope)
		if cerr != nil {
			c.deps.Logger.Info("sign", "type", "opcert", "caller-key", hash.String(), "result", "error", "reason", cerr.Error())
			c.deps.Metrics.observe("opcert", string(CodeBackend))
			c.deps.Metrics.observeBackendError("watermark")
			return nil, CodeBackend, fmt.Errorf("opcert counter lookup: %w", cerr)
		}
		if exists && issueCounter <= stored {
			c.deps.Metrics.observeWatermarkConflict()
			if c.deps.WMMode == watermark.ModeEnforce {
				c.deps.Logger.Info("sign", "type", "opcert", "caller-key", hash.String(), "issue-counter", issueCounter, "stored-counter", stored, "result", "denied", "reason", "issue counter is not strictly greater than the highest signed")
				c.deps.Metrics.observe("opcert", string(CodeConflict))
				c.deps.Metrics.observeDeny(string(CodeConflict))
				return nil, CodeConflict, fmt.Errorf("opcert issue counter %d is not greater than the highest signed %d for this cold key", issueCounter, stored)
			}
			// warn mode: log and allow; the signature is still produced.
			c.deps.Logger.Warn("sign", "type", "opcert", "caller-key", hash.String(), "issue-counter", issueCounter, "stored-counter", stored, "result", "warn", "reason", "issue counter is not strictly greater than the highest signed (warn mode)")
		}
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

	// Persist the new highest counter only after a verified signature. The commit
	// is an atomic advance-if-greater, so if a concurrent request advanced the
	// counter past ours between the pre-sign check and here, we lose the race and
	// must discard this signature rather than return a second opcert for a
	// now-stale counter.
	if counterWM != nil {
		if werr := counterWM.CheckAndCommitCounter(ctx, hash, opcertCounterScope, issueCounter); werr != nil {
			if errors.Is(werr, watermark.ErrCounterRegression) {
				if c.deps.WMMode == watermark.ModeEnforce {
					c.deps.Logger.Info("sign", "type", "opcert", "caller-key", hash.String(), "issue-counter", issueCounter, "result", "denied", "reason", "issue counter regression detected at commit (concurrent signer)")
					c.deps.Metrics.observe("opcert", string(CodeConflict))
					c.deps.Metrics.observeDeny(string(CodeConflict))
					c.deps.Metrics.observeWatermarkConflict()
					return nil, CodeConflict, fmt.Errorf("opcert issue counter %d is not greater than the highest signed for this cold key", issueCounter)
				}
				// warn mode: the stored counter already meets or exceeds ours;
				// nothing to advance. The signature is still returned.
			} else {
				c.deps.Logger.Error("sign", "type", "opcert", "caller-key", hash.String(), "result", "error", "reason", werr.Error())
				if c.deps.WMMode == watermark.ModeEnforce {
					c.deps.Metrics.observe("opcert", string(CodeBackend))
					c.deps.Metrics.observeBackendError("watermark")
					return nil, CodeBackend, fmt.Errorf("opcert counter commit: %w", werr)
				}
			}
		}
	}

	c.deps.Logger.Info("sign", "type", "opcert", "caller-key", hash.String(), "issue-counter", issueCounter, "result", "signed")
	c.deps.Metrics.observe("opcert", "signed")
	return &OpCertResult{
		SignatureHex: hex.EncodeToString(sig),
		ColdVKeyHex:  hex.EncodeToString(pub),
		KeyHex:       hash.String(),
	}, "", nil
}
