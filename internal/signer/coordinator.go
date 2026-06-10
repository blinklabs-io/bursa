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
	"log/slog"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/operation"
	"github.com/blinklabs-io/bursa/internal/signer/policy"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// ErrorCode classifies a per-signer or request failure (mapped to HTTP in Part 8).
type ErrorCode string

const (
	CodeBadRequest  ErrorCode = "bad_request"
	CodeNotFound    ErrorCode = "not_found"
	CodeDenied      ErrorCode = "denied"
	CodeConflict    ErrorCode = "conflict"
	CodeUnsupported ErrorCode = "unsupported"
	CodeBackend     ErrorCode = "backend_error"
	CodeInternal    ErrorCode = "internal"
)

// SignerError is a per-signer failure within a (possibly partial) tx request.
type SignerError struct {
	Signer string    `json:"signer"`
	Code   ErrorCode `json:"code"`
	Reason string    `json:"reason"`
}

// TxResult is the outcome of a transaction signing request.
type TxResult struct {
	TxID      string   `json:"tx_id"`
	Witnesses [][]byte `json:"-"` // CBOR per signer; hex-encoded by the API layer
	SignedTx  []byte   `json:"-"`
}

// CIP8Result is the outcome of a data-signing request.
type CIP8Result struct {
	SignatureHex string
	KeyHex       string
}

// Deps are the coordinator's collaborators.
type Deps struct {
	Resolver  *backend.Resolver
	Policy    *policy.Engine
	Watermark watermark.Watermark
	WMMode    watermark.Mode
	Cardano   operation.Cardano
	Logger    *slog.Logger
	Metrics   *Metrics
}

// Coordinator orchestrates a single signing request end-to-end.
type Coordinator struct {
	deps Deps
}

// New builds a Coordinator. A nil Logger defaults to slog.Default(). A nil
// Metrics creates a new default metrics instance (not registered anywhere).
func New(deps Deps) *Coordinator {
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	if deps.Metrics == nil {
		deps.Metrics = NewMetrics()
	}
	switch deps.WMMode {
	case watermark.ModeOff, watermark.ModeWarn, watermark.ModeEnforce:
		// valid — keep as-is
	case "":
		deps.WMMode = watermark.ModeEnforce
	default:
		deps.Logger.Warn("unrecognized watermark mode; coercing to enforce (fail closed)",
			"requested_mode", string(deps.WMMode))
		deps.WMMode = watermark.ModeEnforce
	}
	if deps.WMMode != watermark.ModeOff && deps.Watermark == nil {
		deps.Logger.Warn("watermark mode requires a store; using in-memory watermark")
		deps.Watermark = watermark.NewMemWatermark()
	}
	return &Coordinator{deps: deps}
}

// resolveSigner accepts a key-hash hex or a bech32 address and returns the key hash.
// For a payment-type address the payment key hash is used; for a stake-only address
// (AddressTypeNoneKey, e.g. stake1…) the stake key hash is used. Addresses with no
// key credential (script-only, pointer-only) return an error.
func resolveSigner(s string) (backend.KeyHash, error) {
	if h, err := backend.ParseKeyHash(s); err == nil {
		return h, nil
	}
	addr, err := lcommon.NewAddress(s)
	if err != nil {
		return backend.KeyHash{}, fmt.Errorf("signer %q is neither a key hash nor an address", s)
	}
	// Prefer the payment key hash when present.
	pkh := addr.PaymentKeyHash()
	if pkh != (lcommon.Blake2b224{}) {
		var h backend.KeyHash
		copy(h[:], pkh[:])
		return h, nil
	}
	// Fall back to the stake key hash (stake-address signer: AddressTypeNoneKey).
	skh := addr.StakeKeyHash()
	if skh != (lcommon.Blake2b224{}) {
		var h backend.KeyHash
		copy(h[:], skh[:])
		return h, nil
	}
	return backend.KeyHash{}, fmt.Errorf("signer %q: address has no key credential usable as a signer", s)
}

// SignTx decodes, policy-checks, watermarks, signs, verifies, and assembles.
// It returns a result (with whatever witnesses succeeded), per-signer errors,
// and a hard error only for request-level failures (e.g. undecodable tx).
//
// Every signing decision (allow or deny) is emitted as a structured audit-log
// line so that all outcomes are auditable. Secrets (private keys, raw tx bytes)
// are never logged.
func (c *Coordinator) SignTx(ctx context.Context, cborInput []byte, signers []string) (*TxResult, []SignerError, error) {
	raw, err := bursa.ReadCborInput(cborInput)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", errBadRequest, err)
	}
	insp, err := c.deps.Cardano.Inspect(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", errBadRequest, err)
	}
	txid, err := c.deps.Cardano.TxID(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", errBadRequest, err)
	}
	if len(signers) == 0 {
		return nil, nil, fmt.Errorf("%w: no signers specified", errBadRequest)
	}
	// Scope is the tx-id, making it identical to the payload being signed.
	// Because the scope IS the txid, ErrConflict cannot fire by construction
	// (Check/Commit on the same txid is idempotent in the mem/sqlite watermark);
	// the record is purely forensic for the tx flow. The enforce path becomes
	// meaningful for Phase-3 KES scopes where the scope is a slot number that
	// must not regress.
	scope := "tx:" + hex.EncodeToString(txid)

	var (
		wits []lcommon.VkeyWitness
		errs []SignerError
	)
	for _, s := range signers {
		hash, err := resolveSigner(s)
		if err != nil {
			errs = append(errs, SignerError{Signer: s, Code: CodeBadRequest, Reason: err.Error()})
			c.deps.Logger.Info("sign", "type", "tx", "caller-key", s, "txid", insp.TxId, "result", "denied", "reason", err.Error())
			c.deps.Metrics.observe("tx", string(CodeBadRequest))
			continue
		}
		ref, err := c.deps.Resolver.Resolve(ctx, hash)
		if errors.Is(err, backend.ErrKeyNotFound) {
			errs = append(errs, SignerError{Signer: s, Code: CodeNotFound, Reason: "key not found"})
			c.deps.Logger.Info("sign", "type", "tx", "caller-key", hash.String(), "txid", insp.TxId, "result", "denied", "reason", "key not found")
			c.deps.Metrics.observe("tx", string(CodeNotFound))
			continue
		}
		if err != nil {
			errs = append(errs, SignerError{Signer: s, Code: CodeBackend, Reason: err.Error()})
			c.deps.Logger.Info("sign", "type", "tx", "caller-key", hash.String(), "txid", insp.TxId, "result", "error", "reason", err.Error())
			c.deps.Metrics.observe("tx", string(CodeBackend))
			continue
		}
		if dec := c.deps.Policy.EvaluateTx(hash, insp); !dec.Allow {
			errs = append(errs, SignerError{Signer: s, Code: CodeDenied, Reason: dec.Reason})
			c.deps.Logger.Info("sign", "type", "tx", "caller-key", hash.String(), "txid", insp.TxId, "result", "denied", "reason", dec.Reason)
			c.deps.Metrics.observe("tx", string(CodeDenied))
			continue
		}
		watermarkCommitted := false
		if c.deps.WMMode == watermark.ModeEnforce {
			if werr := c.deps.Watermark.CheckAndCommit(ctx, hash, scope, txid); werr != nil {
				if errors.Is(werr, watermark.ErrConflict) {
					errs = append(errs, SignerError{Signer: s, Code: CodeConflict, Reason: werr.Error()})
					c.deps.Logger.Info("sign", "type", "tx", "caller-key", hash.String(), "txid", insp.TxId, "result", "denied", "reason", "watermark conflict")
					c.deps.Metrics.observe("tx", string(CodeConflict))
					continue
				}
				errs = append(errs, SignerError{Signer: s, Code: CodeBackend, Reason: werr.Error()})
				c.deps.Logger.Info("sign", "type", "tx", "caller-key", hash.String(), "txid", insp.TxId, "result", "error", "reason", werr.Error())
				c.deps.Metrics.observe("tx", string(CodeBackend))
				continue
			}
			watermarkCommitted = true
		} else if c.deps.WMMode == watermark.ModeWarn {
			if werr := c.deps.Watermark.Check(ctx, hash, scope, txid); werr != nil {
				if errors.Is(werr, watermark.ErrConflict) {
					c.deps.Logger.Warn("watermark conflict (warn mode)", "key", hash.String(), "scope", scope)
				} else {
					errs = append(errs, SignerError{Signer: s, Code: CodeBackend, Reason: werr.Error()})
					c.deps.Logger.Info("sign", "type", "tx", "caller-key", hash.String(), "txid", insp.TxId, "result", "error", "reason", werr.Error())
					c.deps.Metrics.observe("tx", string(CodeBackend))
					continue
				}
			}
		}
		sig, err := ref.Sign(ctx, txid)
		if err != nil {
			code := CodeBackend
			if errors.Is(err, backend.ErrUnsupportedExtended) {
				code = CodeUnsupported
			}
			errs = append(errs, SignerError{Signer: s, Code: code, Reason: err.Error()})
			c.deps.Logger.Info("sign", "type", "tx", "caller-key", hash.String(), "txid", insp.TxId, "result", "error", "reason", err.Error())
			c.deps.Metrics.observe("tx", string(code))
			continue
		}
		pub := ref.PublicKey()
		if len(pub) != ed25519.PublicKeySize {
			errs = append(errs, SignerError{Signer: s, Code: CodeInternal, Reason: "backend returned malformed public key"})
			c.deps.Logger.Error("sign", "type", "tx", "caller-key", hash.String(), "txid", insp.TxId, "result", "internal-error", "reason", "malformed public key from backend")
			c.deps.Metrics.observe("tx", string(CodeInternal))
			continue
		}
		if !ed25519.Verify(pub, txid, sig) {
			errs = append(errs, SignerError{Signer: s, Code: CodeInternal, Reason: "produced signature failed verification"})
			c.deps.Logger.Error("sign", "type", "tx", "caller-key", hash.String(), "txid", insp.TxId, "result", "internal-error", "reason", "produced signature failed ed25519 verification")
			c.deps.Metrics.observe("tx", string(CodeInternal))
			continue
		}
		if c.deps.WMMode != watermark.ModeOff && !watermarkCommitted {
			if cerr := c.deps.Watermark.Commit(ctx, hash, scope, txid); cerr != nil {
				c.deps.Logger.Error("watermark commit failed after signing",
					"key", hash.String(), "scope", scope, "error", cerr.Error())
			}
		}
		wits = append(wits, lcommon.VkeyWitness{Vkey: pub, Signature: sig})
		c.deps.Logger.Info("sign", "type", "tx", "caller-key", hash.String(), "txid", insp.TxId, "result", "signed")
		c.deps.Metrics.observe("tx", "signed")
	}

	res := &TxResult{TxID: insp.TxId}
	for _, w := range wits {
		enc, err := bursa.EncodeWitness(w)
		if err != nil {
			return nil, errs, fmt.Errorf("encode witness: %w", err)
		}
		res.Witnesses = append(res.Witnesses, enc)
	}
	if len(wits) > 0 {
		signed, err := c.deps.Cardano.Assemble(raw, wits)
		if err != nil {
			return nil, errs, fmt.Errorf("assemble tx: %w", err)
		}
		res.SignedTx = signed
	}
	return res, errs, nil
}

// errBadRequest tags request-level decode failures so the API maps them to 400.
var errBadRequest = errors.New("bad request")

// IsBadRequest reports whether err is a request-level decode failure.
func IsBadRequest(err error) bool { return errors.Is(err, errBadRequest) }
