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

package backend

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/blake2b"
)

// AttestedProtocol is the version string every attested-signer message
// carries. A peer speaking a different version is refused.
const AttestedProtocol = "bursa-attested-signer/1"

// AttestedProtocolSummary is the sign request version that asks the enclave
// for its signing policy's summary of a transaction body. The summary is one
// more field of the response binding. Inventory and challenge messages stay at
// AttestedProtocol.
const AttestedProtocolSummary = "bursa-attested-signer/2"

// attestedUnsupportedVersion is the refusal a version-1-only device returns
// for a sign request at any other version.
const attestedUnsupportedVersion = "unsupported protocol version"

// attestedMaxSummary bounds the summary text the signer passes on, which is
// device-supplied.
const attestedMaxSummary = 1024

// AttestedProtocolMode selects the sign request version an attested backend
// sends.
type AttestedProtocolMode int

const (
	// AttestedVersion1 sends version 1 only. Replies carry no summary.
	AttestedVersion1 AttestedProtocolMode = iota
	// AttestedNegotiate sends version 2 and retries at version 1 when the
	// device answers that the version is unsupported.
	AttestedNegotiate
	// AttestedRequireVersion2 sends version 2 and refuses to fall back.
	AttestedRequireVersion2
)

// ParseAttestedProtocolMode maps the backend "protocol" setting to a mode:
// "" or "1", "negotiate", or "2".
func ParseAttestedProtocolMode(s string) (AttestedProtocolMode, error) {
	switch s {
	case "", "1":
		return AttestedVersion1, nil
	case "negotiate":
		return AttestedNegotiate, nil
	case "2":
		return AttestedRequireVersion2, nil
	}
	return AttestedVersion1, fmt.Errorf("protocol %q is not 1, negotiate, or 2", s)
}

// attestedNonceSize is the length in bytes of the attestation and per-request
// nonces.
const attestedNonceSize = 32

var (
	// ErrAttestation is returned when an enclave's attestation evidence is
	// missing, malformed, unauthentic, or does not match the expected
	// measurements. A backend that fails attestation serves no keys.
	ErrAttestation = errors.New("attestation failed")
	// ErrPurposeRequired is returned by a plain Sign on an attested key: every
	// attested signature must be bound to a purpose.
	ErrPurposeRequired = errors.New("attested keys sign only through SignPurpose")
	// ErrAttestedProtocol is returned for a malformed, mismatched, or replayed
	// enclave message.
	ErrAttestedProtocol = errors.New("attested protocol violation")
	// ErrInvalidSignature is returned when an attested signer response does not
	// verify under the key admitted by the attestation.
	ErrInvalidSignature = errors.New("attested signature does not verify")
)

// Purpose binds a signature request to the Cardano operation it authorizes.
// The enclave signs a payload only when its shape matches the purpose and the
// key's role may perform it.
type Purpose string

const (
	// PurposeTxHash signs a 32-byte transaction body hash.
	PurposeTxHash Purpose = "tx-hash"
	// PurposeTxBody authorizes the encoded transaction body and signs its
	// Blake2b-256 hash. The request also carries the resolved transaction era.
	PurposeTxBody Purpose = "tx-body"
	// PurposeOpCert signs the 48-byte OCertSignable bytes
	// (kes_vkey || issue_counter || kes_period). Pool cold keys only.
	PurposeOpCert Purpose = "opcert"
	// PurposeOpCertNext asks the enclave to issue the next operational
	// certificate signature. The 48-byte payload is kes_vkey || on-chain
	// counter || KES period; the enclave picks the issue number (above the
	// chain counter) and returns it as IssueCounter. Pool cold keys only.
	PurposeOpCertNext Purpose = "opcert-next"
	// PurposeCIP8 signs a COSE Sig_structure built for CIP-8 data signing.
	PurposeCIP8 Purpose = "cip8"
)

const (
	txHashSize = 32
	// opCertSignableSize is kes_vkey (32) + issue counter (8) + KES period (8).
	opCertSignableSize = 48
	// opCertKESVKeySize is the leading KES verification key in the payload.
	opCertKESVKeySize = 32
)

// validate checks payload shape and key role for the purpose.
func (p Purpose) validate(role KeyType, payload []byte) error {
	switch p {
	case PurposeTxHash:
		if len(payload) != txHashSize {
			return fmt.Errorf("%w: tx-hash payload must be %d bytes, got %d", ErrAttestedProtocol, txHashSize, len(payload))
		}
	case PurposeTxBody:
		if len(payload) == 0 {
			return fmt.Errorf("%w: tx-body payload is empty", ErrAttestedProtocol)
		}
	case PurposeOpCert:
		if len(payload) != opCertSignableSize {
			return fmt.Errorf("%w: opcert payload must be %d bytes, got %d", ErrAttestedProtocol, opCertSignableSize, len(payload))
		}
		if role != KeyTypePool {
			return fmt.Errorf("%w: opcert requires a %q key, got %q", ErrAttestedProtocol, KeyTypePool, role)
		}
	case PurposeOpCertNext:
		if len(payload) != opCertSignableSize {
			return fmt.Errorf("%w: opcert-next payload must be %d bytes, got %d", ErrAttestedProtocol, opCertSignableSize, len(payload))
		}
		if role != KeyTypePool {
			return fmt.Errorf("%w: opcert-next requires a %q key, got %q", ErrAttestedProtocol, KeyTypePool, role)
		}
	case PurposeCIP8:
		if len(payload) == 0 {
			return fmt.Errorf("%w: cip8 payload is empty", ErrAttestedProtocol)
		}
	default:
		return fmt.Errorf("%w: unknown purpose %q", ErrAttestedProtocol, p)
	}
	return nil
}

// PurposeSigner is implemented by KeyRefs that bind every signature to a
// purpose (attested remote keys).
type PurposeSigner interface {
	SignPurpose(ctx context.Context, purpose Purpose, payload []byte) ([]byte, error)
}

// TxBodySigner is implemented by key references whose custody boundary must
// inspect an encoded transaction body before signing its hash. It also returns
// the boundary's summary of the body, empty when the boundary gave none.
type TxBodySigner interface {
	SignTxBody(ctx context.Context, body []byte, era uint) (sig []byte, summary string, err error)
}

// OpCertNextSigner is implemented by key references whose custody boundary
// chooses the operational certificate issue number itself.
type OpCertNextSigner interface {
	SignOpCertNext(ctx context.Context, kesVKey []byte, chainCounter, kesPeriod uint64) (sig []byte, issue uint64, err error)
}

// SignFor signs payload for purpose, using the purpose-bound path when the key
// offers one and a plain Sign otherwise.
func SignFor(ctx context.Context, ref KeyRef, purpose Purpose, payload []byte) ([]byte, error) {
	if ps, ok := ref.(PurposeSigner); ok {
		return ps.SignPurpose(ctx, purpose, payload)
	}
	return ref.Sign(ctx, payload)
}

// SignTxFor sends the encoded body and resolved era to body-aware custody and
// returns the custody boundary's summary of the body with the signature.
// Other backends retain the established contract of signing txHash directly,
// with no summary.
func SignTxFor(ctx context.Context, ref KeyRef, body []byte, era uint, txHash []byte) (sig []byte, summary string, err error) {
	if signer, ok := ref.(TxBodySigner); ok {
		return signer.SignTxBody(ctx, body, era)
	}
	sig, err = SignFor(ctx, ref, PurposeTxHash, txHash)
	return sig, "", err
}

// AttestedKeyInfo is one key an enclave reports holding.
type AttestedKeyInfo struct {
	Role      KeyType `json:"role"`
	PublicKey []byte  `json:"public_key"`
}

// AttestedInventory lists the keys an enclave holds, with attestation evidence
// that binds the list to a verified workload and to the caller's nonce.
type AttestedInventory struct {
	Version     string            `json:"version"`
	Keys        []AttestedKeyInfo `json:"keys"`
	Attestation []byte            `json:"attestation"`
}

// AttestedRequest asks the enclave to sign Payload with the key KeyHash in
// the stated Role. Nonce is fresh per request and must be echoed.
type AttestedRequest struct {
	Version string  `json:"version"`
	Purpose Purpose `json:"purpose"`
	KeyHash string  `json:"key_hash"`
	Role    KeyType `json:"role"`
	Nonce   []byte  `json:"nonce"`
	Payload []byte  `json:"payload"`
	Profile string  `json:"profile,omitempty"`
	Era     *uint   `json:"era,omitempty"`
	// Challenge, HostKey and HostSignature authenticate the request to a
	// device that registers host keys: HostKey signs AttestedRequestBinding
	// over the request and a one-time Challenge from the device.
	Challenge     []byte `json:"challenge,omitempty"`
	HostKey       []byte `json:"host_key,omitempty"`
	HostSignature []byte `json:"host_signature,omitempty"`
}

// AttestedResponse is the enclave's answer to an AttestedRequest. A non-empty
// Error means the enclave refused.
type AttestedResponse struct {
	Version          string `json:"version"`
	Nonce            []byte `json:"nonce"`
	Signature        []byte `json:"signature,omitempty"`
	BindingSignature []byte `json:"binding_signature,omitempty"`
	// IssueCounter is the opcert issue number the enclave chose for an
	// opcert-next request.
	IssueCounter *uint64 `json:"issue_counter,omitempty"`
	// Summary is the enclave's description of a signed transaction body. It
	// is present only in a reply to an AttestedProtocolSummary request and is
	// covered by BindingSignature.
	Summary string `json:"summary,omitempty"`
	Error   string `json:"error,omitempty"`
}

// AttestedResponseBinding is the digest a profiled workload signs alongside
// the Cardano signature. It binds the response to the complete request so an
// untrusted proxy cannot select another profile while reusing a valid Cardano
// signature from the same key. For an AttestedProtocolSummary request the
// reply's summary is one more field, present even when empty; a non-empty
// summary is appended at any version, so one added to a reply after signing
// does not verify. It mirrors armory/device.ResponseBinding, which the root
// module cannot import; TestAttestedSummaryBindingVector pins both to one
// digest.
func AttestedResponseBinding(req AttestedRequest, signature []byte, summary string) []byte {
	h := sha256.New()
	era := []byte(nil)
	if req.Era != nil {
		era = []byte(strconv.FormatUint(uint64(*req.Era), 10))
	}
	for _, field := range [][]byte{
		[]byte(req.Version),
		[]byte(req.Purpose),
		[]byte(req.KeyHash),
		[]byte(req.Role),
		req.Nonce,
		req.Payload,
		[]byte(req.Profile),
		era,
		signature,
	} {
		h.Write([]byte(strconv.Itoa(len(field)) + ":"))
		h.Write(field)
	}
	if req.Version == AttestedProtocolSummary || summary != "" {
		h.Write([]byte(strconv.Itoa(len(summary)) + ":" + summary))
	}
	return h.Sum(nil)
}

// attestedRequestDomain separates host signatures over requests from every
// other signature a host key could make.
const attestedRequestDomain = "bursa-armory-request/1"

// AttestedRequestBinding is the digest a host key signs to authenticate a
// request: the domain string, then the request fields and the challenge,
// length-prefixed as in AttestedResponseBinding. An absent era is an empty
// field.
func AttestedRequestBinding(req AttestedRequest) []byte {
	h := sha256.New()
	era := []byte(nil)
	if req.Era != nil {
		era = []byte(strconv.FormatUint(uint64(*req.Era), 10))
	}
	for _, field := range [][]byte{
		[]byte(attestedRequestDomain),
		[]byte(req.Version),
		[]byte(req.Purpose),
		[]byte(req.KeyHash),
		[]byte(req.Role),
		req.Nonce,
		req.Payload,
		[]byte(req.Profile),
		era,
		req.Challenge,
	} {
		h.Write([]byte(strconv.Itoa(len(field)) + ":"))
		h.Write(field)
	}
	return h.Sum(nil)
}

// Enclave is the host-side view of a workload that custodies keys inside a
// trusted execution environment. Implementations carry the messages over a
// host proxy that is NOT trusted: authenticity comes from the attestation
// evidence and from verifying signatures, never from the channel.
type Enclave interface {
	// Inventory returns the held keys and attestation evidence bound to nonce
	// (see InventoryBinding).
	Inventory(ctx context.Context, nonce []byte) (AttestedInventory, error)
	// Sign performs one purpose-bound signature.
	Sign(ctx context.Context, req AttestedRequest) (AttestedResponse, error)
}

// AttestationVerifier validates attestation evidence from a specific
// platform. It must fail unless the evidence is authentic, comes from the
// expected non-debug workload, and commits to binding.
type AttestationVerifier interface {
	Verify(ctx context.Context, evidence, binding []byte) error
}

// InventoryBinding is the digest an enclave commits to in its attestation
// evidence: the protocol version, the caller's nonce, and every key's role and
// public key in order. A verifier checks the evidence carries this value, so
// evidence cannot be replayed for another nonce or paired with another key list.
func InventoryBinding(nonce []byte, keys []AttestedKeyInfo) []byte {
	h := sha256.New()
	h.Write([]byte(AttestedProtocol))
	h.Write(nonce)
	for _, k := range keys {
		h.Write([]byte(strconv.Itoa(len(k.Role)) + ":" + string(k.Role)))
		h.Write(k.PublicKey)
	}
	return h.Sum(nil)
}

type attestedKey struct {
	owner       *AttestedBackend
	enclave     Enclave
	pub         ed25519.PublicKey
	hash        KeyHash
	typ         KeyType
	backendName string
	profile     string
}

func (k *attestedKey) Hash() KeyHash                { return k.hash }
func (k *attestedKey) PublicKey() ed25519.PublicKey { return k.pub }
func (k *attestedKey) Type() KeyType                { return k.typ }
func (k *attestedKey) Extended() bool               { return false }
func (k *attestedKey) Backend() string              { return k.backendName }

func (k *attestedKey) Sign(context.Context, []byte) ([]byte, error) {
	return nil, ErrPurposeRequired
}

// SignPurpose refuses unless k is still in the owner's served set, both before
// contacting the enclave and after it answers: a handle resolved before a
// reload must not outlive the attestation that admitted it.
func (k *attestedKey) SignPurpose(ctx context.Context, purpose Purpose, payload []byte) ([]byte, error) {
	if purpose == PurposeTxBody {
		return nil, fmt.Errorf("%w: tx-body requires SignTxBody with an era", ErrAttestedProtocol)
	}
	if purpose == PurposeOpCertNext {
		return nil, fmt.Errorf("%w: opcert-next requires SignOpCertNext, which returns the issue counter", ErrAttestedProtocol)
	}
	return k.signAttested(ctx, purpose, payload, nil, payload)
}

// SignTxBody sends the original encoded body across the custody boundary and
// verifies that custody returned the Cardano witness signature for its hash.
// It also returns the summary the enclave bound to its reply, empty unless
// version 2 was negotiated.
func (k *attestedKey) SignTxBody(ctx context.Context, body []byte, era uint) ([]byte, string, error) {
	hash := blake2b.Sum256(body)
	resp, err := k.exchange(ctx, PurposeTxBody, body, &era, func(resp AttestedResponse) error {
		return k.verifyCardano(hash[:], resp.Signature)
	})
	if err != nil {
		return nil, "", err
	}
	return resp.Signature, resp.Summary, nil
}

// SignOpCertNext asks custody to issue the next opcert signature. The host
// sends the on-chain counter and never picks the issue number: custody returns
// it, and Bursa accepts it only when it exceeds chainCounter and the signature
// verifies under the key over kes_vkey || issue || period.
func (k *attestedKey) SignOpCertNext(ctx context.Context, kesVKey []byte, chainCounter, kesPeriod uint64) ([]byte, uint64, error) {
	if len(kesVKey) != opCertKESVKeySize {
		return nil, 0, fmt.Errorf("%w: KES vkey must be %d bytes, got %d", ErrAttestedProtocol, opCertKESVKeySize, len(kesVKey))
	}
	payload := make([]byte, 0, opCertSignableSize)
	payload = append(payload, kesVKey...)
	payload = binary.BigEndian.AppendUint64(payload, chainCounter)
	payload = binary.BigEndian.AppendUint64(payload, kesPeriod)

	var issue uint64
	resp, err := k.exchange(ctx, PurposeOpCertNext, payload, nil, func(resp AttestedResponse) error {
		if resp.IssueCounter == nil {
			return fmt.Errorf("%w: opcert-next response has no issue_counter", ErrAttestedProtocol)
		}
		issue = *resp.IssueCounter
		if issue <= chainCounter {
			return fmt.Errorf("%w: issue counter %d is not above chain counter %d", ErrAttestedProtocol, issue, chainCounter)
		}
		signed := binary.BigEndian.AppendUint64(append([]byte(nil), kesVKey...), issue)
		signed = binary.BigEndian.AppendUint64(signed, kesPeriod)
		return k.verifyCardano(signed, resp.Signature)
	})
	if err != nil {
		return nil, 0, err
	}
	return resp.Signature, issue, nil
}

// verifyCardano checks sig is a well-formed Ed25519 signature by k over signed.
func (k *attestedKey) verifyCardano(signed, sig []byte) error {
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature must be %d bytes, got %d", ErrAttestedProtocol, ed25519.SignatureSize, len(sig))
	}
	if !ed25519.Verify(k.pub, signed, sig) {
		return fmt.Errorf("%w: %w", ErrAttestedProtocol, ErrInvalidSignature)
	}
	return nil
}

func (k *attestedKey) signAttested(ctx context.Context, purpose Purpose, payload []byte, era *uint, signed []byte) ([]byte, error) {
	resp, err := k.exchange(ctx, purpose, payload, era, func(resp AttestedResponse) error {
		return k.verifyCardano(signed, resp.Signature)
	})
	if err != nil {
		return nil, err
	}
	return resp.Signature, nil
}

// exchange sends one request and applies the checks common to every purpose:
// version, nonce, enclave refusal, the purpose's own verify of the response
// (including the Cardano signature), the binding signature, and that k is still
// served.
//
// A tx-body request goes out at the owner's mode: AttestedProtocolSummary for
// AttestedNegotiate and AttestedRequireVersion2, otherwise AttestedProtocol.
// Under AttestedNegotiate, a device that answers the version-2 request with
// the version-1 firmware's refusal gets the request again at version 1, with a
// new nonce and, through Enclave.Sign, a new challenge. The refusal carries no
// signature, so an untrusted proxy can forge it and pin the signer to version
// 1: that costs the summary, never signature integrity, and
// AttestedRequireVersion2 refuses it. A reply at any other version than the
// one requested is refused.
func (k *attestedKey) exchange(ctx context.Context, purpose Purpose, payload []byte, era *uint, verify func(AttestedResponse) error) (AttestedResponse, error) {
	if err := purpose.validate(k.typ, payload); err != nil {
		return AttestedResponse{}, err
	}
	if !k.owner.serves(k) {
		return AttestedResponse{}, ErrKeyNotFound
	}
	version := AttestedProtocol
	if purpose == PurposeTxBody {
		version = k.owner.requestVersion()
	}
	resp, unsupported, err := k.exchangeAt(ctx, version, purpose, payload, era, verify)
	if unsupported {
		if !k.owner.pinVersion1(k) {
			return AttestedResponse{}, ErrKeyNotFound
		}
		resp, _, err = k.exchangeAt(ctx, AttestedProtocol, purpose, payload, era, verify)
	}
	return resp, err
}

// exchangeAt is one request at version. unsupported reports that a version-2
// request got the version-1 firmware's refusal and the backend may retry at
// version 1.
func (k *attestedKey) exchangeAt(ctx context.Context, version string, purpose Purpose, payload []byte, era *uint, verify func(AttestedResponse) error) (resp AttestedResponse, unsupported bool, err error) {
	nonce := make([]byte, attestedNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return AttestedResponse{}, false, fmt.Errorf("attested nonce: %w", err)
	}
	req := AttestedRequest{
		Version: version,
		Purpose: purpose,
		KeyHash: k.hash.String(),
		Role:    k.typ,
		Nonce:   nonce,
		Payload: payload,
		Profile: k.profile,
		Era:     era,
	}
	resp, err = k.enclave.Sign(ctx, req)
	if err != nil {
		// the device may have been replaced or updated: probe again
		k.owner.unpinVersion()
		return AttestedResponse{}, false, fmt.Errorf("attested sign: %w", err)
	}
	if subtle.ConstantTimeCompare(resp.Nonce, nonce) != 1 {
		return AttestedResponse{}, false, fmt.Errorf("%w: response nonce does not match request", ErrAttestedProtocol)
	}
	if version == AttestedProtocolSummary && resp.Version == AttestedProtocol && resp.Error == attestedUnsupportedVersion &&
		len(resp.Signature) == 0 && len(resp.BindingSignature) == 0 && resp.Summary == "" && resp.IssueCounter == nil {
		if k.owner.mode != AttestedNegotiate {
			return AttestedResponse{}, false, fmt.Errorf("%w: enclave does not support protocol version %q, which is required", ErrAttestedProtocol, version)
		}
		return AttestedResponse{}, true, nil
	}
	if resp.Version != version {
		return AttestedResponse{}, false, fmt.Errorf("%w: response version %q, requested %q", ErrAttestedProtocol, resp.Version, version)
	}
	if resp.Error != "" {
		return AttestedResponse{}, false, fmt.Errorf("attested sign: enclave refused: %s", resp.Error)
	}
	if version != AttestedProtocolSummary && resp.Summary != "" {
		return AttestedResponse{}, false, fmt.Errorf("%w: version 1 response carries a summary", ErrAttestedProtocol)
	}
	if err := verify(resp); err != nil {
		return AttestedResponse{}, false, err
	}
	// a summary is trusted only through the binding, so version 2 requires it
	if k.profile != "" || len(resp.BindingSignature) > 0 || version == AttestedProtocolSummary {
		if len(resp.BindingSignature) != ed25519.SignatureSize {
			return AttestedResponse{}, false, fmt.Errorf("%w: binding signature must be %d bytes, got %d", ErrAttestedProtocol, ed25519.SignatureSize, len(resp.BindingSignature))
		}
		if !ed25519.Verify(k.pub, AttestedResponseBinding(req, resp.Signature, resp.Summary), resp.BindingSignature) {
			return AttestedResponse{}, false, fmt.Errorf("%w: %w", ErrAttestedProtocol, ErrInvalidSignature)
		}
	}
	if !k.owner.serves(k) {
		return AttestedResponse{}, false, ErrKeyNotFound
	}
	resp.Summary = clipSummary(resp.Summary)
	return resp, false, nil
}

// clipSummary bounds device-supplied text after its binding has verified.
func clipSummary(s string) string {
	if len(s) <= attestedMaxSummary {
		return s
	}
	return strings.ToValidUTF8(s[:attestedMaxSummary], "") + "..."
}

// AttestedBackend serves keys held by an attested enclave. Keys are resolved
// by Cardano key hash with the role the attested inventory declares. Until
// Load succeeds, and after any Load fails, the backend holds no keys.
type AttestedBackend struct {
	name     string
	profile  string
	enclave  Enclave
	verifier AttestationVerifier
	mode     AttestedProtocolMode
	mu       sync.RWMutex
	keys     map[KeyHash]*attestedKey
	// version1 is set when the enclave refused version 2 under
	// AttestedNegotiate, so later requests start at version 1. Load and a
	// failed round trip clear it.
	version1 bool
}

// requestVersion is the version a tx-body request starts at.
func (b *AttestedBackend) requestVersion() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.mode == AttestedVersion1 || b.version1 {
		return AttestedProtocol
	}
	return AttestedProtocolSummary
}

// pinVersion1 caches version 1 when k is still served, so a reply that
// arrives after Load replaced the keys cannot restore a pin Load cleared. It
// reports whether k is served.
func (b *AttestedBackend) pinVersion1(k *attestedKey) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.keys[k.hash] != k {
		return false
	}
	b.version1 = true
	return true
}

func (b *AttestedBackend) unpinVersion() {
	b.mu.Lock()
	b.version1 = false
	b.mu.Unlock()
}

// WithProtocolMode sets the sign request version policy and returns b. Call it
// before Load.
func (b *AttestedBackend) WithProtocolMode(m AttestedProtocolMode) *AttestedBackend {
	b.mode = m
	return b
}

// NewAttestedBackend builds a backend over enclave, trusting only keys whose
// inventory passes verifier.
func NewAttestedBackend(name string, enclave Enclave, verifier AttestationVerifier) *AttestedBackend {
	return &AttestedBackend{name: name, enclave: enclave, verifier: verifier, keys: map[KeyHash]*attestedKey{}}
}

// NewProfiledAttestedBackend builds an attested backend whose inventory and
// signing requests select one fixed workload profile.
func NewProfiledAttestedBackend(name, profile string, enclave Enclave, verifier AttestationVerifier) *AttestedBackend {
	return &AttestedBackend{name: name, profile: profile, enclave: enclave, verifier: verifier, keys: map[KeyHash]*attestedKey{}}
}

// Load attests the enclave and replaces the served key set with its verified
// inventory. It drops every key first, so a failed or repeated attestation
// (for example after an enclave restart) never leaves stale keys in service.
func (b *AttestedBackend) Load(ctx context.Context) error {
	b.mu.Lock()
	b.keys = map[KeyHash]*attestedKey{}
	b.version1 = false
	b.mu.Unlock()

	nonce := make([]byte, attestedNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("attested nonce: %w", err)
	}
	inv, err := b.enclave.Inventory(ctx, nonce)
	if err != nil {
		return fmt.Errorf("attested inventory: %w", err)
	}
	if inv.Version != AttestedProtocol {
		return fmt.Errorf("%w: inventory version %q", ErrAttestedProtocol, inv.Version)
	}
	if len(inv.Attestation) == 0 {
		return fmt.Errorf("%w: missing attestation evidence", ErrAttestation)
	}
	if err := b.verifier.Verify(ctx, inv.Attestation, InventoryBinding(nonce, inv.Keys)); err != nil {
		return fmt.Errorf("%w: %w", ErrAttestation, err)
	}
	keys := make(map[KeyHash]*attestedKey, len(inv.Keys))
	for _, ki := range inv.Keys {
		if !ki.Role.Valid() {
			return fmt.Errorf("%w: invalid key role %q", ErrAttestedProtocol, ki.Role)
		}
		if len(ki.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: public key must be %d bytes, got %d", ErrAttestedProtocol, ed25519.PublicKeySize, len(ki.PublicKey))
		}
		hash := HashPublicKey(ki.PublicKey)
		if _, dup := keys[hash]; dup {
			return fmt.Errorf("%w: duplicate key %s in inventory", ErrAttestedProtocol, hash)
		}
		keys[hash] = &attestedKey{
			owner:       b,
			enclave:     b.enclave,
			pub:         ed25519.PublicKey(append([]byte(nil), ki.PublicKey...)),
			hash:        hash,
			typ:         ki.Role,
			backendName: b.name,
			profile:     b.profile,
		}
	}
	b.mu.Lock()
	b.keys = keys
	b.mu.Unlock()
	return nil
}

// serves reports whether k is the handle the current attested load issued.
func (b *AttestedBackend) serves(k *attestedKey) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.keys[k.hash] == k
}

// Name returns the configured backend name.
func (b *AttestedBackend) Name() string { return b.name }

// GetKey resolves an attested key by hash.
func (b *AttestedBackend) GetKey(_ context.Context, hash KeyHash) (KeyRef, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	k, ok := b.keys[hash]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return k, nil
}

// ListKeys enumerates the attested keys.
func (b *AttestedBackend) ListKeys(_ context.Context) ([]KeyRef, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]KeyRef, 0, len(b.keys))
	for _, k := range b.keys {
		out = append(out, k)
	}
	return out, nil
}
