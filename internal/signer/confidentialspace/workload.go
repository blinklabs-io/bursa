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

package confidentialspace

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"sync"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

const (
	envelopeVersionV1 = "bursa-confidential-space-key/1"
	envelopeVersion   = "bursa-confidential-space-key/2"
	envelopePending   = "counter-pending"
	envelopeActive    = "active"
	maxRequestBody    = 64 << 10
	maxRequestNonces  = 4096
)

// TokenSource requests a custom-audience attestation token from the
// Confidential Space launcher.
type TokenSource interface {
	Token(ctx context.Context, audience string, nonces []string) ([]byte, error)
}

// KeyWrapper wraps and unwraps one data-encryption key with Cloud KMS.
type KeyWrapper interface {
	Wrap(ctx context.Context, plaintext, aad []byte) ([]byte, error)
	Unwrap(ctx context.Context, ciphertext, aad []byte) ([]byte, error)
}

// EnvelopeStore persists only envelope-encrypted key material.
type EnvelopeStore interface {
	Load() ([]byte, error)
	Create([]byte) error
	Replace([]byte, []byte) error
}

// CounterStore binds durable state to one pool cold key and atomically reserves
// sequential operational-certificate issue counters.
type CounterStore interface {
	Prepare(context.Context, backend.KeyHash, bool) error
	CheckAndAdvance(context.Context, backend.KeyHash, uint64) error
}

// Config contains the workload's immutable security inputs.
type Config struct {
	Audience string
	KMSKey   string
	Tokens   TokenSource
	Wrapper  KeyWrapper
	Store    EnvelopeStore
	Counter  CounterStore
}

type envelope struct {
	Version    string          `json:"version"`
	Phase      string          `json:"phase,omitempty"`
	Role       backend.KeyType `json:"role"`
	KMSKey     string          `json:"kms_key"`
	PublicKey  []byte          `json:"public_key"`
	Nonce      []byte          `json:"nonce"`
	Ciphertext []byte          `json:"ciphertext"`
	WrappedDEK []byte          `json:"wrapped_dek"`
}

type keyMaterial struct {
	priv    ed25519.PrivateKey
	stored  []byte
	active  []byte
	pending bool
}

// Workload implements the enclave side of the attested signer protocol for a
// single pool cold key. The private key exists only in this process and in the
// encrypted envelope persisted by Store.
type Workload struct {
	audience string
	tokens   TokenSource
	pub      ed25519.PublicKey
	priv     ed25519.PrivateKey
	hash     backend.KeyHash
	counter  CounterStore

	mu        sync.Mutex
	nonces    map[[32]byte]struct{}
	nonceFIFO [][32]byte
	nonceNext int
	closed    bool
	signFunc  func(ed25519.PrivateKey, []byte) []byte
}

// New creates or reloads a pool cold key. A new key is generated inside the
// workload, encrypted with a fresh AES-256-GCM DEK, and the DEK is wrapped by
// Cloud KMS before anything is persisted.
func New(ctx context.Context, cfg Config) (*Workload, error) {
	if cfg.Audience == "" {
		return nil, errors.New(
			"confidential space workload requires an audience",
		)
	}
	if cfg.KMSKey == "" || len(cfg.KMSKey) > 1024 {
		return nil, errors.New("confidential space workload requires a KMS key")
	}
	if cfg.Tokens == nil || cfg.Wrapper == nil || cfg.Store == nil ||
		cfg.Counter == nil {
		return nil, errors.New(
			"confidential space workload requires token, KMS, envelope, and counter providers",
		)
	}
	key, err := loadOrCreateKey(ctx, cfg)
	if err != nil {
		return nil, err
	}
	pub := append(ed25519.PublicKey(nil), key.priv.Public().(ed25519.PublicKey)...)
	hash := backend.HashPublicKey(pub)
	if err := cfg.Counter.Prepare(ctx, hash, key.pending); err != nil {
		wipe(key.priv)
		return nil, fmt.Errorf("prepare counter state: %w", err)
	}
	if key.pending {
		if err := activateEnvelope(ctx, cfg, key, pub); err != nil {
			wipe(key.priv)
			return nil, fmt.Errorf("activate wrapped key: %w", err)
		}
	}
	return &Workload{
		audience:  cfg.Audience,
		tokens:    cfg.Tokens,
		pub:       pub,
		priv:      key.priv,
		hash:      hash,
		counter:   cfg.Counter,
		nonces:    make(map[[32]byte]struct{}),
		nonceFIFO: make([][32]byte, 0, maxRequestNonces),
		signFunc:  ed25519.Sign,
	}, nil
}

func loadOrCreateKey(
	ctx context.Context,
	cfg Config,
) (*keyMaterial, error) {
	data, err := cfg.Store.Load()
	switch {
	case err == nil:
		return openEnvelope(ctx, cfg, data)
	case !errors.Is(err, ErrEnvelopeNotFound):
		return nil, fmt.Errorf("load wrapped key: %w", err)
	}

	key, err := createEnvelope(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := cfg.Store.Create(key.stored); err == nil {
		return key, nil
	} else if !errors.Is(err, ErrEnvelopeExists) {
		wipe(key.priv)
		return nil, fmt.Errorf("persist wrapped key: %w", err)
	}

	// Another workload won the create race. Discard this key and load the
	// published envelope so all replicas expose the same public identity.
	wipe(key.priv)
	data, err = cfg.Store.Load()
	if err != nil {
		return nil, fmt.Errorf("load concurrently created wrapped key: %w", err)
	}
	return openEnvelope(ctx, cfg, data)
}

func createEnvelope(
	ctx context.Context,
	cfg Config,
) (*keyMaterial, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, fmt.Errorf("generate pool key: %w", err)
	}
	defer wipe(seed)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := append(ed25519.PublicKey(nil), priv.Public().(ed25519.PublicKey)...)

	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		wipe(priv)
		return nil, fmt.Errorf("generate data-encryption key: %w", err)
	}
	defer wipe(dek)
	block, err := aes.NewCipher(dek)
	if err != nil {
		wipe(priv)
		return nil, fmt.Errorf("initialize envelope cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		wipe(priv)
		return nil, fmt.Errorf("initialize envelope AEAD: %w", err)
	}
	e := envelope{
		Version:   envelopeVersion,
		Phase:     envelopePending,
		Role:      backend.KeyTypePool,
		KMSKey:    cfg.KMSKey,
		PublicKey: pub,
	}
	data, err := encodeEnvelope(ctx, cfg, e, seed, dek, gcm)
	if err != nil {
		wipe(priv)
		return nil, err
	}
	e.Phase = envelopeActive
	active, err := encodeEnvelope(ctx, cfg, e, seed, dek, gcm)
	if err != nil {
		wipe(priv)
		return nil, err
	}
	return &keyMaterial{
		priv:    priv,
		stored:  data,
		active:  active,
		pending: true,
	}, nil
}

func encodeEnvelope(
	ctx context.Context,
	cfg Config,
	e envelope,
	seed, dek []byte,
	gcm cipher.AEAD,
) ([]byte, error) {
	e.Nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, e.Nonce); err != nil {
		return nil, fmt.Errorf("generate envelope nonce: %w", err)
	}
	aad := envelopeAAD(e)
	e.Ciphertext = gcm.Seal(nil, e.Nonce, seed, aad)
	wrapped, err := cfg.Wrapper.Wrap(ctx, dek, aad)
	if err != nil {
		return nil, fmt.Errorf("wrap data-encryption key: %w", err)
	}
	e.WrappedDEK = wrapped
	data, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("encode wrapped key: %w", err)
	}
	return data, nil
}

func openEnvelope(
	ctx context.Context,
	cfg Config,
	data []byte,
) (*keyMaterial, error) {
	var e envelope
	if len(data) > maxRequestBody {
		return nil, errors.New("wrapped key exceeds size limit")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("decode wrapped key: %w", err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return nil, fmt.Errorf("decode wrapped key: %w", err)
	}
	if !validEnvelopePhase(e) || e.Role != backend.KeyTypePool ||
		e.KMSKey != cfg.KMSKey {
		return nil, errors.New(
			"wrapped key metadata does not match workload configuration",
		)
	}
	if len(e.PublicKey) != ed25519.PublicKeySize || len(e.Nonce) == 0 ||
		len(e.Ciphertext) == 0 ||
		len(e.WrappedDEK) == 0 {
		return nil, errors.New("wrapped key is incomplete")
	}
	aad := envelopeAAD(e)
	dek, err := cfg.Wrapper.Unwrap(ctx, e.WrappedDEK, aad)
	if err != nil {
		return nil, fmt.Errorf("unwrap data-encryption key: %w", err)
	}
	defer wipe(dek)
	if len(dek) != 32 {
		return nil, errors.New(
			"unwrapped data-encryption key has invalid length",
		)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("initialize envelope cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize envelope AEAD: %w", err)
	}
	if len(e.Nonce) != gcm.NonceSize() {
		return nil, errors.New("wrapped key nonce has invalid length")
	}
	seed, err := gcm.Open(nil, e.Nonce, e.Ciphertext, aad)
	if err != nil {
		return nil, errors.New("decrypt wrapped key")
	}
	defer wipe(seed)
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("wrapped pool key has invalid length")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if !ed25519.PublicKey(priv.Public().(ed25519.PublicKey)).
		Equal(ed25519.PublicKey(e.PublicKey)) {
		wipe(priv)
		return nil, errors.New(
			"wrapped key public key does not match plaintext",
		)
	}
	key := &keyMaterial{
		priv:    priv,
		stored:  append([]byte(nil), data...),
		pending: e.Version == envelopeVersion && e.Phase == envelopePending,
	}
	if key.pending {
		e.Phase = envelopeActive
		active, err := encodeEnvelope(ctx, cfg, e, seed, dek, gcm)
		if err != nil {
			wipe(priv)
			return nil, err
		}
		key.active = active
	}
	return key, nil
}

func validEnvelopePhase(e envelope) bool {
	switch e.Version {
	case envelopeVersionV1:
		return e.Phase == ""
	case envelopeVersion:
		return e.Phase == envelopePending || e.Phase == envelopeActive
	default:
		return false
	}
}

func envelopeAAD(e envelope) []byte {
	buf := make(
		[]byte,
		0,
		len(e.Version)+len(e.Role)+len(e.KMSKey)+len(e.PublicKey)+16,
	)
	parts := [][]byte{[]byte(e.Version), []byte(e.Role), []byte(e.KMSKey), e.PublicKey}
	if e.Version == envelopeVersion {
		parts = append(parts, []byte(e.Phase))
	}
	for _, part := range parts {
		var size [4]byte
		binary.BigEndian.PutUint32(
			size[:],
			uint32(len(part)), // #nosec G115 -- envelope and key fields are bounded above.
		)
		buf = append(buf, size[:]...)
		buf = append(buf, part...)
	}
	return buf
}

func activateEnvelope(
	ctx context.Context,
	cfg Config,
	key *keyMaterial,
	publicKey ed25519.PublicKey,
) error {
	for range maxCounterCASRetries {
		if err := cfg.Store.Replace(key.stored, key.active); err == nil {
			return nil
		} else if !errors.Is(err, ErrEnvelopeChanged) {
			return err
		}
		data, err := cfg.Store.Load()
		if err != nil {
			return err
		}
		current, err := openEnvelope(ctx, cfg, data)
		if err != nil {
			return err
		}
		currentPublicKey := append(
			ed25519.PublicKey(nil),
			current.priv.Public().(ed25519.PublicKey)...,
		)
		wipe(current.priv)
		if !ed25519.PublicKey(publicKey).Equal(currentPublicKey) {
			return ErrEnvelopeChanged
		}
		if !current.pending {
			return nil
		}
		key.stored = current.stored
		key.active = current.active
	}
	return errors.New("wrapped key changed too often")
}

// Inventory returns the public key and a custom token bound to the caller's
// nonce and the exact inventory.
func (w *Workload) Inventory(
	ctx context.Context,
	nonce []byte,
) (backend.AttestedInventory, error) {
	if len(nonce) != 32 {
		return backend.AttestedInventory{}, errors.New(
			"inventory nonce must be 32 bytes",
		)
	}
	keys := []backend.AttestedKeyInfo{
		{Role: backend.KeyTypePool, PublicKey: append([]byte(nil), w.pub...)},
	}
	binding := backend.InventoryBinding(nonce, keys)
	token, err := w.tokens.Token(
		ctx,
		w.audience,
		[]string{hex.EncodeToString(binding)},
	)
	if err != nil {
		return backend.AttestedInventory{}, fmt.Errorf(
			"request attestation token: %w",
			err,
		)
	}
	if len(token) == 0 {
		return backend.AttestedInventory{}, errors.New(
			"attestation token is empty",
		)
	}
	return backend.AttestedInventory{
		Version:     backend.AttestedProtocol,
		Keys:        keys,
		Attestation: token,
	}, nil
}

// Sign permits only canonical pool operational-certificate signable bytes with
// an explicit issue counter. It refuses opcert-next, which would let the host
// re-issue an existing number for a new KES key, and profiled requests, whose
// binding signature this workload does not produce.
func (w *Workload) Sign(
	ctx context.Context,
	req backend.AttestedRequest,
) (backend.AttestedResponse, error) {
	resp := backend.AttestedResponse{
		Version: backend.AttestedProtocol,
		Nonce:   append([]byte(nil), req.Nonce...),
	}
	if req.Version != backend.AttestedProtocol ||
		req.Purpose != backend.PurposeOpCert ||
		req.Profile != "" ||
		req.Role != backend.KeyTypePool ||
		req.KeyHash != w.hash.String() ||
		len(req.Nonce) != 32 ||
		len(req.Payload) != 48 {
		resp.Error = "request refused"
		return resp, nil
	}
	var nonce [32]byte
	copy(nonce[:], req.Nonce)

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return backend.AttestedResponse{}, errors.New("workload is closed")
	}
	if _, exists := w.nonces[nonce]; exists {
		resp.Error = "request refused"
		return resp, nil
	}
	issueNumber := binary.BigEndian.Uint64(req.Payload[32:40])
	if err := w.counter.CheckAndAdvance(ctx, w.hash, issueNumber); err != nil {
		resp.Error = "request refused"
		return resp, nil
	}
	if len(w.nonceFIFO) >= maxRequestNonces {
		delete(w.nonces, w.nonceFIFO[w.nonceNext])
		w.nonceFIFO[w.nonceNext] = nonce
		w.nonceNext = (w.nonceNext + 1) % maxRequestNonces
	} else {
		w.nonceFIFO = append(w.nonceFIFO, nonce)
	}
	w.nonces[nonce] = struct{}{}
	sig := w.signFunc(w.priv, req.Payload)
	if len(sig) != ed25519.SignatureSize ||
		!ed25519.Verify(w.pub, req.Payload, sig) {
		wipe(sig)
		return backend.AttestedResponse{}, errors.New(
			"pool key signature verification failed",
		)
	}
	resp.Signature = sig
	return resp, nil
}

// Handler serves the existing attested signer protocol with strict body
// bounds and JSON decoding.
func (w *Workload) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/inventory", w.handleInventory)
	mux.HandleFunc("POST /v1/sign", w.handleSign)
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 ||
			len(r.TLS.VerifiedChains) == 0 {
			http.Error(rw, "client certificate required", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(rw, r)
	})
}

func (w *Workload) handleInventory(rw http.ResponseWriter, r *http.Request) {
	var req struct {
		Nonce []byte `json:"nonce"`
	}
	if err := decodeRequest(rw, r, &req); err != nil {
		http.Error(rw, "invalid request", http.StatusBadRequest)
		return
	}
	inv, err := w.Inventory(r.Context(), req.Nonce)
	if err != nil {
		http.Error(rw, "attestation unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(rw, inv)
}

func (w *Workload) handleSign(rw http.ResponseWriter, r *http.Request) {
	var req backend.AttestedRequest
	if err := decodeRequest(rw, r, &req); err != nil {
		http.Error(rw, "invalid request", http.StatusBadRequest)
		return
	}
	resp, err := w.Sign(r.Context(), req)
	if err != nil {
		http.Error(rw, "signing unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(rw, resp)
}

func decodeRequest(rw http.ResponseWriter, r *http.Request, out any) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return errors.New("content type must be application/json")
	}
	r.Body = http.MaxBytesReader(rw, r.Body, maxRequestBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	return requireJSONEOF(dec)
}

func requireJSONEOF(dec *json.Decoder) error {
	if err := dec.Decode(&json.RawMessage{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func writeJSON(rw http.ResponseWriter, v any) {
	rw.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(rw).Encode(v); err != nil {
		return
	}
}

// Close wipes the in-memory private key.
func (w *Workload) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.closed {
		wipe(w.priv)
		w.closed = true
	}
	return nil
}

func wipe(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}
