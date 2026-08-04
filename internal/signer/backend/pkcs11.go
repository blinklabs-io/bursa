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

//go:build pkcs11

// Package backend, PKCS#11 driver. Compiled only with -tags pkcs11 (requires
// CGO). Keys never leave the HSM: the token holds the private key and performs
// the Ed25519 signature. Because no in-process private key is available, this
// backend deliberately does NOT implement LoadedKeyProvider, so the CIP-8 path
// (which needs a *bursa.LoadedKey) correctly rejects pkcs11 keys — the same
// posture as the Vault backend.
package backend

import (
	"context"
	"crypto/ed25519"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

// PKCS#11 v3.0 constants for Edwards-curve keys and PureEdDSA. miekg/pkcs11
// v1.1.2 does not define these, so we declare the standard spec values.
const (
	ckkECEdwards = 0x00000040 // CKK_EC_EDWARDS
	ckmEDDSA     = 0x00001057 // CKM_EDDSA (PureEdDSA over the raw message)
)

// pkcs11Key is a KeyRef whose private key lives in the HSM. Sign delegates to
// the token over the shared session.
type pkcs11Key struct {
	label       string
	pub         ed25519.PublicKey
	hash        KeyHash
	typ         KeyType
	backendName string
	priv        pkcs11.ObjectHandle
	sign        func(priv pkcs11.ObjectHandle, msg []byte) ([]byte, error)
}

func (k *pkcs11Key) Hash() KeyHash                { return k.hash }
func (k *pkcs11Key) PublicKey() ed25519.PublicKey { return k.pub }
func (k *pkcs11Key) Type() KeyType                { return k.typ }
func (k *pkcs11Key) Extended() bool               { return false }
func (k *pkcs11Key) Backend() string              { return k.backendName }

// Sign asks the HSM to produce a 64-byte Ed25519 signature over digest.
// CKM_EDDSA with no parameter is PureEdDSA, so the token signs digest as the
// message exactly like ed25519.Sign — byte-for-byte identical to the software
// and Vault backends for the same key and message (Ed25519 is deterministic).
func (k *pkcs11Key) Sign(_ context.Context, digest []byte) ([]byte, error) {
	sig, err := k.sign(k.priv, digest)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 sign: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("pkcs11 sign: expected %d-byte signature, got %d", ed25519.SignatureSize, len(sig))
	}
	return sig, nil
}

// PKCS11Backend signs standard Ed25519 keys held in a PKCS#11 token (HSM).
type PKCS11Backend struct {
	name    string
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
	// mu serializes token operations: a PKCS#11 session is single-threaded and
	// SignInit/Sign form one non-reentrant operation.
	mu   sync.Mutex
	keys map[KeyHash]*pkcs11Key
}

// NewPKCS11Backend loads the module, selects the token, logs in with the PIN,
// and enumerates its Ed25519 signing keys. The returned backend keeps the
// session open for the process lifetime; call Close to release it.
func NewPKCS11Backend(cfg PKCS11Config) (Backend, error) {
	if cfg.Module == "" {
		return nil, errors.New("pkcs11 backend requires a module path")
	}
	if cfg.TokenLabel == "" && cfg.Slot == nil {
		return nil, errors.New("pkcs11 backend requires a token label or slot")
	}
	for _, k := range cfg.Keys {
		if !k.Type.Valid() {
			return nil, fmt.Errorf("pkcs11 key %q: invalid key type %q", k.Label, k.Type)
		}
	}

	p := pkcs11.New(cfg.Module)
	if p == nil {
		return nil, fmt.Errorf("pkcs11: failed to load module %q", cfg.Module)
	}
	if err := p.Initialize(); err != nil {
		p.Destroy()
		return nil, fmt.Errorf("pkcs11 initialize: %w", err)
	}

	b := &PKCS11Backend{name: cfg.Name, ctx: p, keys: map[KeyHash]*pkcs11Key{}}

	slot, err := selectSlot(p, cfg)
	if err != nil {
		_ = b.teardown(false, false)
		return nil, err
	}
	session, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		_ = b.teardown(false, false)
		return nil, fmt.Errorf("pkcs11 open session: %w", err)
	}
	b.session = session
	if err := p.Login(session, pkcs11.CKU_USER, cfg.PIN); err != nil {
		_ = b.teardown(true, false)
		return nil, fmt.Errorf("pkcs11 login: %w", err)
	}

	if err := b.loadKeys(cfg); err != nil {
		_ = b.teardown(true, true)
		return nil, err
	}
	if len(b.keys) == 0 {
		_ = b.teardown(true, true)
		return nil, fmt.Errorf("pkcs11 backend %q: no Ed25519 signing keys found on the token", cfg.Name)
	}
	return b, nil
}

// signWithSession runs one SignInit+Sign under the session mutex.
func (b *PKCS11Backend) signWithSession(priv pkcs11.ObjectHandle, msg []byte) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(ckmEDDSA, nil)}
	if err := b.ctx.SignInit(b.session, mech, priv); err != nil {
		return nil, fmt.Errorf("sign init: %w", err)
	}
	sig, err := b.ctx.Sign(b.session, msg)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return sig, nil
}

func (b *PKCS11Backend) loadKeys(cfg PKCS11Config) error {
	var filter map[string]KeyType
	if len(cfg.Keys) > 0 {
		filter = make(map[string]KeyType, len(cfg.Keys))
		for _, k := range cfg.Keys {
			filter[k.Label] = k.Type
		}
	}

	privs, err := findEdwardsObjects(b.ctx, b.session, pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		return fmt.Errorf("pkcs11 enumerate private keys: %w", err)
	}
	for _, priv := range privs {
		attrs, err := b.ctx.GetAttributeValue(b.session, priv, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		})
		if err != nil {
			return fmt.Errorf("pkcs11 read private key attributes: %w", err)
		}
		id, label := attrs[0].Value, string(attrs[1].Value)

		typ := KeyTypePayment
		if filter != nil {
			t, ok := filter[label]
			if !ok {
				continue // not in the configured allowlist
			}
			typ = t
		}

		pub, err := publicKeyForID(b.ctx, b.session, id)
		if err != nil {
			// A signing key with no readable public counterpart cannot be
			// addressed by key hash; skip it rather than fail the whole load.
			continue
		}
		hash := HashPublicKey(pub)
		b.keys[hash] = &pkcs11Key{
			label:       label,
			pub:         ed25519.PublicKey(pub),
			hash:        hash,
			typ:         typ,
			backendName: b.name,
			priv:        priv,
			sign:        b.signWithSession,
		}
	}
	return nil
}

// selectSlot resolves the configured slot id or token label to a slot with a
// present token.
func selectSlot(p *pkcs11.Ctx, cfg PKCS11Config) (uint, error) {
	slots, err := p.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("pkcs11 get slot list: %w", err)
	}
	if cfg.Slot != nil {
		for _, s := range slots {
			if s == *cfg.Slot {
				return s, nil
			}
		}
		return 0, fmt.Errorf("pkcs11: slot %d not found or has no token", *cfg.Slot)
	}
	for _, s := range slots {
		ti, err := p.GetTokenInfo(s)
		if err != nil {
			continue
		}
		if strings.TrimSpace(ti.Label) == cfg.TokenLabel {
			return s, nil
		}
	}
	return 0, fmt.Errorf("pkcs11: no token with label %q", cfg.TokenLabel)
}

// findEdwardsObjects returns all CKK_EC_EDWARDS objects of the given class.
func findEdwardsObjects(p *pkcs11.Ctx, session pkcs11.SessionHandle, class uint) ([]pkcs11.ObjectHandle, error) {
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, uint(ckkECEdwards)),
	}
	if err := p.FindObjectsInit(session, tmpl); err != nil {
		return nil, err
	}
	var out []pkcs11.ObjectHandle
	for {
		objs, _, err := p.FindObjects(session, 128)
		if err != nil {
			_ = p.FindObjectsFinal(session)
			return nil, err
		}
		if len(objs) == 0 {
			break
		}
		out = append(out, objs...)
	}
	if err := p.FindObjectsFinal(session); err != nil {
		return nil, err
	}
	return out, nil
}

// publicKeyForID finds the Edwards public key object with the given CKA_ID and
// returns its raw 32-byte Ed25519 public key.
func publicKeyForID(p *pkcs11.Ctx, session pkcs11.SessionHandle, id []byte) ([]byte, error) {
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, uint(ckkECEdwards)),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	if err := p.FindObjectsInit(session, tmpl); err != nil {
		return nil, err
	}
	objs, _, err := p.FindObjects(session, 1)
	if err != nil {
		_ = p.FindObjectsFinal(session)
		return nil, err
	}
	if err := p.FindObjectsFinal(session); err != nil {
		return nil, err
	}
	if len(objs) == 0 {
		return nil, errors.New("no matching public key object")
	}
	attrs, err := p.GetAttributeValue(session, objs[0], []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return nil, err
	}
	return edwardsPublicKey(attrs[0].Value)
}

// edwardsPublicKey extracts the 32-byte Ed25519 public key from a CKA_EC_POINT
// value. Per PKCS#11 v3.0 the point is a DER-encoded OCTET STRING wrapping the
// raw key (0x04 0x20 || key); some tokens return the raw 32 bytes.
func edwardsPublicKey(ecPoint []byte) ([]byte, error) {
	var raw []byte
	if _, err := asn1.Unmarshal(ecPoint, &raw); err == nil && len(raw) == ed25519.PublicKeySize {
		return raw, nil
	}
	if len(ecPoint) == ed25519.PublicKeySize {
		return ecPoint, nil
	}
	return nil, fmt.Errorf("unexpected EC_POINT encoding (%d bytes)", len(ecPoint))
}

func (b *PKCS11Backend) Name() string { return b.name }

func (b *PKCS11Backend) GetKey(_ context.Context, hash KeyHash) (KeyRef, error) {
	k, ok := b.keys[hash]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return k, nil
}

func (b *PKCS11Backend) ListKeys(_ context.Context) ([]KeyRef, error) {
	out := make([]KeyRef, 0, len(b.keys))
	for _, k := range b.keys {
		out = append(out, k)
	}
	return out, nil
}

// Close logs out and finalizes the module, releasing the session.
func (b *PKCS11Backend) Close() error {
	return b.teardown(true, true)
}

// teardown releases resources in reverse order of acquisition. loggedIn and
// sessionOpen let partially-constructed backends clean up on the error path.
func (b *PKCS11Backend) teardown(sessionOpen, loggedIn bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ctx == nil {
		return nil
	}
	if loggedIn {
		_ = b.ctx.Logout(b.session)
	}
	if sessionOpen {
		_ = b.ctx.CloseSession(b.session)
	}
	err := b.ctx.Finalize()
	b.ctx.Destroy()
	b.ctx = nil
	return err
}
