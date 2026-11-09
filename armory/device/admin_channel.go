// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package device

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/blinklabs-io/bursa/armory/profile"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	adminChannelKeyDomain = "bursa-armory-admin-channel-key/1"
	adminChannelKDFDomain = "bursa-armory-admin-channel-kdf/1"
	maxEncryptedRequest   = 96 << 10
	x25519KeySize         = 32
)

// EncryptedAdminRequest carries one private-key provisioning request encrypted
// to the ephemeral key authenticated by the device identity proof.
type EncryptedAdminRequest struct {
	Version       string `json:"version"`
	Challenge     []byte `json:"challenge"`
	HostPublicKey []byte `json:"host_public_key"`
	Nonce         []byte `json:"nonce"`
	Ciphertext    []byte `json:"ciphertext"`
}

// AdminChannel is a one-use authenticated channel to an Armory device.
type AdminChannel struct {
	challenge     []byte
	hostPublicKey []byte
	binding       []byte
	key           []byte
}

// NewAdminChannel verifies proof under identity and derives the host half of
// the private-key provisioning channel.
func NewAdminChannel(
	route string,
	identity ed25519.PublicKey,
	req IdentityProofRequest,
	proof IdentityProofResponse,
	hostPrivate *ecdh.PrivateKey,
) (*AdminChannel, error) {
	if !AdminRouteContainsSecrets(route) || req.Version != Protocol ||
		req.Route != route || hostPrivate == nil ||
		len(identity) != ed25519.PublicKeySize ||
		!bytes.Equal(req.HostPublicKey, hostPrivate.PublicKey().Bytes()) ||
		proof.Version != Protocol || !bytes.Equal(proof.PublicKey, identity) {
		return nil, errors.New("invalid device identity proof")
	}

	binding := IdentityBinding(req, proof.PublicKey, proof.EncryptionPublicKey)
	if !ed25519.Verify(identity, binding, proof.Attestation) {
		return nil, errors.New(
			"device identity proof does not verify under the pinned identity key",
		)
	}

	devicePublic, err := ecdh.X25519().NewPublicKey(proof.EncryptionPublicKey)
	if err != nil {
		return nil, errors.New(
			"device identity proof has an invalid encryption key",
		)
	}

	shared, err := hostPrivate.ECDH(devicePublic)
	if err != nil {
		return nil, fmt.Errorf("derive device channel: %w", err)
	}
	defer clear(shared)

	key, err := deriveAdminChannelKey(shared, binding)
	if err != nil {
		return nil, err
	}

	return &AdminChannel{
		challenge:     bytes.Clone(req.Challenge),
		hostPublicKey: bytes.Clone(req.HostPublicKey),
		binding:       binding,
		key:           key,
	}, nil
}

// Seal encrypts body for the authenticated device. The channel key is erased
// after this call, whether it succeeds or fails.
func (c *AdminChannel) Seal(body []byte) (EncryptedAdminRequest, error) {
	if c == nil || len(c.key) != chacha20poly1305.KeySize {
		return EncryptedAdminRequest{}, errors.New(
			"admin channel is not available",
		)
	}
	defer func() {
		clear(c.key)
		c.key = nil
	}()

	aead, err := chacha20poly1305.NewX(c.key)
	if err != nil {
		return EncryptedAdminRequest{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return EncryptedAdminRequest{}, fmt.Errorf(
			"generate admin channel nonce: %w",
			err,
		)
	}

	return EncryptedAdminRequest{
		Version:       Protocol,
		Challenge:     bytes.Clone(c.challenge),
		HostPublicKey: bytes.Clone(c.hostPublicKey),
		Nonce:         nonce,
		Ciphertext:    aead.Seal(nil, nonce, body, c.binding),
	}, nil
}

func deriveAdminPrivate(
	challengeKey []byte,
	route string,
	challenge, hostPublicKey []byte,
) (*ecdh.PrivateKey, error) {
	m := hmac.New(sha256.New, challengeKey)
	for _, field := range [][]byte{
		[]byte(adminChannelKeyDomain),
		[]byte(Protocol),
		[]byte(route),
		challenge,
		hostPublicKey,
	} {
		_, _ = m.Write([]byte(strconv.Itoa(len(field)) + ":"))
		_, _ = m.Write(field)
	}
	seed := m.Sum(nil)
	defer clear(seed)

	return ecdh.X25519().NewPrivateKey(seed)
}

func deriveAdminChannelKey(shared, binding []byte) ([]byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(
		hkdf.New(sha256.New, shared, binding, []byte(adminChannelKDFDomain)),
		key,
	); err != nil {
		clear(key)
		return nil, fmt.Errorf("derive admin channel key: %w", err)
	}

	return key, nil
}

func (s *Service) openAdminRequest(
	route string,
	req EncryptedAdminRequest,
) ([]byte, error) {
	if req.Version != Protocol || !AdminRouteContainsSecrets(route) ||
		len(req.HostPublicKey) != x25519KeySize {
		return nil, errors.New("invalid encrypted admin request")
	}
	if err := s.validateChallenge(req.Challenge); err != nil {
		return nil, err
	}

	hostPublic, err := ecdh.X25519().NewPublicKey(req.HostPublicKey)
	if err != nil {
		return nil, errors.New("invalid encrypted admin request")
	}
	devicePrivate, err := deriveAdminPrivate(
		s.challengeKey,
		route,
		req.Challenge,
		req.HostPublicKey,
	)
	if err != nil {
		return nil, err
	}
	shared, err := devicePrivate.ECDH(hostPublic)
	if err != nil {
		return nil, errors.New("invalid encrypted admin request")
	}
	defer clear(shared)

	identity, err := s.chip.PublicKeyEd25519(profile.IdentityKeyID)
	if err != nil {
		s.logf("read identity public key: %v", err)
		return nil, errIdentityNotProvisioned
	}
	proof := IdentityProofRequest{
		Version:       Protocol,
		Route:         route,
		Challenge:     req.Challenge,
		HostPublicKey: req.HostPublicKey,
	}
	binding := IdentityBinding(
		proof,
		identity,
		devicePrivate.PublicKey().Bytes(),
	)
	key, err := deriveAdminChannelKey(shared, binding)
	if err != nil {
		return nil, err
	}
	defer clear(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil || len(req.Nonce) != chacha20poly1305.NonceSizeX {
		return nil, errors.New("invalid encrypted admin request")
	}
	body, err := aead.Open(nil, req.Nonce, req.Ciphertext, binding)
	if err != nil {
		return nil, errors.New("invalid encrypted admin request")
	}
	if len(body) > maxRequest {
		clear(body)
		return nil, errMalformedRequest
	}
	if err = s.takeChallenge(req.Challenge); err != nil {
		clear(body)
		return nil, err
	}

	return body, nil
}
