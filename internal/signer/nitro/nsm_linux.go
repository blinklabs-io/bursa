// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//go:build linux

package nitro

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/blinklabs-io/bursa/internal/signer/nitro/kmsrecipient"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
)

const recipientRSAKeyBits = 2048

type nsmSession interface {
	Send(request.Request) (response.Response, error)
	Close() error
}

type nsmRecipient struct {
	privateKey  *rsa.PrivateKey
	publicKey   []byte
	openSession func() (nsmSession, error)
}

// NewNSMRecipient creates the ephemeral RSA recipient key whose public half is
// attested by the Nitro Security Module. The private half never leaves this
// process or appears in an RPC.
func NewNSMRecipient() (Recipient, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, recipientRSAKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generate KMS recipient key: %w", err)
	}
	return newNSMRecipient(privateKey, func() (nsmSession, error) {
		return nsm.OpenDefaultSession()
	})
}

func newNSMRecipient(privateKey *rsa.PrivateKey, openSession func() (nsmSession, error)) (*nsmRecipient, error) {
	if privateKey == nil || openSession == nil {
		return nil, errors.New("NSM recipient key and session factory are required")
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal KMS recipient key: %w", err)
	}
	return &nsmRecipient{privateKey: privateKey, publicKey: publicKey, openSession: openSession}, nil
}

func (r *nsmRecipient) request(value *request.Attestation) ([]byte, error) {
	session, err := r.openSession()
	if err != nil {
		return nil, fmt.Errorf("open NSM session: %w", err)
	}
	defer session.Close() //nolint:errcheck // the completed NSM request is authoritative
	result, err := session.Send(value)
	if err != nil {
		return nil, fmt.Errorf("request NSM attestation: %w", err)
	}
	if result.Error != "" || result.Attestation == nil || len(result.Attestation.Document) == 0 {
		return nil, errors.New("NSM did not return an attestation document")
	}
	return bytes.Clone(result.Attestation.Document), nil
}

func (r *nsmRecipient) KMSAttestation() ([]byte, error) {
	return r.request(&request.Attestation{PublicKey: bytes.Clone(r.publicKey)})
}

func (r *nsmRecipient) DecryptKMSRecipient(ciphertext []byte) ([]byte, error) {
	return kmsrecipient.Decrypt(r.privateKey, ciphertext)
}

func (r *nsmRecipient) Attest(userData []byte) ([]byte, error) {
	return r.request(&request.Attestation{UserData: bytes.Clone(userData)})
}
