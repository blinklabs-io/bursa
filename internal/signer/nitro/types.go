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

// Package nitro implements the AWS Nitro Enclaves side of Bursa's attested
// signer protocol. The host handles storage and byte forwarding only; key
// recovery and signing happen inside the enclave.
package nitro

import (
	"context"
	"errors"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

const (
	// Protocol is the version carried by every host/enclave RPC.
	Protocol = "bursa-nitro-custody/1"
	// EnvelopeVersion is the only wrapped-key representation accepted.
	EnvelopeVersion = 1
	// DefaultSignerPort is the enclave gRPC listener port.
	DefaultSignerPort = 10350
	// DefaultKMSProxyPort is the host KMS byte-proxy listener port.
	DefaultKMSProxyPort = 10351
)

var (
	// ErrProtocol marks a malformed, unsupported, or replayed RPC.
	ErrProtocol = errors.New("nitro custody protocol violation")
	// ErrNotLoaded is returned until an envelope has been recovered.
	ErrNotLoaded = errors.New("nitro custody key is not loaded")
	// ErrMeasurement is returned when recipient evidence is absent or debug.
	ErrMeasurement = errors.New("nitro production measurement required")
	// ErrEnvelope marks malformed or unauthentic wrapped key material.
	ErrEnvelope = errors.New("invalid wrapped key envelope")
	// ErrNoEnvelope marks an existing Secrets Manager secret with no value.
	ErrNoEnvelope = errors.New("wrapped key envelope is absent")
)

// Credentials are temporary AWS credentials delivered to the enclave for a
// single KMS client. Long-lived credentials are deliberately unsupported.
type Credentials struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
}

func (c Credentials) validate() error {
	if c.AccessKeyID == "" || c.SecretAccessKey == "" || c.SessionToken == "" {
		return errors.New("temporary AWS credentials are incomplete")
	}
	return nil
}

// Envelope is the only key representation permitted outside the enclave.
// Ciphertext is an AES-256-GCM encrypted Ed25519 seed. EncryptedDataKey is the
// KMS CiphertextBlob for the AES key.
type Envelope struct {
	Version          uint            `json:"version"`
	Role             backend.KeyType `json:"role"`
	KMSKeyID         string          `json:"kms_key_id"`
	PublicKey        []byte          `json:"public_key"`
	EncryptedDataKey []byte          `json:"encrypted_data_key"`
	Ciphertext       []byte          `json:"ciphertext"`
	Nonce            []byte          `json:"nonce"`
}

// ProvisionRequest asks the enclave to generate and wrap one pool cold key.
type ProvisionRequest struct {
	Version     string          `json:"version"`
	Region      string          `json:"region"`
	Credentials Credentials     `json:"credentials"`
	KMSKeyID    string          `json:"kms_key_id"`
	Role        backend.KeyType `json:"role"`
}

// ProvisionResponse returns only wrapped material and public metadata.
type ProvisionResponse struct {
	Version  string   `json:"version"`
	Envelope Envelope `json:"envelope"`
}

// ReloadRequest recovers an existing envelope after process or enclave restart.
type ReloadRequest struct {
	Version     string      `json:"version"`
	Region      string      `json:"region"`
	Credentials Credentials `json:"credentials"`
	Envelope    Envelope    `json:"envelope"`
}

// ReloadResponse confirms which public key was installed.
type ReloadResponse struct {
	Version   string `json:"version"`
	PublicKey []byte `json:"public_key"`
}

// InventoryRequest is the gRPC form of backend.Enclave.Inventory.
type InventoryRequest struct {
	Version string `json:"version"`
	Nonce   []byte `json:"nonce"`
}

// KMS exposes only the recipient-attested operations required for envelope
// encryption. Implementations must never return plaintext data keys.
type KMS interface {
	GenerateDataKey(ctx context.Context, keyID string, recipient []byte) (
		kmsCiphertext, ciphertextForRecipient []byte, err error,
	)
	Decrypt(ctx context.Context, keyID string, kmsCiphertext, recipient []byte) (
		ciphertextForRecipient []byte, err error,
	)
}

// KMSFactory creates an enclave-side KMS client. The client sends TLS through
// the host byte proxy, but constructs and signs each KMS request in-enclave.
type KMSFactory func(region string, credentials Credentials) (KMS, error)

// Recipient creates NSM evidence for AWS KMS and decrypts the resulting
// CiphertextForRecipient inside the enclave. Attest binds arbitrary user data
// into an NSM document for the signer-side inventory verifier.
type Recipient interface {
	KMSAttestation() ([]byte, error)
	DecryptKMSRecipient([]byte) ([]byte, error)
	Attest(userData []byte) ([]byte, error)
}
