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
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	secretmanagerclient "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/option"
)

// maxTLSBundleSize is Secret Manager's payload limit.
const maxTLSBundleSize = 64 << 10

// tlsSecretClient is the part of Secret Manager the TLS bundle read uses.
type tlsSecretClient interface {
	AccessSecretVersion(
		context.Context,
		*secretmanagerpb.AccessSecretVersionRequest,
	) (*secretmanagerpb.AccessSecretVersionResponse, error)
	Close() error
}

// LoadTLSCertificate reads the workload's HTTPS certificate chain and private
// key from the newest enabled version of an existing Secret Manager secret,
// through the measured workload's external-account credentials. The secret
// holds one PEM bundle. Any read, shape or key-match failure is an error: the
// workload must not serve with a certificate it could not verify.
//
// A stale read is harmless here, so the latest alias is used; the state store,
// whose counters must not roll back, reads by version number instead.
func LoadTLSCertificate(
	ctx context.Context,
	secret, credentialFile string,
) (tls.Certificate, error) {
	if err := validateTLSSecret(secret); err != nil {
		return tls.Certificate{}, err
	}
	if err := validateWIFCredentials(credentialFile); err != nil {
		return tls.Certificate{}, err
	}
	client, err := secretmanagerclient.NewClient(
		ctx,
		option.WithAuthCredentialsFile(option.ExternalAccount, credentialFile),
	)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"create Secret Manager client: %w", err,
		)
	}
	return loadTLSCertificate(ctx, cloudSecretStateClient{Client: client}, secret)
}

func validateTLSSecret(secret string) error {
	if !stateSecretPattern.MatchString(secret) {
		return errors.New(
			"TLS secret must be projects/<project>/secrets/<secret>",
		)
	}
	return nil
}

func loadTLSCertificate(
	ctx context.Context,
	client tlsSecretClient,
	secret string,
) (tls.Certificate, error) {
	defer client.Close()
	if err := validateTLSSecret(secret); err != nil {
		return tls.Certificate{}, err
	}
	rpcCtx, cancel := context.WithTimeout(ctx, secretRPCTimeout)
	defer cancel()
	resp, err := client.AccessSecretVersion(
		rpcCtx,
		&secretmanagerpb.AccessSecretVersionRequest{
			Name: secret + "/versions/latest",
		},
	)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read TLS secret: %w", err)
	}
	payload := resp.GetPayload()
	data := payload.GetData()
	defer wipe(data)
	if len(data) == 0 {
		return tls.Certificate{}, errors.New("TLS secret is empty")
	}
	if len(data) > maxTLSBundleSize {
		return tls.Certificate{}, errors.New("TLS secret exceeds size limit")
	}
	// Presence matters: an absent checksum is not a zero one.
	if payload.DataCrc32C != nil && //nolint:protogetter
		*payload.DataCrc32C != checksumValue(data) { //nolint:protogetter
		return tls.Certificate{}, errors.New("TLS secret failed integrity check")
	}
	if parent, _, ok := strings.Cut(resp.GetName(), "/versions/"); !ok ||
		!stateSecretPattern.MatchString(parent) ||
		secretID(parent) != secretID(secret) {
		return tls.Certificate{}, errors.New(
			"TLS secret version has an unexpected name",
		)
	}
	return parseTLSBundle(data)
}

// parseTLSBundle accepts only certificate blocks and exactly one private key,
// in any order. The tls package then checks the key against the leaf, and its
// errors name no key material.
func parseTLSBundle(bundle []byte) (tls.Certificate, error) {
	var certs, keys int
	rest := bundle
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		wipe(block.Bytes)
		switch {
		case block.Type == "CERTIFICATE":
			certs++
		case strings.HasSuffix(block.Type, "PRIVATE KEY"):
			keys++
		default:
			return tls.Certificate{}, fmt.Errorf(
				"TLS secret holds an unexpected %q PEM block", block.Type,
			)
		}
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return tls.Certificate{}, errors.New("TLS secret is not valid PEM")
	}
	switch {
	case certs == 0 && keys == 0:
		return tls.Certificate{}, errors.New("TLS secret is not valid PEM")
	case keys == 0:
		return tls.Certificate{}, errors.New("TLS secret holds no private key")
	case certs == 0:
		return tls.Certificate{}, errors.New("TLS secret holds no certificate")
	case keys > 1:
		return tls.Certificate{}, errors.New(
			"TLS secret holds more than one private key",
		)
	}
	certificate, err := tls.X509KeyPair(bundle, bundle)
	if err != nil {
		if strings.Contains(err.Error(), "does not match") {
			return tls.Certificate{}, errors.New(
				"TLS secret private key does not match its certificate",
			)
		}
		return tls.Certificate{}, fmt.Errorf(
			"TLS secret certificate and key are unusable: %w", err,
		)
	}
	return certificate, nil
}
