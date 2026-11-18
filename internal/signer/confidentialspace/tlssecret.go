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
	"strconv"
	"strings"

	secretmanagerclient "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/option"
)

// maxTLSBundleSize is Secret Manager's payload limit.
const maxTLSBundleSize = 64 << 10

var pemBegin = []byte("-----BEGIN")

// tlsSecretClient is the part of Secret Manager the TLS bundle read uses.
type tlsSecretClient interface {
	AccessSecretVersion(
		context.Context,
		*secretmanagerpb.AccessSecretVersionRequest,
	) (*secretmanagerpb.AccessSecretVersionResponse, error)
	Close() error
}

// LoadTLSCertificate reads the workload's HTTPS certificate chain and private
// key from the most recently created version of an existing Secret Manager
// secret,
// through the measured workload's external-account credentials. The secret
// holds one PEM bundle. Any read, shape or key-match failure is an error: the
// workload must not serve with a certificate it could not verify.
//
// A stale read is harmless here, so the latest alias is used; the state store,
// whose counters must not roll back, reads by version number instead. The
// alias does not skip a disabled version: a disabled newest version stops
// startup.
func LoadTLSCertificate(
	ctx context.Context,
	secret, credentialFile string,
) (tls.Certificate, error) {
	if err := ValidateTLSSecret(secret); err != nil {
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

// ValidateTLSSecret checks the form of a TLS secret name without reading it.
func ValidateTLSSecret(secret string) error {
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
	if err := ValidateTLSSecret(secret); err != nil {
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
	// As in the state store, the project is not compared: Secret Manager names
	// it by number in the names it returns.
	parent, number, ok := strings.Cut(resp.GetName(), "/versions/")
	if n, err := strconv.ParseUint(number, 10, 64); !ok || err != nil ||
		n == 0 || !stateSecretPattern.MatchString(parent) ||
		secretID(parent) != secretID(secret) {
		return tls.Certificate{}, errors.New(
			"TLS secret version has an unexpected name",
		)
	}
	return parseTLSBundle(data)
}

// parseTLSBundle accepts only certificate blocks and exactly one private key,
// in any order, separated by nothing but white space. pem.Decode skips text
// before a block and a malformed block, so each block must start where the
// previous one ended and be the only one in the bytes it consumed. The tls
// package then checks the key against the leaf, and its errors name no key
// material. It is given the blocks alone, since pem.Decode finds a block only
// at the start of its input or of a line, and misses one indented by white
// space that this loop accepts.
func parseTLSBundle(bundle []byte) (tls.Certificate, error) {
	var certs, keys int
	// Only the last block can lack a closing newline, so blocks fits in the
	// capacity and append never leaves an unwiped copy behind.
	blocks := make([]byte, 0, len(bundle)+1)
	defer func() { wipe(blocks) }()
	rest := bundle
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 {
			break
		}
		block, next := pem.Decode(rest)
		if block == nil || !bytes.HasPrefix(rest, pemBegin) ||
			bytes.Count(rest[:len(rest)-len(next)], pemBegin) != 1 {
			if block != nil {
				wipe(block.Bytes)
			}
			return tls.Certificate{}, errors.New("TLS secret is not valid PEM")
		}
		blocks = append(blocks, rest[:len(rest)-len(next)]...)
		if blocks[len(blocks)-1] != '\n' {
			blocks = append(blocks, '\n')
		}
		rest = next
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
	certificate, err := tls.X509KeyPair(blocks, blocks)
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
