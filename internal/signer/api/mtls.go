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

package api

import (
	"crypto/x509"
	"errors"
	"net/http"
	"os"
)

// LoadClientCAPool reads a PEM bundle of CA certificate(s) used to verify TLS
// client certificates (mTLS). It fails if the file is unreadable or contains no
// parsable certificate so a misconfiguration is caught at boot.
func LoadClientCAPool(pemPath string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(pemPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("no certificates found in client CA PEM")
	}
	return pool, nil
}

// mtlsAuthenticator derives the caller identity from a verified TLS client
// certificate. The certificate chain is already verified by the TLS stack
// (crypto/tls ClientCAs + ClientAuth RequireAndVerifyClientCert or
// VerifyClientCertIfGiven), so a non-empty r.TLS.PeerCertificates is trusted:
// this Authenticator only maps the verified leaf to a caller subject.
//
// When RequireAndVerifyClientCert is configured, every connection carries a
// verified cert, so mTLS placed first in the chain always wins over JWT /
// request-signing — a transport-level identity that a captured bearer token
// cannot override. When only VerifyClientCertIfGiven is configured, a
// connection without a client cert falls through to the next scheme.
type mtlsAuthenticator struct{}

// NewMTLSAuthenticator returns an Authenticator that maps a verified TLS client
// certificate to a caller.
func NewMTLSAuthenticator() Authenticator { return mtlsAuthenticator{} }

func (mtlsAuthenticator) Authenticate(r *http.Request) (string, bool, error) {
	if r == nil {
		return "", true, errNilRequest
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", false, nil
	}
	caller := callerFromCert(r.TLS.PeerCertificates[0])
	if caller == "" {
		return "", true, errNoCertIdentity
	}
	return caller, true, nil
}

// callerFromCert derives the caller subject from a verified client certificate.
// Precedence (first non-empty wins): the first URI SAN, else the first DNS SAN,
// else the Subject CommonName. Operators set signer.callers[].subject to the
// matching value to scope keys per client identity.
func callerFromCert(c *x509.Certificate) string {
	if len(c.URIs) > 0 {
		return c.URIs[0].String()
	}
	if len(c.DNSNames) > 0 {
		return c.DNSNames[0]
	}
	return c.Subject.CommonName
}
