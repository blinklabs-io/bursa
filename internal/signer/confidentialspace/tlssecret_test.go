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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const tlsTestServerName = "workload.test"

type tlsTestIdentity struct {
	certPEM []byte
	keyPEM  []byte
	cert    *x509.Certificate
}

func newTLSTestIdentity(t *testing.T, serial int64) tlsTestIdentity {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: tlsTestServerName},
		DNSNames:     []string{tlsTestServerName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(
		rand.Reader, template, template, &key.PublicKey, key,
	)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return tlsTestIdentity{
		certPEM: pem.EncodeToMemory(
			&pem.Block{Type: "CERTIFICATE", Bytes: der},
		),
		keyPEM: pem.EncodeToMemory(
			&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER},
		),
		cert: cert,
	}
}

func (i tlsTestIdentity) bundle() []byte {
	return append(append([]byte{}, i.certPEM...), i.keyPEM...)
}

// servedCertificate serves one HTTPS request with certificate and returns the
// certificate the client verified against the identity's own root.
func servedCertificate(
	t *testing.T, certificate tls.Certificate, id tlsTestIdentity,
) *x509.Certificate {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "ok")
		},
	))
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
	}
	srv.StartTLS()
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(id.cert)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    roots,
			ServerName: tlsTestServerName,
		},
	}}
	defer client.CloseIdleConnections()
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("TLS request with the bundle certificate: %v", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	return resp.TLS.PeerCertificates[0]
}

func TestLoadTLSCertificateServesBundle(t *testing.T) {
	t.Parallel()
	id := newTLSTestIdentity(t, 1)
	keyFirst := append(append([]byte{}, id.keyPEM...), id.certPEM...)
	for name, bundle := range map[string][]byte{
		"certificate then key": id.bundle(),
		"key then certificate": keyFirst,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := &fakeSecretClient{}
			c.seed(bundle)
			certificate, err := loadTLSCertificate(
				t.Context(), c, testStateSecret,
			)
			if err != nil {
				t.Fatal(err)
			}
			if got := servedCertificate(t, certificate, id); !got.Equal(id.cert) {
				t.Fatal("server presented a certificate other than the bundle's")
			}
		})
	}
}

func TestLoadTLSCertificateReadsNewestEnabledVersion(t *testing.T) {
	t.Parallel()
	older := newTLSTestIdentity(t, 1)
	newer := newTLSTestIdentity(t, 2)
	c := &fakeSecretClient{}
	c.seed(older.bundle())
	c.seed(newer.bundle())
	certificate, err := loadTLSCertificate(t.Context(), c, testStateSecret)
	if err != nil {
		t.Fatal(err)
	}
	if got := servedCertificate(t, certificate, newer); !got.Equal(newer.cert) {
		t.Fatal("did not serve the newest version's certificate")
	}
}

func TestLoadTLSCertificateRefusesBadBundles(t *testing.T) {
	t.Parallel()
	id := newTLSTestIdentity(t, 1)
	other := newTLSTestIdentity(t, 2)
	denied := errors.New("permission denied")
	tests := []struct {
		name    string
		secret  string
		setup   func(*fakeSecretClient)
		wantErr string
		wantIs  error
	}{
		{
			name:    "empty version",
			secret:  testStateSecret,
			setup:   func(c *fakeSecretClient) { c.seed(nil) },
			wantErr: "TLS secret is empty",
		},
		{
			name:    "no versions",
			secret:  testStateSecret,
			setup:   func(*fakeSecretClient) {},
			wantErr: "read TLS secret",
		},
		{
			name:    "missing secret",
			secret:  testStateSecret,
			setup:   func(c *fakeSecretClient) { c.missing = true },
			wantErr: "read TLS secret",
		},
		{
			name:   "access error",
			secret: testStateSecret,
			setup: func(c *fakeSecretClient) {
				c.seed(id.bundle())
				c.accessErr = denied
			},
			wantErr: "read TLS secret",
			wantIs:  denied,
		},
		{
			name:    "not PEM",
			secret:  testStateSecret,
			setup:   func(c *fakeSecretClient) { c.seed([]byte("not a pem")) },
			wantErr: "not valid PEM",
		},
		{
			name:    "no key",
			secret:  testStateSecret,
			setup:   func(c *fakeSecretClient) { c.seed(id.certPEM) },
			wantErr: "no private key",
		},
		{
			name:    "no certificate",
			secret:  testStateSecret,
			setup:   func(c *fakeSecretClient) { c.seed(id.keyPEM) },
			wantErr: "no certificate",
		},
		{
			name:   "key of another certificate",
			secret: testStateSecret,
			setup: func(c *fakeSecretClient) {
				c.seed(append(
					append([]byte{}, id.certPEM...), other.keyPEM...,
				))
			},
			wantErr: "does not match",
		},
		{
			name:   "two keys",
			secret: testStateSecret,
			setup: func(c *fakeSecretClient) {
				c.seed(append(id.bundle(), other.keyPEM...))
			},
			wantErr: "more than one private key",
		},
		{
			name:   "trailing data",
			secret: testStateSecret,
			setup: func(c *fakeSecretClient) {
				c.seed(append(id.bundle(), []byte("junk")...))
			},
			wantErr: "not valid PEM",
		},
		{
			name:    "bad secret name",
			secret:  "pool-state",
			setup:   func(c *fakeSecretClient) { c.seed(id.bundle()) },
			wantErr: "must be projects/<project>/secrets/<secret>",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := &fakeSecretClient{}
			tt.setup(c)
			certificate, err := loadTLSCertificate(t.Context(), c, tt.secret)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %v, want %q", err, tt.wantErr)
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Fatalf("error %v does not wrap %v", err, tt.wantIs)
			}
			if len(certificate.Certificate) != 0 || certificate.PrivateKey != nil {
				t.Fatal("a refused bundle returned a certificate")
			}
			for _, key := range [][]byte{id.keyPEM, other.keyPEM} {
				body := strings.Split(string(key), "\n")[1]
				if strings.Contains(err.Error(), body) {
					t.Fatal("error discloses key material")
				}
			}
		})
	}
}
