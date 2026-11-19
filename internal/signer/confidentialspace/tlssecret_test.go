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

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
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
	join := func(parts ...string) []byte {
		return []byte(strings.Join(parts, ""))
	}
	for name, bundle := range map[string][]byte{
		"certificate then key": id.bundle(),
		"key then certificate": keyFirst,
		"indented key": join(
			string(id.certPEM), " \t", string(id.keyPEM),
		),
		"indented certificate": join(
			string(id.keyPEM), "\t", string(id.certPEM),
		),
		"leading white space": join(" \r\n\t", string(id.bundle())),
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

func TestLoadTLSCertificateReadsNewestVersion(t *testing.T) {
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
			name:   "leading text",
			secret: testStateSecret,
			setup: func(c *fakeSecretClient) {
				c.seed(append([]byte("junk\n"), id.bundle()...))
			},
			wantErr: "not valid PEM",
		},
		{
			name:   "malformed block before a valid one",
			secret: testStateSecret,
			setup: func(c *fakeSecretClient) {
				c.seed(append([]byte(
					"-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----\n",
				), id.bundle()...))
			},
			wantErr: "not valid PEM",
		},
		{
			name:   "unexpected block type",
			secret: testStateSecret,
			setup: func(c *fakeSecretClient) {
				c.seed(append(id.bundle(), pem.EncodeToMemory(
					&pem.Block{Type: "X509 CRL", Bytes: []byte{1}},
				)...))
			},
			wantErr: "unexpected \"X509 CRL\" PEM block",
		},
		{
			name:   "oversized",
			secret: testStateSecret,
			setup: func(c *fakeSecretClient) {
				c.seed(append(
					id.bundle(),
					bytes.Repeat([]byte("\n"), maxTLSBundleSize)...,
				))
			},
			wantErr: "exceeds size limit",
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

// stubTLSSecretClient answers every read with one response.
type stubTLSSecretClient struct {
	resp *secretmanagerpb.AccessSecretVersionResponse
}

func (c stubTLSSecretClient) AccessSecretVersion(
	context.Context,
	*secretmanagerpb.AccessSecretVersionRequest,
) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	return c.resp, nil
}

func (stubTLSSecretClient) Close() error { return nil }

func TestLoadTLSCertificateRefusesBadResponses(t *testing.T) {
	t.Parallel()
	id := newTLSTestIdentity(t, 1)
	tests := []struct {
		name    string
		resp    func(*secretmanagerpb.AccessSecretVersionResponse)
		wantErr string
	}{
		{
			name: "checksum mismatch",
			resp: func(r *secretmanagerpb.AccessSecretVersionResponse) {
				bad := r.GetPayload().GetDataCrc32C() + 1
				r.Payload.DataCrc32C = &bad
			},
			wantErr: "failed integrity check",
		},
		{
			name: "another secret",
			resp: func(r *secretmanagerpb.AccessSecretVersionResponse) {
				r.Name = "projects/data/secrets/other/versions/1"
			},
			wantErr: "unexpected name",
		},
		{
			name: "no version",
			resp: func(r *secretmanagerpb.AccessSecretVersionResponse) {
				r.Name = testStateSecret
			},
			wantErr: "unexpected name",
		},
		{
			name: "alias version",
			resp: func(r *secretmanagerpb.AccessSecretVersionResponse) {
				r.Name = testStateSecret + "/versions/latest"
			},
			wantErr: "unexpected name",
		},
		{
			name: "empty version",
			resp: func(r *secretmanagerpb.AccessSecretVersionResponse) {
				r.Name = testStateSecret + "/versions/"
			},
			wantErr: "unexpected name",
		},
		{
			name: "version zero",
			resp: func(r *secretmanagerpb.AccessSecretVersionResponse) {
				r.Name = testStateSecret + "/versions/0"
			},
			wantErr: "unexpected name",
		},
		{
			name: "nested version",
			resp: func(r *secretmanagerpb.AccessSecretVersionResponse) {
				r.Name = testStateSecret + "/versions/1/x"
			},
			wantErr: "unexpected name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data := id.bundle()
			crc := checksumValue(data)
			resp := &secretmanagerpb.AccessSecretVersionResponse{
				Name: testStateSecret + "/versions/1",
				Payload: &secretmanagerpb.SecretPayload{
					Data:       data,
					DataCrc32C: &crc,
				},
			}
			tt.resp(resp)
			certificate, err := loadTLSCertificate(
				t.Context(), stubTLSSecretClient{resp: resp}, testStateSecret,
			)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %v, want %q", err, tt.wantErr)
			}
			if len(certificate.Certificate) != 0 || certificate.PrivateKey != nil {
				t.Fatal("a refused response returned a certificate")
			}
		})
	}
	// The control: the same response, unaltered, is accepted.
	data := id.bundle()
	crc := checksumValue(data)
	if _, err := loadTLSCertificate(t.Context(), stubTLSSecretClient{
		resp: &secretmanagerpb.AccessSecretVersionResponse{
			Name: "projects/123/secrets/pool-state/versions/7",
			Payload: &secretmanagerpb.SecretPayload{
				Data: data, DataCrc32C: &crc,
			},
		},
	}, testStateSecret); err != nil {
		t.Fatalf("a well-formed response was refused: %v", err)
	}
}
