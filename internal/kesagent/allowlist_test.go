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

package kesagent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

type tlsFixture struct {
	pool       *x509.CertPool
	ca         *x509.Certificate
	caKey      *ecdsa.PrivateKey
	serverCert tls.Certificate
}

func newCert(
	t *testing.T,
	parent *x509.Certificate,
	parentKey *ecdsa.PrivateKey,
	tmpl *x509.Certificate,
) (*x509.Certificate, *ecdsa.PrivateKey, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert, key, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}
}

func newTLSFixture(t *testing.T) *tlsFixture {
	t.Helper()
	ca, caKey, _ := newCert(t, nil, nil, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "test ca"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	})
	_, _, server := newCert(t, ca, caKey, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "server"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &tlsFixture{pool: pool, ca: ca, caKey: caKey, serverCert: server}
}

func (f *tlsFixture) client(t *testing.T, name string) (tls.Certificate, [sha256.Size]byte) {
	t.Helper()
	cert, _, pair := newCert(t, f.ca, f.caKey, &x509.Certificate{
		Subject:     pkix.Name{CommonName: name},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return pair, sha256.Sum256(cert.RawSubjectPublicKeyInfo)
}

func (f *tlsFixture) listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{f.serverCert},
		ClientCAs:    f.pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func (f *tlsFixture) dial(t *testing.T, addr string, client tls.Certificate) *tls.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      f.pool,
		Certificates: []tls.Certificate{client},
	})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestAuthenticateRemotePeerClientAllowlist(t *testing.T) {
	t.Parallel()
	f := newTLSFixture(t)
	listedCert, listedFP := f.client(t, "listed")
	otherCert, otherFP := f.client(t, "unlisted")

	cases := []struct {
		name    string
		client  tls.Certificate
		allowed [][sha256.Size]byte
		wantErr bool
	}{
		{"listed client accepted", listedCert, [][sha256.Size]byte{otherFP, listedFP}, false},
		{"unlisted client with valid chain refused", otherCert, [][sha256.Size]byte{listedFP}, true},
		{"unset allowlist accepts any verified client", otherCert, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ln := f.listen(t)
			go func() {
				c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
					MinVersion:   tls.VersionTLS13,
					RootCAs:      f.pool,
					Certificates: []tls.Certificate{tc.client},
				})
				if err == nil {
					// Hold the connection until the server side is done.
					_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
					_, _ = c.Read(make([]byte, 1))
					_ = c.Close()
				}
			}()
			conn, err := ln.Accept()
			if err != nil {
				t.Fatalf("accept: %v", err)
			}
			defer conn.Close()
			err = authenticateRemotePeer(context.Background(), conn, tc.allowed)
			if tc.wantErr {
				if !errors.Is(err, ErrUnauthenticatedPeer) {
					t.Fatalf("err = %v, want ErrUnauthenticatedPeer", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("authenticateRemotePeer: %v", err)
			}
		})
	}
}

func TestAttestedServiceClientAllowlistGatesHello(t *testing.T) {
	t.Parallel()
	f := newTLSFixture(t)
	listedCert, listedFP := f.client(t, "listed")
	otherCert, _ := f.client(t, "unlisted")
	a, _, _ := newHeaderAgent(t)
	ln := f.listen(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- a.ServeAttestedService(ctx, ln, AttestedServiceConfig{
			Provider:          "nitro",
			Attester:          bindingAttester{},
			AllowedClientSPKI: [][sha256.Size]byte{listedFP},
		})
	}()

	listed := f.dial(t, ln.Addr().String(), listedCert)
	_ = listed.SetReadDeadline(time.Now().Add(5 * time.Second))
	var hello Hello
	if err := readFrame(listed, &hello); err != nil {
		t.Fatalf("listed client got no hello: %v", err)
	}

	unlisted := f.dial(t, ln.Addr().String(), otherCert)
	_ = unlisted.SetReadDeadline(time.Now().Add(5 * time.Second))
	var refused Hello
	err := readFrame(unlisted, &refused)
	if err == nil {
		t.Fatal("unlisted client received a hello")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("unlisted client was not closed: %v", err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeAttestedService: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeAttestedService did not stop")
	}
}
