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
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"
)

// certKey is a generated certificate plus its private key and PEM encoding.
type certKey struct {
	cert    *x509.Certificate
	der     []byte
	key     *ecdsa.PrivateKey
	certPEM []byte
	keyPEM  []byte
}

// makeCA generates a self-signed CA certificate.
func makeCA(t *testing.T) certKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return certKey{cert: cert, der: der, key: key, certPEM: pemBlock("CERTIFICATE", der)}
}

// makeLeaf signs a leaf certificate with the given CA. mutate customizes the
// template (SANs, CN, key usage).
func makeLeaf(t *testing.T, ca certKey, mutate func(*x509.Certificate)) certKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	mutate(tmpl)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return certKey{
		cert:    cert,
		der:     der,
		key:     key,
		certPEM: pemBlock("CERTIFICATE", der),
		keyPEM:  pemBlock("EC PRIVATE KEY", keyDER),
	}
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

// TestCallerFromCert covers the URI > DNS > CN precedence.
func TestCallerFromCert(t *testing.T) {
	u, _ := url.Parse("spiffe://example.org/client")
	cases := []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{"uri-san", &x509.Certificate{URIs: []*url.URL{u}, DNSNames: []string{"host.example"}, Subject: pkix.Name{CommonName: "cn"}}, "spiffe://example.org/client"},
		{"dns-san", &x509.Certificate{DNSNames: []string{"host.example"}, Subject: pkix.Name{CommonName: "cn"}}, "host.example"},
		{"cn", &x509.Certificate{Subject: pkix.Name{CommonName: "cn"}}, "cn"},
		{"none", &x509.Certificate{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := callerFromCert(tc.cert); got != tc.want {
				t.Fatalf("callerFromCert = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestMTLSAuthenticator_NoCert falls through when no client cert is present.
func TestMTLSAuthenticator_NoCert(t *testing.T) {
	a := NewMTLSAuthenticator()
	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil) // r.TLS == nil
	caller, ok, err := a.Authenticate(req)
	if ok || err != nil || caller != "" {
		t.Fatalf("expected fall-through (ok=false), got caller=%q ok=%v err=%v", caller, ok, err)
	}
}

// TestMTLSAuthenticator_NoIdentity rejects a verified cert with no usable identity.
func TestMTLSAuthenticator_NoIdentity(t *testing.T) {
	a := NewMTLSAuthenticator()
	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{}}}}
	_, ok, err := a.Authenticate(req)
	if !ok || err == nil {
		t.Fatalf("expected reject (ok=true,err!=nil), got ok=%v err=%v", ok, err)
	}
}

func TestLoadClientCAPool(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	path := dir + "/ca.pem"
	if err := writeFile(t, path, ca.certPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadClientCAPool(path); err != nil {
		t.Fatalf("LoadClientCAPool: %v", err)
	}
	// Non-PEM content fails.
	bad := dir + "/bad.pem"
	if err := writeFile(t, bad, []byte("not a pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadClientCAPool(bad); err == nil {
		t.Fatal("expected error for non-PEM client CA file")
	}
	if _, err := LoadClientCAPool(dir + "/missing.pem"); err == nil {
		t.Fatal("expected error for missing client CA file")
	}
}

// TestMTLSHandshake exercises the real TLS handshake path end-to-end: a client
// cert signed by the configured CA is accepted and its CN becomes the caller;
// no cert / untrusted cert under RequireAndVerifyClientCert is rejected at the
// handshake.
func TestMTLSHandshake(t *testing.T) {
	ca := makeCA(t)
	server := makeLeaf(t, ca, func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "signer"}
		c.DNSNames = []string{"127.0.0.1"}
		c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	})
	client := makeLeaf(t, ca, func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "client-alice"}
	})

	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	serverTLSCert := tls.Certificate{Certificate: [][]byte{server.der}, PrivateKey: server.key}

	// Handler records the caller resolved by the mTLS authenticator chain. The
	// handler runs on a server goroutine and the test reads the result on its
	// own goroutine, so hand it off through a channel rather than a shared
	// variable (the TCP round-trip orders the two in wall-clock time, but that
	// ordering is invisible to the Go memory model / race detector).
	callers := make(chan string, 1)
	h := AuthMiddleware([]Authenticator{NewMTLSAuthenticator()}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callers <- CallerFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	srv := newTLSServer(t, serverTLSCert, pool, tls.RequireAndVerifyClientCert, h)
	defer srv.Close()

	// Trusted client cert -> 200, caller = CN.
	t.Run("trusted-cert", func(t *testing.T) {
		clientTLSCert := tls.Certificate{Certificate: [][]byte{client.der}, PrivateKey: client.key}
		resp := doTLSGet(t, srv.addr, pool, &clientTLSCert)
		if resp != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp)
		}
		select {
		case got := <-callers:
			if got != "client-alice" {
				t.Fatalf("expected caller client-alice, got %q", got)
			}
		case <-time.After(time.Second):
			t.Fatal("handler did not record a caller")
		}
	})

	// No client cert under RequireAndVerifyClientCert -> handshake failure.
	t.Run("no-cert", func(t *testing.T) {
		if _, err := tlsGetErr(t, srv.addr, pool, nil); err == nil {
			t.Fatal("expected handshake failure with no client cert")
		}
	})

	// Untrusted client cert (different CA) -> handshake failure.
	t.Run("untrusted-cert", func(t *testing.T) {
		otherCA := makeCA(t)
		rogue := makeLeaf(t, otherCA, func(c *x509.Certificate) { c.Subject = pkix.Name{CommonName: "rogue"} })
		rogueTLS := tls.Certificate{Certificate: [][]byte{rogue.der}, PrivateKey: rogue.key}
		if _, err := tlsGetErr(t, srv.addr, pool, &rogueTLS); err == nil {
			t.Fatal("expected handshake failure with untrusted client cert")
		}
	})
}

// tlsServer is a minimal TLS listener serving h.
type tlsServer struct {
	ln   net.Listener
	addr string
	srv  *http.Server
}

func (s *tlsServer) Close() { _ = s.srv.Close() }

func newTLSServer(t *testing.T, cert tls.Certificate, clientCAs *x509.CertPool, auth tls.ClientAuthType, h http.Handler) *tlsServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    clientCAs,
		ClientAuth:   auth,
	}
	// TLSConfig must be set before ServeTLS; the empty file args fall back to
	// TLSConfig.Certificates.
	srv := &http.Server{Handler: h, TLSConfig: cfg}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	return &tlsServer{ln: ln, addr: ln.Addr().String(), srv: srv}
}

func tlsGetErr(t *testing.T, addr string, roots *x509.CertPool, clientCert *tls.Certificate) (int, error) {
	t.Helper()
	cfg := &tls.Config{RootCAs: roots, ServerName: "127.0.0.1"}
	if clientCert != nil {
		cfg.Certificates = []tls.Certificate{*clientCert}
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: cfg},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get("https://" + addr + "/v1/keys")
	if err != nil {
		return 0, err
	}
	if resp == nil {
		return 0, errors.New("nil response")
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	return resp.StatusCode, nil
}

func doTLSGet(t *testing.T, addr string, roots *x509.CertPool, clientCert *tls.Certificate) int {
	t.Helper()
	code, err := tlsGetErr(t, addr, roots, clientCert)
	if err != nil {
		t.Fatalf("TLS GET: %v", err)
	}
	return code
}

func writeFile(t *testing.T, path string, data []byte) error {
	t.Helper()
	return os.WriteFile(path, data, 0o600)
}
