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
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

func tlsTestCert(
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
	return cert, key, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestNoEvidenceAttestationRoundTrip(t *testing.T) {
	t.Parallel()
	a, cold, spec := newHeaderAgent(t)
	ca, caKey, _ := tlsTestCert(t, nil, nil, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "test ca"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	})
	serverLeaf, _, serverCert := tlsTestCert(t, ca, caKey, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "server"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	_, _, clientCert := tlsTestCert(t, ca, caKey, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "client"},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- a.ServeAttestedService(ctx, ln, AttestedServiceConfig{Provider: NoEvidenceProvider})
	}()

	// The client pins the server certificate public key, not the CA.
	pinned := sha256.Sum256(serverLeaf.RawSubjectPublicKeyInfo)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", ln.Addr().String(), &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, //nolint:gosec // pin verified below
		Certificates:       []tls.Certificate{clientCert},
		VerifyConnection: func(cs tls.ConnectionState) error {
			got := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if got != pinned {
				return errors.New("server key does not match pin")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	var hello Hello
	if err := readFrame(conn, &hello); err != nil {
		t.Fatalf("read hello: %v", err)
	}
	req, err := NewAttestationRequest()
	if err != nil {
		t.Fatalf("NewAttestationRequest: %v", err)
	}
	if err := writeFrame(conn, req); err != nil {
		t.Fatalf("write challenge: %v", err)
	}
	var resp AttestationResponse
	if err := readFrame(conn, &resp); err != nil {
		t.Fatalf("read attestation: %v", err)
	}
	if resp.Error != "" || resp.Provider != NoEvidenceProvider {
		t.Fatalf("response = error %q provider %q", resp.Error, resp.Provider)
	}
	if len(resp.Attestation) != 0 {
		t.Fatalf("none response carries %d bytes of evidence", len(resp.Attestation))
	}
	if err := VerifyAttestation(t.Context(), req, resp, NoEvidenceProvider, cold.pub, resp.OpCert, nil); err != nil {
		t.Fatalf("VerifyAttestation: %v", err)
	}

	msg := spec.encode(t)
	if err := writeFrame(conn, SignRequest{Type: "sign_request", Period: 5, Message: msg}); err != nil {
		t.Fatalf("write sign request: %v", err)
	}
	var signed SignResponse
	if err := readFrame(conn, &signed); err != nil {
		t.Fatalf("read sign response: %v", err)
	}
	if signed.Error != "" || len(signed.Signature) == 0 {
		t.Fatalf("signing refused: %q", signed.Error)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ServeAttestedService did not stop")
	}
}

func TestServeAttestedServiceNilAttesterOnlyForNone(t *testing.T) {
	t.Parallel()
	a, _, _ := newHeaderAgent(t)
	for _, provider := range []string{"nitro", "confidential-space", "other", ""} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
		err = a.ServeAttestedService(ctx, ln, AttestedServiceConfig{Provider: provider})
		cancel()
		_ = ln.Close()
		if err == nil {
			t.Fatalf("provider %q with a nil attester was served", provider)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// A refused configuration returns at once; a served one blocks until the
	// context ends, which the assertion below reports as the defect.
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	if err := a.ServeAttestedService(ctx, ln, AttestedServiceConfig{
		Provider: NoEvidenceProvider,
		Attester: bindingAttester{},
	}); err == nil {
		t.Fatal("none with an attester was served")
	}
}

func TestVerifyAttestationEmptyEvidenceOnlyForNone(t *testing.T) {
	t.Parallel()
	a, cold, _ := newHeaderAgent(t)
	respFor := func(provider string, att Attester) (AttestationRequest, AttestationResponse) {
		server, client := tcpConnPair(t)
		go func() {
			a.serveAttestedConn(t.Context(), server, AttestedServiceConfig{Provider: provider, Attester: att})
		}()
		_ = client.SetDeadline(time.Now().Add(5 * time.Second))
		var hello Hello
		if err := readFrame(client, &hello); err != nil {
			t.Fatalf("read hello: %v", err)
		}
		req, _ := NewAttestationRequest()
		if err := writeFrame(client, req); err != nil {
			t.Fatalf("write challenge: %v", err)
		}
		var resp AttestationResponse
		if err := readFrame(client, &resp); err != nil {
			t.Fatalf("read attestation: %v", err)
		}
		return req, resp
	}

	req, resp := respFor(NoEvidenceProvider, nil)
	if err := VerifyAttestation(t.Context(), req, resp, NoEvidenceProvider, cold.pub, resp.OpCert, nil); err != nil {
		t.Fatalf("none with empty evidence refused: %v", err)
	}
	withEvidence := resp
	withEvidence.Attestation = []byte("x")
	if err := VerifyAttestation(t.Context(), req, withEvidence, NoEvidenceProvider, cold.pub, resp.OpCert, nil); err == nil {
		t.Fatal("none with non-empty evidence accepted")
	}
	downgraded := resp
	downgraded.Provider = "nitro"
	if err := VerifyAttestation(t.Context(), req, downgraded, "nitro", cold.pub, resp.OpCert, bindingVerifier{}); err == nil {
		t.Fatal("nitro with empty evidence accepted")
	}
	if err := VerifyAttestation(t.Context(), req, resp, "nitro", cold.pub, resp.OpCert, bindingVerifier{}); err == nil {
		t.Fatal("none response accepted for an expected nitro provider")
	}
	if err := VerifyAttestation(t.Context(), req, resp, "nitro", cold.pub, resp.OpCert, nil); err == nil {
		t.Fatal("nil verifier accepted for nitro")
	}
}

func TestSPKIFingerprintMatchesOpenSSLComputation(t *testing.T) {
	t.Parallel()
	cert, key, _ := tlsTestCert(t, nil, nil, &x509.Certificate{Subject: pkix.Name{CommonName: "fp"}})
	// openssl x509 -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	if got, want := SPKIFingerprint(cert), hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("SPKIFingerprint = %q, want %q", got, want)
	}
}
