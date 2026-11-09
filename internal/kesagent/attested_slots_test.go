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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// attestedTLSConfigs returns mTLS server and client configurations that trust
// one throwaway CA, matching the attested listener's TLS policy.
func attestedTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	leaf := func(serial int64, usage x509.ExtKeyUsage) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: "leaf"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	server := &tls.Config{
		Certificates: []tls.Certificate{leaf(2, x509.ExtKeyUsageServerAuth)},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	client := &tls.Config{
		Certificates: []tls.Certificate{leaf(3, x509.ExtKeyUsageClientAuth)},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}
	return server, client
}

// acceptCounter signals once its listener has accepted want connections, so a
// test can act only after the server has taken every connection it dialed.
type acceptCounter struct {
	net.Listener
	want  int64
	n     atomic.Int64
	ready chan struct{}
}

func (l *acceptCounter) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil && l.n.Add(1) == l.want {
		close(l.ready)
	}
	return c, err
}

// TestAttestedServiceServesPeerDuringHandshakeFlood covers a remote client
// that opens TCP connections and never completes the TLS handshake. Those
// connections must not lock out an authenticated block producer, even one
// dialing from the same address as the flood.
func TestAttestedServiceServesPeerDuringHandshakeFlood(t *testing.T) {
	a, _, _ := newHeaderAgent(t)
	serverCfg, clientCfg := attestedTLSConfigs(t)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := raw.Addr().String()
	counted := &acceptCounter{
		Listener: raw,
		want:     maxTrackedConns,
		ready:    make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- a.ServeAttestedService(
			ctx,
			tls.NewListener(counted, serverCfg),
			AttestedServiceConfig{Provider: "nitro", Attester: bindingAttester{}},
		)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("ServeAttestedService did not stop")
		}
	})

	flood := net.Dialer{Timeout: 2 * time.Second}
	for range maxTrackedConns {
		c, err := flood.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("flood dial: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() })
	}
	select {
	case <-counted.ready:
	case <-time.After(5 * time.Second):
		t.Fatalf("server accepted %d of %d flood connections", counted.n.Load(), maxTrackedConns)
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 3 * time.Second},
		"tcp",
		addr,
		clientCfg,
	)
	if err != nil {
		t.Fatalf("authenticated peer refused during handshake flood: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	var hello Hello
	if err := readFrame(conn, &hello); err != nil {
		t.Fatalf("authenticated peer got no hello during handshake flood: %v", err)
	}
	if hello.Protocol != AttestedProtocolID {
		t.Fatalf("hello = %+v", hello)
	}
}

// sourceConn is a pipe end that reports a chosen remote address and records
// whether it was closed.
type sourceConn struct {
	net.Conn
	addr   net.Addr
	closed atomic.Bool
}

func (c *sourceConn) RemoteAddr() net.Addr { return c.addr }

func (c *sourceConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func newSourceConn(t *testing.T, addr net.Addr) *sourceConn {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return &sourceConn{Conn: a, addr: addr}
}

func TestHandshakeSetEvictsOldest(t *testing.T) {
	tcp := func(ip string) net.Addr {
		return &net.TCPAddr{IP: net.ParseIP(ip), Port: 1}
	}
	s := newHandshakeSet()
	sameHost := make([]*sourceConn, 0, maxPendingHandshakesPerHost)
	for range maxPendingHandshakesPerHost {
		c := newSourceConn(t, tcp("192.0.2.1"))
		if !s.add(c) {
			t.Fatal("add refused before closeAll")
		}
		sameHost = append(sameHost, c)
	}
	other := newSourceConn(t, tcp("198.51.100.1"))
	s.add(other)
	if sameHost[0].closed.Load() || other.closed.Load() {
		t.Fatal("a connection was evicted below its source budget")
	}
	s.add(newSourceConn(t, tcp("192.0.2.1")))
	if !sameHost[0].closed.Load() {
		t.Fatal("a source over its budget did not evict its oldest handshake")
	}
	if other.closed.Load() || sameHost[1].closed.Load() {
		t.Fatal("eviction took a connection other than the source's oldest")
	}
	s.remove(sameHost[0])
	s.mu.Lock()
	if got := s.perHost["192.0.2.1"]; got != maxPendingHandshakesPerHost {
		t.Errorf("per-source count after evict and remove = %d", got)
	}
	s.mu.Unlock()

	v6 := make([]*sourceConn, 0, maxPendingHandshakesPerHost)
	for i := 1; i <= maxPendingHandshakesPerHost; i++ {
		c := newSourceConn(t, tcp(fmt.Sprintf("2001:db8::%d", i)))
		s.add(c)
		v6 = append(v6, c)
	}
	s.add(newSourceConn(t, tcp("2001:db8::ffff")))
	if !v6[0].closed.Load() {
		t.Fatal("addresses in one IPv6 /64 escaped the per-source budget")
	}

	s = newHandshakeSet()
	global := make([]*sourceConn, 0, maxPendingHandshakes)
	for range maxPendingHandshakes {
		c := newSourceConn(t, nil)
		s.add(c)
		global = append(global, c)
	}
	s.add(newSourceConn(t, tcp("192.0.2.9")))
	if !global[0].closed.Load() || global[1].closed.Load() {
		t.Fatal("a full global budget did not evict exactly the oldest handshake")
	}
	s.mu.Lock()
	if len(s.conns) != maxPendingHandshakes {
		t.Errorf("tracked %d handshakes, want %d", len(s.conns), maxPendingHandshakes)
	}
	s.mu.Unlock()

	s.closeAll()
	if !global[1].closed.Load() {
		t.Fatal("closeAll left a pending handshake open")
	}
	if s.add(newSourceConn(t, tcp("192.0.2.9"))) {
		t.Fatal("add accepted a connection after closeAll")
	}
}
