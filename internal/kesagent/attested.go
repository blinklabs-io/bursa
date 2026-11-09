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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/kesagent/wire"
	"github.com/blinklabs-io/gouroboros/ledger"
)

const (
	// AttestedProtocolID is the protocol spoken by an attested KES workload.
	AttestedProtocolID   = wire.AttestedProtocolID
	attestationNonceSize = 32
	attesterMaxResponse  = 1 << 20
)

var (
	// ErrAttestation is returned when workload evidence cannot be produced or
	// verified. The connection is closed without admitting sign requests.
	ErrAttestation = errors.New("kesagent: attestation failed")
	// ErrUnauthenticatedPeer is returned when the remote service connection is
	// not protected by mutually authenticated TLS.
	ErrUnauthenticatedPeer = errors.New(
		"kesagent: remote peer is not authenticated",
	)
)

// AttestationRequest and AttestationResponse are defined in kesagent/wire.
type (
	AttestationRequest  = wire.AttestationRequest
	AttestationResponse = wire.AttestationResponse
)

// Attester produces platform evidence that commits to binding. Implementations
// live inside the protected workload and call the platform attestation API.
type Attester interface {
	Evidence(context.Context, []byte) ([]byte, error)
}

// AttestationVerifier validates provider evidence against a binding. Nitro
// and Confidential Space verifiers in internal/signer/backend implement it.
type AttestationVerifier interface {
	Verify(context.Context, []byte, []byte) error
}

// AttestedServiceConfig configures the remotely reachable KES sign service.
// Provider is a stable adapter name such as "nitro" or "confidential-space".
type AttestedServiceConfig struct {
	Provider string
	Attester Attester
}

type attestedKeyState struct {
	coldVKey []byte
	kesVKey  []byte
	opcert   []byte
	period   uint64
}

func (a *Agent) attestedKeyState() (attestedKeyState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cfg.Mode != ModeSign {
		return attestedKeyState{}, errors.New(
			"kesagent: attested service requires sign mode",
		)
	}
	if a.active == nil || !a.activeAuthorizedLocked() {
		return attestedKeyState{}, ErrNoActiveKey
	}
	if floor, set := a.guard.Floor(); set && a.active.absPeriod() < floor {
		return attestedKeyState{}, ErrPeriodRollback
	}
	return attestedKeyState{
		coldVKey: append([]byte(nil), a.cfg.ColdVKey...),
		kesVKey:  append([]byte(nil), a.active.vkey...),
		opcert:   append([]byte(nil), a.active.opcert...),
		period:   a.active.absPeriod(),
	}, nil
}

// AttestationBinding is the digest provider evidence must commit to. It binds
// a caller nonce to the active public KES state and the pool identity.
func AttestationBinding(
	nonce, coldVKey, kesVKey, opcert []byte,
	period uint64,
) []byte {
	h := sha256.New()
	h.Write([]byte(AttestedProtocolID))
	writeBindingField(h, nonce)
	writeBindingField(h, coldVKey)
	writeBindingField(h, kesVKey)
	writeBindingField(h, opcert)
	var p [8]byte
	binary.BigEndian.PutUint64(p[:], period)
	h.Write(p[:])
	return h.Sum(nil)
}

type bindingWriter interface{ Write([]byte) (int, error) }

func writeBindingField(w bindingWriter, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = w.Write(size[:])
	_, _ = w.Write(value)
}

// VerifyAttestation validates a response before a client admits the workload.
func VerifyAttestation(
	ctx context.Context,
	req AttestationRequest,
	resp AttestationResponse,
	expectedProvider string,
	coldVKey, expectedOpCert []byte,
	verifier AttestationVerifier,
) error {
	if verifier == nil || req.Type != "attestation_request" ||
		req.Protocol != AttestedProtocolID ||
		len(req.Nonce) != attestationNonceSize {
		return ErrAttestation
	}
	if resp.Type != "attestation_response" ||
		resp.Protocol != AttestedProtocolID ||
		resp.Error != "" ||
		resp.Provider != expectedProvider ||
		len(resp.KESVKey) != 32 ||
		len(resp.OpCert) == 0 ||
		len(resp.Attestation) == 0 {
		return ErrAttestation
	}
	if subtle.ConstantTimeCompare(req.Nonce, resp.Nonce) != 1 {
		return ErrAttestation
	}
	if len(expectedOpCert) == 0 ||
		subtle.ConstantTimeCompare(resp.OpCert, expectedOpCert) != 1 {
		return ErrAttestation
	}
	decoded, err := bursa.DecodeOpCert(resp.OpCert)
	if err != nil || !bytes.Equal(decoded.ColdVKey, coldVKey) ||
		!bytes.Equal(decoded.KESVKey, resp.KESVKey) ||
		resp.Period < decoded.KESPeriod {
		return ErrAttestation
	}
	if err := ledger.VerifyOpCertSignature(decoded.LedgerOpCert(), coldVKey); err != nil {
		return ErrAttestation
	}
	binding := AttestationBinding(
		req.Nonce,
		coldVKey,
		resp.KESVKey,
		resp.OpCert,
		resp.Period,
	)
	if err := verifier.Verify(ctx, resp.Attestation, binding); err != nil {
		return fmt.Errorf("%w: %w", ErrAttestation, err)
	}
	return nil
}

// NewAttestationRequest creates a fresh challenge for an attested KES service.
func NewAttestationRequest() (AttestationRequest, error) {
	req := AttestationRequest{
		Type:     "attestation_request",
		Protocol: AttestedProtocolID,
		Nonce:    make([]byte, attestationNonceSize),
	}
	if _, err := rand.Read(req.Nonce); err != nil {
		return AttestationRequest{}, fmt.Errorf(
			"kesagent: attestation nonce: %w",
			err,
		)
	}
	return req, nil
}

// ServeAttestedService serves sign mode over mutually authenticated TLS. The
// listener may be TCP or another stream transport, but every accepted
// connection must be a TLS connection with a verified client certificate.
func (a *Agent) ServeAttestedService(
	ctx context.Context,
	ln net.Listener,
	cfg AttestedServiceConfig,
) error {
	if a.cfg.Mode != ModeSign {
		return errors.New("kesagent: attested service requires sign mode")
	}
	if cfg.Provider == "" || cfg.Attester == nil {
		return errors.New(
			"kesagent: attested service requires provider and attester",
		)
	}
	// Connections still in the TLS handshake are tracked apart from
	// authenticated ones, so a peer without a client certificate can never
	// hold a slot a block producer needs.
	pending := newConnSet()
	conns := newConnSet()
	gate := newHandshakeGate()
	srvCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-srvCtx.Done()
		_ = ln.Close()
		pending.closeAll()
		conns.closeAll()
	}()
	var wg sync.WaitGroup
	defer func() { pending.closeAll(); conns.closeAll(); wg.Wait() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("kesagent: attested service accept: %w", err)
			}
		}
		host, ok := gate.acquire(conn.RemoteAddr())
		if !ok {
			_ = conn.Close()
			continue
		}
		if !pending.add(conn) {
			gate.release(host)
			_ = conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conn.Close()
			err := authenticateRemotePeer(ctx, conn)
			pending.remove(conn)
			gate.release(host)
			if err != nil {
				a.logger.Warn("refusing unauthenticated KES peer", "error", err)
				return
			}
			if !conns.add(conn) {
				return
			}
			defer conns.remove(conn)
			a.serveAttestedConn(ctx, conn, cfg)
		}()
	}
}

const (
	// maxPendingHandshakes bounds connections that have not yet completed
	// mutual TLS. Each one holds a slot for at most frameIOTimeout.
	maxPendingHandshakes = 64
	// maxPendingHandshakesPerHost keeps one remote address from taking the
	// whole handshake budget. Block producers dial from a handful of hosts and
	// hold one long-lived connection each, so a few concurrent handshakes per
	// address is ample.
	maxPendingHandshakesPerHost = 4
)

// handshakeGate admits a connection to the TLS handshake only while both the
// global and the per-source budgets have room. A source is an IPv4 address or
// an IPv6 /64. A non-IP transport has no source
// address to separate peers by, so only the global budget applies to it.
type handshakeGate struct {
	mu      sync.Mutex
	total   int
	perHost map[string]int
}

func newHandshakeGate() *handshakeGate {
	return &handshakeGate{perHost: make(map[string]int)}
}

// acquire reserves a handshake slot for addr and returns the key to release
// it with.
func (g *handshakeGate) acquire(addr net.Addr) (string, bool) {
	host := ""
	if tcp, ok := addr.(*net.TCPAddr); ok {
		host = tcp.IP.String()
		if tcp.IP.To4() == nil {
			// One IPv6 subscriber is routinely delegated a whole /64.
			host = tcp.IP.Mask(net.CIDRMask(64, 128)).String()
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.total >= maxPendingHandshakes {
		return "", false
	}
	if host != "" && g.perHost[host] >= maxPendingHandshakesPerHost {
		return "", false
	}
	g.total++
	if host != "" {
		g.perHost[host]++
	}
	return host, true
}

func (g *handshakeGate) release(host string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.total--
	if host == "" {
		return
	}
	if g.perHost[host] <= 1 {
		delete(g.perHost, host)
		return
	}
	g.perHost[host]--
}

func authenticateRemotePeer(ctx context.Context, conn net.Conn) error {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return ErrUnauthenticatedPeer
	}
	if err := tlsConn.SetDeadline(time.Now().Add(frameIOTimeout)); err != nil {
		return fmt.Errorf("%w: %w", ErrUnauthenticatedPeer, err)
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrUnauthenticatedPeer, err)
	}
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("%w: %w", ErrUnauthenticatedPeer, err)
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return ErrUnauthenticatedPeer
	}
	return nil
}

func (a *Agent) serveAttestedConn(
	ctx context.Context,
	conn net.Conn,
	cfg AttestedServiceConfig,
) {
	if err := writeFrame(conn, Hello{Protocol: AttestedProtocolID, Mode: ModeSign}); err != nil {
		return
	}
	var req AttestationRequest
	if err := readFrame(conn, &req); err != nil {
		return
	}
	resp := AttestationResponse{
		Type:     "attestation_response",
		Protocol: AttestedProtocolID,
		Nonce:    append([]byte(nil), req.Nonce...),
		Provider: cfg.Provider,
	}
	if req.Type != "attestation_request" ||
		req.Protocol != AttestedProtocolID ||
		len(req.Nonce) != attestationNonceSize {
		resp.Error = ErrAttestation.Error()
		_ = writeFrame(conn, resp)
		return
	}
	state, err := a.attestedKeyState()
	if err != nil {
		resp.Error = err.Error()
		_ = writeFrame(conn, resp)
		return
	}
	resp.KESVKey, resp.OpCert, resp.Period = state.kesVKey, state.opcert, state.period
	binding := AttestationBinding(
		req.Nonce,
		state.coldVKey,
		state.kesVKey,
		state.opcert,
		state.period,
	)
	resp.Attestation, err = cfg.Attester.Evidence(ctx, binding)
	if err != nil || len(resp.Attestation) == 0 {
		resp.Attestation = nil
		resp.Error = ErrAttestation.Error()
		_ = writeFrame(conn, resp)
		return
	}
	if err := writeFrame(conn, resp); err != nil {
		return
	}
	a.handleSign(ctx, conn)
}

// HTTPAttester calls a workload-local provider adapter. The adapter receives
// the binding and returns platform evidence that commits to it.
type HTTPAttester struct {
	client *http.Client
	base   string
}

// NewHTTPAttester accepts HTTPS, loopback HTTP, or a Unix socket URL. Cleartext
// non-loopback HTTP is refused because the adapter controls attestation.
func NewHTTPAttester(address string) (*HTTPAttester, error) {
	u, err := url.Parse(address)
	if err != nil {
		return nil, fmt.Errorf("kesagent: invalid attester address: %w", err)
	}
	client := &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	switch u.Scheme {
	case "https":
		if u.Host == "" {
			return nil, errors.New("kesagent: attester address has no host")
		}
		return &HTTPAttester{client: client, base: "https://" + u.Host}, nil
	case "http":
		if u.Host == "" || !isLoopbackHost(u.Hostname()) {
			return nil, errors.New(
				"kesagent: attester HTTP address must be loopback",
			)
		}
		return &HTTPAttester{client: client, base: "http://" + u.Host}, nil
	case "unix":
		if u.Path == "" {
			return nil, errors.New(
				"kesagent: attester Unix address has no path",
			)
		}
		path := u.Path
		client.Transport = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", path)
			},
		}
		return &HTTPAttester{client: client, base: "http://attester"}, nil
	default:
		return nil, fmt.Errorf(
			"kesagent: attester address scheme %q is not https, loopback http, or unix",
			u.Scheme,
		)
	}
}

func isLoopbackHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback() || host == "localhost"
}

func (a *HTTPAttester) Evidence(
	ctx context.Context,
	binding []byte,
) ([]byte, error) {
	body, err := json.Marshal(struct {
		Protocol string `json:"protocol"`
		Binding  []byte `json:"binding"`
	}{AttestedProtocolID, binding})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		a.base+"/v1/attest",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, attesterMaxResponse+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK || len(data) > attesterMaxResponse {
		return nil, ErrAttestation
	}
	var out struct {
		Protocol    string `json:"protocol"`
		Binding     []byte `json:"binding"`
		Attestation []byte `json:"attestation"`
		Error       string `json:"error,omitempty"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return nil, ErrAttestation
	}
	if err := dec.Decode(&json.RawMessage{}); !errors.Is(err, io.EOF) {
		return nil, ErrAttestation
	}
	if out.Protocol != AttestedProtocolID || out.Error != "" ||
		subtle.ConstantTimeCompare(out.Binding, binding) != 1 ||
		len(out.Attestation) == 0 {
		return nil, ErrAttestation
	}
	return out.Attestation, nil
}
