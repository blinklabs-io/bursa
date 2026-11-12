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
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
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
	AttestedProtocolID = wire.AttestedProtocolID
	// NoEvidenceProvider is defined in kesagent/wire.
	NoEvidenceProvider   = wire.NoEvidenceProvider
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
// The "none" provider has no Attester and sends no evidence.
type AttestedServiceConfig struct {
	Provider string
	Attester Attester
	// Plaintext serves the protocol on plain TCP connections. The listener is
	// then not expected to be TLS, and no remote-peer authentication is done by
	// the agent.
	Plaintext bool
	// ClientCertOptional accepts a TLS connection without a client
	// certificate. It is for a listener configured without a client CA; the
	// default requires a verified client certificate.
	ClientCertOptional bool
}

type attestedKeyState struct {
	coldVKey []byte
	kesVKey  []byte
	opcert   []byte
	period   uint64
}

// attestedKeyState returns the profile an attestation request selects (see
// selectProfile) and its key state. The session is bound to that profile:
// its sign requests are refused with ErrProfileMismatch when their header
// routes to another one.
func (a *Agent) attestedKeyState(
	name string,
	kesVKey []byte,
) (*profile, attestedKeyState, error) {
	p, err := a.selectProfile(name, kesVKey)
	if err != nil {
		return nil, attestedKeyState{}, err
	}
	st, err := p.attestedKeyState()
	if err != nil {
		return nil, attestedKeyState{}, err
	}
	// selectProfile read the routing snapshot; st was read under the
	// profile lock. A rotation between the two must not attest another key.
	if len(kesVKey) != 0 && !bytes.Equal(st.kesVKey, kesVKey) {
		return nil, attestedKeyState{}, fmt.Errorf(
			"%w: no active key matches",
			ErrUnknownProfile,
		)
	}
	return p, st, nil
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
	noEvidence := expectedProvider == NoEvidenceProvider
	if (verifier == nil && !noEvidence) || req.Type != "attestation_request" ||
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
		// Evidence is required except for none, which must carry none.
		(len(resp.Attestation) == 0) == !noEvidence {
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
	if noEvidence {
		// No evidence: the pinned TLS server key is the authentication.
		return nil
	}
	if verifier == nil {
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

// ServeAttestedService serves sign mode. The listener may be TCP or another
// stream transport. By default every accepted connection must be a TLS
// connection with a verified client certificate; cfg.ClientCertOptional
// relaxes the certificate requirement and cfg.Plaintext serves plain
// connections.
func (a *Agent) ServeAttestedService(
	ctx context.Context,
	ln net.Listener,
	cfg AttestedServiceConfig,
) error {
	if a.cfg.Mode != ModeSign {
		return errors.New("kesagent: attested service requires sign mode")
	}
	if cfg.Provider == "" {
		return errors.New("kesagent: attested service requires provider")
	}
	if (cfg.Provider == NoEvidenceProvider) != (cfg.Attester == nil) {
		return errors.New(
			"kesagent: attested service requires an attester, except for the none provider, which takes none",
		)
	}
	// Connections still in the TLS handshake are tracked apart from
	// authenticated ones, so a peer that has not completed peer
	// authentication can never hold a slot a block producer needs.
	pending := newHandshakeSet()
	conns := newConnSet()
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
		if !pending.add(conn) {
			_ = conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conn.Close()
			err := authenticateRemotePeer(ctx, conn, cfg)
			pending.remove(conn)
			if err != nil {
				a.logger.Warn("refusing unauthenticated KES peer", "error", err)
				return
			}
			if !conns.add(conn) {
				if srvCtx.Err() == nil {
					a.logger.Warn(
						"refusing authenticated KES peer: connection limit reached",
						"limit", maxTrackedConns,
						"remote", conn.RemoteAddr().String(),
					)
				}
				return
			}
			defer conns.remove(conn)
			a.serveAttestedConn(ctx, conn, cfg)
		}()
	}
}

const (
	// maxPendingHandshakes bounds connections that have not yet completed
	// the TLS handshake. Each one holds a slot for at most frameIOTimeout.
	maxPendingHandshakes = 64
	// maxPendingHandshakesPerHost keeps one source from taking the whole
	// handshake budget. Block producers dial from a handful of hosts and hold
	// one long-lived connection each, so a few concurrent handshakes per
	// source is ample.
	maxPendingHandshakesPerHost = 4
)

// handshakeSet tracks connections still in the TLS handshake. When a budget is
// full, a new connection evicts the oldest pending handshake from its own
// source, or else the oldest overall, instead of being refused. A refusal
// would let a peer that opens connections and never finishes the handshake
// hold every slot for frameIOTimeout and lock out a producer's reconnect, even
// from a shared address. With eviction, a stalled connection holds its slot
// only until newer ones arrive, and a producer's handshake, which completes in
// a round trip or two, is lost only to an attacker opening a full budget of
// connections within that window.
//
// A source is an IPv4 address or an IPv6 /64. A non-IP transport has no
// source address to separate peers by, so only the global budget applies.
type handshakeSet struct {
	mu      sync.Mutex
	closed  bool
	next    uint64
	conns   map[net.Conn]pendingHandshake
	perHost map[string]int
}

type pendingHandshake struct {
	host string
	seq  uint64
}

func newHandshakeSet() *handshakeSet {
	return &handshakeSet{
		conns:   make(map[net.Conn]pendingHandshake),
		perHost: make(map[string]int),
	}
}

func handshakeSource(addr net.Addr) string {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return ""
	}
	if tcp.IP.To4() == nil {
		// One IPv6 subscriber is routinely delegated a whole /64.
		return tcp.IP.Mask(net.CIDRMask(64, 128)).String()
	}
	return tcp.IP.String()
}

// add admits c, closing the pending handshake it evicts if a budget was full.
// It returns false only after closeAll, in which case the caller closes c.
func (s *handshakeSet) add(c net.Conn) bool {
	host := handshakeSource(c.RemoteAddr())
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false
	}
	var evicted net.Conn
	switch {
	case host != "" && s.perHost[host] >= maxPendingHandshakesPerHost:
		evicted = s.oldestLocked(host, true)
	case len(s.conns) >= maxPendingHandshakes:
		evicted = s.oldestLocked("", false)
	}
	if evicted != nil {
		s.removeLocked(evicted)
	}
	s.next++
	s.conns[c] = pendingHandshake{host: host, seq: s.next}
	if host != "" {
		s.perHost[host]++
	}
	s.mu.Unlock()
	if evicted != nil {
		_ = evicted.Close()
	}
	return true
}

func (s *handshakeSet) oldestLocked(host string, sameHost bool) net.Conn {
	var oldest net.Conn
	var seq uint64
	for c, p := range s.conns {
		if sameHost && p.host != host {
			continue
		}
		if oldest == nil || p.seq < seq {
			oldest, seq = c, p.seq
		}
	}
	return oldest
}

// remove stops tracking c. It is a no-op for a connection already evicted.
func (s *handshakeSet) remove(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeLocked(c)
}

func (s *handshakeSet) removeLocked(c net.Conn) {
	p, ok := s.conns[c]
	if !ok {
		return
	}
	delete(s.conns, c)
	if p.host == "" {
		return
	}
	if s.perHost[p.host] <= 1 {
		delete(s.perHost, p.host)
		return
	}
	s.perHost[p.host]--
}

// closeAll closes every pending handshake and refuses later additions.
func (s *handshakeSet) closeAll() {
	s.mu.Lock()
	s.closed = true
	pending := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		pending = append(pending, c)
	}
	clear(s.conns)
	clear(s.perHost)
	s.mu.Unlock()
	for _, c := range pending {
		_ = c.Close()
	}
}

// authenticateRemotePeer completes the TLS handshake and checks the client
// certificate the listener's TLS configuration verified. A plaintext service
// does no peer authentication. A TLS service requires a verified client
// certificate unless cfg.ClientCertOptional is set, which is for a listener
// that requests none.
func authenticateRemotePeer(
	ctx context.Context,
	conn net.Conn,
	cfg AttestedServiceConfig,
) error {
	if cfg.Plaintext {
		return nil
	}
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
	if cfg.ClientCertOptional {
		return nil
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
	bound, state, err := a.attestedKeyState(req.Profile, req.KESVKey)
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
	if cfg.Provider == NoEvidenceProvider {
		if err := writeFrame(conn, resp); err != nil {
			return
		}
		a.handleSign(ctx, conn, bound)
		return
	}
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
	a.handleSign(ctx, conn, bound)
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

// SPKIFingerprint is the hex SHA-256 of a certificate's DER
// SubjectPublicKeyInfo, the value a client pins for the none provider.
func SPKIFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}
