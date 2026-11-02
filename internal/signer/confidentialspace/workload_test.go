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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/gouroboros/ledger"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

const testKMSKey = "projects/data/locations/global/keyRings/custody/cryptoKeys/pool"

type testCertificate struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	keyPEM  []byte
}

func newTestCA(t *testing.T) testCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
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
	return testCertificate{
		cert: cert,
		key:  key,
		certPEM: pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: der,
		}),
	}
}

func newTestLeaf(
	t *testing.T,
	ca testCertificate,
	server bool,
) testCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	usage := x509.ExtKeyUsageClientAuth
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		usage = x509.ExtKeyUsageServerAuth
		template.IPAddresses = []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("::1"),
		}
	}
	template.ExtKeyUsage = []x509.ExtKeyUsage{usage}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		ca.cert,
		&key.PublicKey,
		ca.key,
	)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCertificate{
		cert: cert,
		key:  key,
		certPEM: pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: der,
		}),
		keyPEM: pem.EncodeToMemory(&pem.Block{
			Type: "EC PRIVATE KEY", Bytes: keyDER,
		}),
	}
}

func writeTestCertificate(
	t *testing.T,
	dir, name string,
	certificate testCertificate,
) (string, string) {
	t.Helper()
	certFile := filepath.Join(dir, name+".crt")
	keyFile := filepath.Join(dir, name+".key")
	if err := os.WriteFile(certFile, certificate.certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, certificate.keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

type memoryStore struct {
	mu                 sync.Mutex
	data               []byte
	counter            uint64
	counterInitialized bool
	counterKey         backend.KeyHash
	prepareErr         error
}

func (s *memoryStore) Prepare(
	_ context.Context,
	key backend.KeyHash,
	allowCreate bool,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prepareErr != nil {
		err := s.prepareErr
		s.prepareErr = nil
		return err
	}
	if s.counterInitialized {
		if s.counterKey != key {
			return errors.New("counter state does not match the pool cold key")
		}
		return nil
	}
	if !allowCreate {
		return errors.New("counter state is missing for the pool cold key")
	}
	s.counterInitialized = true
	s.counterKey = key
	return nil
}

func (s *memoryStore) Load() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data == nil {
		return nil, ErrEnvelopeNotFound
	}
	return append([]byte(nil), s.data...), nil
}

func (s *memoryStore) Create(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data != nil {
		return ErrEnvelopeExists
	}
	s.data = append([]byte(nil), data...)
	return nil
}

func (s *memoryStore) Replace(expected, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !bytes.Equal(s.data, expected) {
		return ErrEnvelopeChanged
	}
	s.data = append([]byte(nil), data...)
	return nil
}

func (s *memoryStore) CheckAndAdvance(
	_ context.Context,
	key backend.KeyHash,
	counter uint64,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.counterInitialized {
		return errors.New("counter state is missing for the pool cold key")
	}
	if s.counterKey != key {
		return errors.New("counter state does not match the pool cold key")
	}
	if err := checkCounterSequence(s.counter, counter); err != nil {
		return err
	}
	s.counter = counter + 1
	return nil
}

type testWrapper struct {
	denyWrap   bool
	denyUnwrap bool
}

func (w *testWrapper) Wrap(
	_ context.Context,
	plaintext, aad []byte,
) ([]byte, error) {
	if w.denyWrap {
		return nil, errors.New("KMS denied encrypt")
	}
	return testSeal(plaintext, aad), nil
}

func (w *testWrapper) Unwrap(
	_ context.Context,
	ciphertext, aad []byte,
) ([]byte, error) {
	if w.denyUnwrap {
		return nil, errors.New("KMS denied decrypt")
	}
	return testOpen(ciphertext, aad)
}

func testSeal(plaintext, aad []byte) []byte {
	key := sha256.Sum256([]byte("test key wrapper"))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	return gcm.Seal(nonce, nonce, plaintext, aad)
}

func testOpen(ciphertext, aad []byte) ([]byte, error) {
	key := sha256.Sum256([]byte("test key wrapper"))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("short ciphertext")
	}
	return gcm.Open(
		nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		aad,
	)
}

func legacyEnvelope(
	t *testing.T,
	wrapper *testWrapper,
) ([]byte, ed25519.PublicKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := append(ed25519.PublicKey(nil), priv.Public().(ed25519.PublicKey)...)
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	e := envelope{
		Version:   envelopeVersionV1,
		Role:      backend.KeyTypePool,
		KMSKey:    testKMSKey,
		PublicKey: pub,
		Nonce:     make([]byte, gcm.NonceSize()),
	}
	if _, err := rand.Read(e.Nonce); err != nil {
		t.Fatal(err)
	}
	aad := envelopeAAD(e)
	e.Ciphertext = gcm.Seal(nil, e.Nonce, seed, aad)
	e.WrappedDEK, err = wrapper.Wrap(t.Context(), dek, aad)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return data, pub
}

type testTokens struct {
	mu       sync.Mutex
	audience string
	nonces   []string
	err      error
}

func (s *testTokens) Token(
	_ context.Context,
	audience string,
	nonces []string,
) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audience = audience
	s.nonces = append([]string(nil), nonces...)
	if s.err != nil {
		return nil, s.err
	}
	return []byte("attestation-token"), nil
}

func newTestWorkload(
	t *testing.T,
	store *memoryStore,
	wrapper *testWrapper,
	tokens *testTokens,
) *Workload {
	t.Helper()
	w, err := New(t.Context(), Config{
		Audience: "https://signer.example/pool",
		KMSKey:   testKMSKey,
		Tokens:   tokens,
		Wrapper:  wrapper,
		Store:    store,
		Counter:  store,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

func TestWorkloadInventorySignAndRestart(t *testing.T) {
	t.Parallel()
	store := &memoryStore{}
	tokens := &testTokens{}
	wrapper := &testWrapper{}
	w := newTestWorkload(t, store, wrapper, tokens)

	nonce := bytes.Repeat([]byte{0x42}, 32)
	inv, err := w.Inventory(t.Context(), nonce)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Keys) != 1 || inv.Keys[0].Role != backend.KeyTypePool ||
		!bytes.Equal(inv.Keys[0].PublicKey, w.pub) {
		t.Fatalf("inventory = %+v", inv.Keys)
	}
	if tokens.audience != "https://signer.example/pool" {
		t.Fatalf("audience = %q", tokens.audience)
	}
	wantBinding := hex.EncodeToString(backend.InventoryBinding(nonce, inv.Keys))
	if len(tokens.nonces) != 1 || tokens.nonces[0] != wantBinding {
		t.Fatalf("attestation nonces = %v, want %q", tokens.nonces, wantBinding)
	}

	kesVKey := bytes.Repeat([]byte{0x23}, 32)
	payload := lcommon.OpCertSignableBytes(kesVKey, 0, 11)
	req := backend.AttestedRequest{
		Version: backend.AttestedProtocol,
		Purpose: backend.PurposeOpCert,
		KeyHash: w.hash.String(),
		Role:    backend.KeyTypePool,
		Nonce:   bytes.Repeat([]byte{0x24}, 32),
		Payload: payload,
	}
	resp, err := w.Sign(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Error != "" || !ed25519.Verify(w.pub, payload, resp.Signature) {
		t.Fatalf("invalid opcert signature response: %+v", resp)
	}
	if err := ledger.VerifyOpCertSignature(&ledger.OpCert{
		KesVkey: kesVKey, IssueNumber: 0, KesPeriod: 11, ColdSignature: resp.Signature,
	}, w.pub); err != nil {
		t.Fatalf("canonical opcert verification: %v", err)
	}
	if replay, err := w.Sign(t.Context(), req); err != nil ||
		replay.Error == "" ||
		replay.Signature != nil {
		t.Fatalf("replay response = %+v, err = %v", replay, err)
	}

	firstPub := append([]byte(nil), w.pub...)
	seed := append([]byte(nil), w.priv[:ed25519.SeedSize]...)
	store.mu.Lock()
	stored := append([]byte(nil), store.data...)
	store.mu.Unlock()
	if bytes.Contains(stored, seed) || bytes.Contains(stored, w.priv) {
		t.Fatal("persisted envelope contains plaintext pool key material")
	}
	_ = w.Close()
	restarted := newTestWorkload(t, store, wrapper, &testTokens{})
	if !bytes.Equal(restarted.pub, firstPub) {
		t.Fatal("restart changed the pool cold public key")
	}
	req.KeyHash = restarted.hash.String()
	req.Nonce = bytes.Repeat([]byte{0x25}, 32)
	if replay, err := restarted.Sign(t.Context(), req); err != nil ||
		replay.Error == "" || replay.Signature != nil {
		t.Fatalf("restart counter replay response = %+v, err = %v", replay, err)
	}
	req.Payload = lcommon.OpCertSignableBytes(kesVKey, 1, 12)
	req.Nonce = bytes.Repeat([]byte{0x26}, 32)
	resp, err = restarted.Sign(t.Context(), req)
	if err != nil || !ed25519.Verify(restarted.pub, req.Payload, resp.Signature) {
		t.Fatalf("restarted signature: response=%+v err=%v", resp, err)
	}
}

func TestWorkloadRefusesMissingCounterForExistingIdentity(t *testing.T) {
	t.Parallel()
	store := &memoryStore{}
	w := newTestWorkload(t, store, &testWrapper{}, &testTokens{})
	_ = w.Close()
	store.mu.Lock()
	store.counterInitialized = false
	store.counterKey = backend.KeyHash{}
	store.mu.Unlock()

	_, err := New(t.Context(), Config{
		Audience: "https://signer.example/pool",
		KMSKey:   testKMSKey,
		Tokens:   &testTokens{},
		Wrapper:  &testWrapper{},
		Store:    store,
		Counter:  store,
	})
	if err == nil || !strings.Contains(err.Error(), "counter state is missing") {
		t.Fatalf("missing counter state error = %v", err)
	}
}

func TestWorkloadRecoversInterruptedCounterBootstrap(t *testing.T) {
	t.Parallel()
	store := &memoryStore{prepareErr: errors.New("counter unavailable")}
	cfg := Config{
		Audience: "https://signer.example/pool",
		KMSKey:   testKMSKey,
		Tokens:   &testTokens{},
		Wrapper:  &testWrapper{},
		Store:    store,
		Counter:  store,
	}
	if _, err := New(t.Context(), cfg); err == nil ||
		!strings.Contains(err.Error(), "counter unavailable") {
		t.Fatalf("first boot error = %v", err)
	}
	store.mu.Lock()
	var interrupted envelope
	if err := json.Unmarshal(store.data, &interrupted); err != nil {
		store.mu.Unlock()
		t.Fatal(err)
	}
	store.mu.Unlock()
	if interrupted.Version != envelopeVersion ||
		interrupted.Phase != envelopePending {
		t.Fatalf("interrupted envelope = %+v", interrupted)
	}

	w, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("second boot: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	if !bytes.Equal(w.pub, interrupted.PublicKey) {
		t.Fatal("second boot changed the interrupted pool identity")
	}
	store.mu.Lock()
	var active envelope
	if err := json.Unmarshal(store.data, &active); err != nil {
		store.mu.Unlock()
		t.Fatal(err)
	}
	initialized := store.counterInitialized
	store.mu.Unlock()
	if active.Version != envelopeVersion || active.Phase != envelopeActive ||
		!initialized {
		t.Fatalf(
			"recovered envelope = %+v, counter initialized = %v",
			active,
			initialized,
		)
	}
}

func TestWorkloadRestartsFromV1State(t *testing.T) {
	t.Parallel()
	wrapper := &testWrapper{}
	envelopeData, publicKey := legacyEnvelope(t, wrapper)
	store := &memoryStore{data: envelopeData}
	keyHash := backend.HashPublicKey(publicKey)
	issueNumber := uint64(7)
	counterData, err := json.Marshal(counterStateWire{
		Version:     counterStateVersionV1,
		KeyHash:     keyHash.String(),
		IssueNumber: &issueNumber,
	})
	if err != nil {
		t.Fatal(err)
	}
	counterObject := &memoryCounterObject{
		data:       counterData,
		generation: 1,
	}
	counter := &CloudCounterStore{object: counterObject}
	w, err := New(t.Context(), Config{
		Audience: "https://signer.example/pool",
		KMSKey:   testKMSKey,
		Tokens:   &testTokens{},
		Wrapper:  wrapper,
		Store:    store,
		Counter:  counter,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	if !bytes.Equal(w.pub, publicKey) {
		t.Fatal("v1 restart changed the pool identity")
	}
	state, _, exists, err := counter.loadCurrent(
		t.Context(),
		keyHash.String(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !exists || state.NextIssueNumber != issueNumber+1 {
		t.Fatalf("migrated counter = %+v, exists = %v", state, exists)
	}
}

func TestWorkloadRejectsOutOfSequenceCounters(t *testing.T) {
	t.Parallel()
	store := &memoryStore{}
	w := newTestWorkload(t, store, &testWrapper{}, &testTokens{})
	kesVKey := bytes.Repeat([]byte{0x23}, 32)
	sign := func(counter uint64, nonce byte) backend.AttestedResponse {
		t.Helper()
		resp, err := w.Sign(t.Context(), backend.AttestedRequest{
			Version: backend.AttestedProtocol,
			Purpose: backend.PurposeOpCert,
			KeyHash: w.hash.String(),
			Role:    backend.KeyTypePool,
			Nonce:   bytes.Repeat([]byte{nonce}, 32),
			Payload: lcommon.OpCertSignableBytes(kesVKey, counter, 11),
		})
		if err != nil {
			t.Fatalf("counter %d: %v", counter, err)
		}
		return resp
	}
	assertRefused := func(counter uint64, nonce byte) {
		t.Helper()
		resp := sign(counter, nonce)
		if resp.Error == "" || resp.Signature != nil {
			t.Fatalf("counter %d response = %+v, want refusal", counter, resp)
		}
	}

	assertRefused(1, 0x31)
	assertRefused(math.MaxUint64, 0x32)
	if resp := sign(0, 0x33); resp.Error != "" || resp.Signature == nil {
		t.Fatalf("bootstrap response = %+v", resp)
	}
	assertRefused(2, 0x34)
	assertRefused(math.MaxUint64, 0x35)
	if resp := sign(1, 0x36); resp.Error != "" || resp.Signature == nil {
		t.Fatalf("sequential response = %+v", resp)
	}
}

func TestWorkloadFailsClosed(t *testing.T) {
	t.Parallel()
	store := &memoryStore{}
	w := newTestWorkload(t, store, &testWrapper{}, &testTokens{})
	payload := lcommon.OpCertSignableBytes(
		bytes.Repeat([]byte{0x23}, 32),
		0,
		11,
	)
	valid := backend.AttestedRequest{
		Version: backend.AttestedProtocol,
		Purpose: backend.PurposeOpCert,
		KeyHash: w.hash.String(),
		Role:    backend.KeyTypePool,
		Nonce:   bytes.Repeat([]byte{0x24}, 32),
		Payload: payload,
	}
	for name, mutate := range map[string]func(*backend.AttestedRequest){
		"version":  func(r *backend.AttestedRequest) { r.Version = "other" },
		"purpose":  func(r *backend.AttestedRequest) { r.Purpose = backend.PurposeTxHash },
		"key hash": func(r *backend.AttestedRequest) { r.KeyHash = backend.KeyHash{}.String() },
		"role":     func(r *backend.AttestedRequest) { r.Role = backend.KeyTypePayment },
		"nonce":    func(r *backend.AttestedRequest) { r.Nonce = []byte("short") },
		"payload":  func(r *backend.AttestedRequest) { r.Payload = r.Payload[:47] },
	} {
		t.Run(name, func(t *testing.T) {
			req := valid
			req.Nonce = append([]byte(nil), valid.Nonce...)
			req.Payload = append([]byte(nil), valid.Payload...)
			mutate(&req)
			resp, err := w.Sign(t.Context(), req)
			if err != nil || resp.Error == "" || resp.Signature != nil {
				t.Fatalf("response=%+v err=%v", resp, err)
			}
		})
	}

	_, wrong, _ := ed25519.GenerateKey(nil)
	w.signFunc = func(ed25519.PrivateKey, []byte) []byte { return ed25519.Sign(wrong, valid.Payload) }
	valid.Nonce = bytes.Repeat([]byte{0x99}, 32)
	if resp, err := w.Sign(t.Context(), valid); err == nil ||
		resp.Signature != nil {
		t.Fatalf("mismatched signature response=%+v err=%v", resp, err)
	}
}

func TestWorkloadKMSDenialAndMissingAttestation(t *testing.T) {
	t.Parallel()
	store := &memoryStore{}
	w := newTestWorkload(t, store, &testWrapper{}, &testTokens{})
	_ = w.Close()
	_, err := New(t.Context(), Config{
		Audience: "https://signer.example/pool", KMSKey: testKMSKey,
		Tokens: &testTokens{}, Wrapper: &testWrapper{denyUnwrap: true}, Store: store,
		Counter: store,
	})
	if err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("KMS denied decrypt")) {
		t.Fatalf("KMS denial error = %v", err)
	}

	attestationDown := newTestWorkload(
		t,
		&memoryStore{},
		&testWrapper{},
		&testTokens{err: errors.New("no attestation")},
	)
	if _, err := attestationDown.Inventory(t.Context(), make([]byte, 32)); err == nil {
		t.Fatal("inventory succeeded without attestation")
	}
}

type acceptEvidence struct{}

func (acceptEvidence) Verify(
	context.Context,
	[]byte,
	[]byte,
) error {
	return nil
}

func TestWorkloadExistingAttestedContract(t *testing.T) {
	t.Parallel()
	w := newTestWorkload(t, &memoryStore{}, &testWrapper{}, &testTokens{})
	ca := newTestCA(t)
	serverCertificate := newTestLeaf(t, ca, true)
	clientCertificate := newTestLeaf(t, ca, false)
	serverPair, err := tls.X509KeyPair(
		serverCertificate.certPEM,
		serverCertificate.keyPEM,
	)
	if err != nil {
		t.Fatal(err)
	}
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(ca.cert)
	srv := httptest.NewUnstartedServer(w.Handler())
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverPair},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caFile, ca.certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	clientCertFile, clientKeyFile := writeTestCertificate(
		t,
		dir,
		"client",
		clientCertificate,
	)
	enclave, err := backend.NewMTLSHTTPEnclave(
		srv.URL,
		caFile,
		clientCertFile,
		clientKeyFile,
	)
	if err != nil {
		t.Fatal(err)
	}
	b := backend.NewAttestedBackend("gcp", enclave, acceptEvidence{})
	if err := b.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	ref, err := b.GetKey(t.Context(), w.hash)
	if err != nil {
		t.Fatal(err)
	}
	payload := lcommon.OpCertSignableBytes(make([]byte, 32), 0, 3)
	sig, err := backend.SignFor(
		t.Context(),
		ref,
		backend.PurposeOpCert,
		payload,
	)
	if err != nil || !ed25519.Verify(ref.PublicKey(), payload, sig) {
		t.Fatalf("sign error=%v", err)
	}

	for _, path := range []string{"/v1/inventory", "/v1/sign"} {
		req, err := http.NewRequest(
			http.MethodPost,
			srv.URL+path,
			strings.NewReader(`{}`),
		)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(ca.cert)
		client := &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    roots,
			},
		}}
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
			t.Fatalf("unauthenticated %s request reached workload", path)
		}
	}

	untrustedCA := newTestCA(t)
	untrustedClient := newTestLeaf(t, untrustedCA, false)
	untrustedCertFile, untrustedKeyFile := writeTestCertificate(
		t,
		dir,
		"untrusted-client",
		untrustedClient,
	)
	untrusted, err := backend.NewMTLSHTTPEnclave(
		srv.URL,
		caFile,
		untrustedCertFile,
		untrustedKeyFile,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := untrusted.Inventory(t.Context(), make([]byte, 32)); err == nil {
		t.Fatal("untrusted client certificate reached workload")
	}
}

func TestWorkloadHandlerRejectsMalformedRequests(t *testing.T) {
	t.Parallel()
	w := newTestWorkload(t, &memoryStore{}, &testWrapper{}, &testTokens{})
	for _, tc := range []struct {
		name        string
		contentType string
		body        string
	}{
		{"wrong content type", "text/plain", `{}`},
		{"unknown field", "application/json", `{"nonce":"","extra":true}`},
		{"trailing JSON", "application/json", `{"nonce":""}{}`},
		{"oversized", "application/json", strings.Repeat(" ", maxRequestBody+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(
				http.MethodPost,
				"/v1/inventory",
				strings.NewReader(tc.body),
			)
			req.Header.Set("Content-Type", tc.contentType)
			req.TLS = &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{{}},
				VerifiedChains:   [][]*x509.Certificate{{{}}},
			}
			rw := httptest.NewRecorder()
			w.Handler().ServeHTTP(rw, req)
			if rw.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rw.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestWorkloadHandlerRequiresAuthenticatedTLS(t *testing.T) {
	t.Parallel()
	w := newTestWorkload(t, &memoryStore{}, &testWrapper{}, &testTokens{})
	for _, path := range []string{"/v1/inventory", "/v1/sign"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		rw := httptest.NewRecorder()
		w.Handler().ServeHTTP(rw, req)
		if rw.Code != http.StatusUnauthorized {
			t.Fatalf("%s status = %d, want %d", path, rw.Code, http.StatusUnauthorized)
		}
	}
}

func TestWrappedEnvelopeRejectsTampering(t *testing.T) {
	t.Parallel()
	store := &memoryStore{}
	w := newTestWorkload(t, store, &testWrapper{}, &testTokens{})
	_ = w.Close()
	store.mu.Lock()
	var e envelope
	if err := json.Unmarshal(store.data, &e); err != nil {
		t.Fatal(err)
	}
	e.PublicKey[0] ^= 1
	store.data, _ = json.Marshal(e)
	store.mu.Unlock()
	_, err := New(t.Context(), Config{
		Audience: "https://signer.example/pool", KMSKey: testKMSKey,
		Tokens: &testTokens{}, Wrapper: &testWrapper{}, Store: store,
		Counter: store,
	})
	if err == nil {
		t.Fatal("tampered envelope loaded")
	}
}
