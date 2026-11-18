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
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	// ImportProtocol is the version of the pool cold-key import protocol.
	ImportProtocol = "bursa-confidential-space-import/1"
	// ImportChallengeRoute and ImportRoute are the only routes an import-mode
	// workload serves.
	ImportChallengeRoute = "/v1/import/challenge"
	ImportRoute          = "/v1/import"

	importBindingDomain = "bursa-confidential-space-import-binding/1"
	importKDFDomain     = "bursa-confidential-space-import-kdf/1"
	importAuthDomain    = "bursa-confidential-space-import-authorization/1"

	importChallengeSize = 32
	// maxImportProfiles keeps the counter records of one import far below the
	// state secret's size limit.
	maxImportProfiles = 16
	// importRequestTimeout bounds a whole import from handler entry. It sits
	// below the serve command's 30 second write timeout.
	importRequestTimeout = 25 * time.Second
	importBodyFixedSize  = ed25519.SeedSize + ed25519.PublicKeySize
)

var (
	errImportRequest       = errors.New("import request refused")
	errImportChallenge     = errors.New("import challenge is unknown or used")
	errImportAuthorization = errors.New("import authorization invalid")
	errImportOpen          = errors.New("import request failed authentication")
	errImportVKey          = errors.New(
		"imported key does not derive the expected verification key",
	)
	errImportDone = errors.New("import already finished")
)

// ImportChallenge is the workload's answer to /v1/import/challenge: a one-use
// X25519 public key and challenge, and an attestation token whose nonces are
// hex(Challenge) and hex(SHA-256(PublicKey)).
type ImportChallenge struct {
	Version     string `json:"version"`
	Challenge   []byte `json:"challenge"`
	PublicKey   []byte `json:"public_key"`
	Attestation []byte `json:"attestation"`
}

// ImportProfile is one profile the import serves and the next operational
// certificate issue number it may sign: the pool's on-chain counter plus one,
// or 0 for a pool that never issued.
type ImportProfile struct {
	Profile         string `json:"profile"`
	NextIssueNumber uint64 `json:"next_issue_number"`
}

// ImportRequest carries one pool cold key sealed to the workload. The profile
// names travel in the clear because the binding, which authenticates the
// ciphertext, covers them.
type ImportRequest struct {
	Version         string   `json:"version"`
	Challenge       []byte   `json:"challenge"`
	Profiles        []string `json:"profiles"`
	ClientPublicKey []byte   `json:"client_public_key"`
	Nonce           []byte   `json:"nonce"`
	Ciphertext      []byte   `json:"ciphertext"`
	// Authorization is the provisioning authority's Ed25519 signature over
	// importAuthorizationDigest.
	Authorization []byte `json:"authorization"`
}

// ImportStore writes the first state of an empty state secret.
type ImportStore interface {
	Import(
		ctx context.Context,
		envelope []byte,
		nextIssue map[string]uint64,
	) error
}

// ImportConfig contains the import-mode workload's immutable inputs.
type ImportConfig struct {
	Audience string
	KMSKey   string
	Tokens   TokenSource
	Wrapper  KeyWrapper
	Store    ImportStore
	// Authority is the Ed25519 provisioning authority. It must not be
	// the key of the mTLS client that presents the request.
	Authority ed25519.PublicKey
}

type importSession struct {
	seed       []byte
	publicKey  []byte
	challenge  []byte
	tokenNonce []byte
}

func (s *importSession) wipe() {
	if s != nil {
		wipe(s.seed)
	}
}

// Importer is the import-mode workload. It serves the two import routes and
// never signs, and it never generates a pool key: the only key it wraps is the
// one the authorized request carries.
type Importer struct {
	cfg ImportConfig

	mu       sync.Mutex
	session  *importSession
	finished bool
	done     chan struct{}
}

// NewImporter creates an import-mode workload.
func NewImporter(cfg ImportConfig) (*Importer, error) {
	if cfg.Audience == "" {
		return nil, errors.New("import mode requires an audience")
	}
	if cfg.KMSKey == "" || len(cfg.KMSKey) > 1024 {
		return nil, errors.New("import mode requires a KMS key")
	}
	if cfg.Tokens == nil || cfg.Wrapper == nil || cfg.Store == nil {
		return nil, errors.New(
			"import mode requires token, KMS and state providers",
		)
	}
	if len(cfg.Authority) != ed25519.PublicKeySize ||
		bytes.Equal(cfg.Authority, make([]byte, ed25519.PublicKeySize)) {
		return nil, errors.New(
			"import mode requires an Ed25519 provisioning authority",
		)
	}
	cfg.Authority = bytes.Clone(cfg.Authority)
	return &Importer{cfg: cfg, done: make(chan struct{})}, nil
}

// Done is closed once an import has been written.
func (i *Importer) Done() <-chan struct{} { return i.done }

// Close wipes the ephemeral key.
func (i *Importer) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.session.wipe()
	i.session = nil
	return nil
}

// importBinding authenticates one import: the protocol version, the route, the
// challenge, the token nonce, both X25519 public keys, the KMS key and the
// sorted profile names. It is the key-derivation salt and the AEAD's
// additional data.
func importBinding(
	route string,
	challenge, tokenNonce, workloadKey, clientKey []byte,
	kmsKey string,
	profiles []string,
) []byte {
	h := sha256.New()
	write := func(field []byte) {
		_, _ = h.Write([]byte(strconv.Itoa(len(field)) + ":"))
		_, _ = h.Write(field)
	}
	for _, field := range [][]byte{
		[]byte(importBindingDomain),
		[]byte(ImportProtocol),
		[]byte(route),
		challenge,
		tokenNonce,
		workloadKey,
		clientKey,
		[]byte(kmsKey),
		[]byte(strconv.Itoa(len(profiles))),
	} {
		write(field)
	}
	for _, profile := range profiles {
		write([]byte(profile))
	}
	return h.Sum(nil)
}

// importAuthorizationDigest is what the provisioning authority signs: the
// binding and the hash of the exact ciphertext.
func importAuthorizationDigest(binding, ciphertext []byte) []byte {
	sum := sha256.Sum256(ciphertext)
	h := sha256.New()
	for _, field := range [][]byte{
		[]byte(importAuthDomain), binding, sum[:],
	} {
		_, _ = h.Write([]byte(strconv.Itoa(len(field)) + ":"))
		_, _ = h.Write(field)
	}
	return h.Sum(nil)
}

func importChannelKey(shared, binding []byte) ([]byte, error) {
	return hkdf.Key(
		sha256.New, shared, binding, importKDFDomain,
		chacha20poly1305.KeySize,
	)
}

// validateImportProfiles requires 1 to maxImportProfiles distinct valid
// profile names, sorted.
func validateImportProfiles(profiles []string) error {
	if len(profiles) == 0 || len(profiles) > maxImportProfiles {
		return fmt.Errorf(
			"import must name 1 to %d profiles", maxImportProfiles,
		)
	}
	for n, profile := range profiles {
		if err := ValidateProfile(profile); err != nil {
			return err
		}
		if n > 0 && profiles[n-1] >= profile {
			return errors.New("import profiles must be sorted and distinct")
		}
	}
	return nil
}

func tokenNonceOf(publicKey []byte) []byte {
	sum := sha256.Sum256(publicKey)
	return sum[:]
}

// Challenge starts an import: it makes a one-use X25519 key pair and a fresh
// challenge, replacing any earlier ones, and attests both.
func (i *Importer) Challenge(ctx context.Context) (ImportChallenge, error) {
	i.mu.Lock()
	finished := i.finished
	i.mu.Unlock()
	if finished {
		return ImportChallenge{}, errImportDone
	}
	session := &importSession{
		seed:      make([]byte, curve25519.ScalarSize),
		challenge: make([]byte, importChallengeSize),
	}
	for _, b := range [][]byte{session.seed, session.challenge} {
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			session.wipe()
			return ImportChallenge{}, fmt.Errorf("generate challenge: %w", err)
		}
	}
	public, err := curve25519.X25519(session.seed, curve25519.Basepoint)
	if err != nil {
		session.wipe()
		return ImportChallenge{}, fmt.Errorf("derive channel key: %w", err)
	}
	session.publicKey = public
	session.tokenNonce = tokenNonceOf(public)
	token, err := i.cfg.Tokens.Token(ctx, i.cfg.Audience, []string{
		hex.EncodeToString(session.challenge),
		hex.EncodeToString(session.tokenNonce),
	})
	if err != nil {
		session.wipe()
		return ImportChallenge{}, fmt.Errorf(
			"request attestation token: %w", err,
		)
	}
	if len(token) == 0 {
		session.wipe()
		return ImportChallenge{}, errors.New("attestation token is empty")
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.finished {
		session.wipe()
		return ImportChallenge{}, errImportDone
	}
	i.session.wipe()
	i.session = session
	return ImportChallenge{
		Version:     ImportProtocol,
		Challenge:   bytes.Clone(session.challenge),
		PublicKey:   bytes.Clone(session.publicKey),
		Attestation: token,
	}, nil
}

// Import verifies the authority's authorization, opens the request, checks the
// key against its expected verification key, and writes the wrapped key and
// the starting counters into the empty state secret.
func (i *Importer) Import(ctx context.Context, req ImportRequest) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.finished {
		return errImportDone
	}
	if req.Version != ImportProtocol ||
		len(req.Challenge) != importChallengeSize ||
		len(req.ClientPublicKey) != curve25519.PointSize ||
		len(req.Nonce) != chacha20poly1305.NonceSizeX ||
		len(req.Authorization) != ed25519.SignatureSize ||
		len(req.Ciphertext) == 0 ||
		validateImportProfiles(req.Profiles) != nil {
		return errImportRequest
	}
	s := i.session
	if s == nil ||
		subtle.ConstantTimeCompare(s.challenge, req.Challenge) != 1 {
		return errImportChallenge
	}
	binding := importBinding(
		ImportRoute, s.challenge, s.tokenNonce, s.publicKey,
		req.ClientPublicKey, i.cfg.KMSKey, req.Profiles,
	)
	if !ed25519.Verify(
		i.cfg.Authority,
		importAuthorizationDigest(binding, req.Ciphertext),
		req.Authorization,
	) {
		return errImportAuthorization
	}
	body, err := openImportBody(s, req, binding)
	if err != nil {
		return err
	}
	defer wipe(body)
	// The challenge is spent from here on, whatever the outcome.
	i.session = nil
	defer s.wipe()

	seed := body[:ed25519.SeedSize]
	vkey := body[ed25519.SeedSize:importBodyFixedSize]
	nextIssue, err := parseImportCounters(
		body[importBodyFixedSize:], req.Profiles,
	)
	if err != nil {
		return err
	}
	derived := ed25519.NewKeyFromSeed(seed)
	defer wipe(derived)
	if !bytes.Equal(derived.Public().(ed25519.PublicKey), vkey) {
		return errImportVKey
	}
	key, err := wrapSeed(ctx, Config{
		KMSKey:  i.cfg.KMSKey,
		Wrapper: i.cfg.Wrapper,
	}, seed)
	if err != nil {
		return err
	}
	defer wipe(key.priv)
	if err := i.cfg.Store.Import(ctx, key.active, nextIssue); err != nil {
		return err
	}
	i.finished = true
	close(i.done)
	return nil
}

// openImportBody derives the channel key and opens the ciphertext. The caller
// wipes the plaintext.
func openImportBody(
	s *importSession,
	req ImportRequest,
	binding []byte,
) ([]byte, error) {
	shared, err := curve25519.X25519(s.seed, req.ClientPublicKey)
	if err != nil {
		return nil, errImportOpen
	}
	defer wipe(shared)
	key, err := importChannelKey(shared, binding)
	if err != nil {
		return nil, errImportOpen
	}
	defer wipe(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, errImportOpen
	}
	body, err := aead.Open(nil, req.Nonce, req.Ciphertext, binding)
	if err != nil {
		return nil, errImportOpen
	}
	if len(body) <= importBodyFixedSize {
		wipe(body)
		return nil, errImportRequest
	}
	return body, nil
}

// parseImportCounters reads the sealed profile list and requires its profiles
// to be exactly the ones the binding names.
func parseImportCounters(
	data []byte,
	profiles []string,
) (map[string]uint64, error) {
	var entries []ImportProfile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&entries); err != nil {
		return nil, errImportRequest
	}
	if err := requireJSONEOF(dec); err != nil {
		return nil, errImportRequest
	}
	names := make([]string, 0, len(entries))
	next := make(map[string]uint64, len(entries))
	for _, e := range entries {
		if e.NextIssueNumber >= math.MaxUint64-1 {
			return nil, errImportRequest
		}
		names = append(names, e.Profile)
		next[e.Profile] = e.NextIssueNumber
	}
	slices.Sort(names)
	if !slices.Equal(names, profiles) || len(next) != len(profiles) {
		return nil, errImportRequest
	}
	return next, nil
}

// Handler serves only the import routes, behind the same mutual-TLS check as
// the signing workload. A request from the key that is the provisioning
// authority is refused: the authority must not be the client identity.
func (i *Importer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+ImportChallengeRoute, i.handleChallenge)
	mux.HandleFunc("POST "+ImportRoute, i.handleImport)
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 ||
			len(r.TLS.VerifiedChains) == 0 {
			http.Error(
				rw, "client certificate required", http.StatusUnauthorized,
			)
			return
		}
		if key, ok := r.TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey); ok &&
			key.Equal(i.cfg.Authority) {
			http.Error(rw, "client certificate refused", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(rw, r)
	})
}

func (i *Importer) handleChallenge(rw http.ResponseWriter, r *http.Request) {
	var req struct{}
	if err := decodeRequest(rw, r, &req); err != nil {
		http.Error(rw, "invalid request", http.StatusBadRequest)
		return
	}
	ch, err := i.Challenge(r.Context())
	if err != nil {
		http.Error(rw, "attestation unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(rw, ch)
}

func (i *Importer) handleImport(rw http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), importRequestTimeout)
	defer cancel()
	var req ImportRequest
	if err := decodeRequest(rw, r, &req); err != nil {
		http.Error(rw, "invalid request", http.StatusBadRequest)
		return
	}
	if err := i.Import(ctx, req); err != nil {
		slog.Warn("import refused", "error", err)
		http.Error(rw, "import refused", http.StatusForbidden)
		return
	}
	writeJSON(rw, struct {
		Version string `json:"version"`
	}{Version: ImportProtocol})
}
