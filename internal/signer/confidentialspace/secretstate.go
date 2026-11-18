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
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	secretmanagerclient "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/opcertrule"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// stateDocumentVersion names the document held in the state secret.
	stateDocumentVersion = "bursa-confidential-space-state/1"
	// sealedCounterVersion is bound into the additional data of every sealed
	// counter record, so a record of another version is refused.
	sealedCounterVersion = "bursa-confidential-space-sealed-counter/1"
	// counterSealLabel separates the sealing key from the envelope's use of the
	// same data-encryption key.
	counterSealLabel = "bursa-confidential-space-counter-seal/1"
	sealKeySize      = 32
	// maxStateDocumentSize is Secret Manager's payload limit.
	maxStateDocumentSize = 64 << 10
	secretRPCTimeout     = 30 * time.Second
	// secretCleanupTimeout bounds the cleanup after a write. The cleanup
	// runs after the response and holds the store's lock, so it also bounds
	// how long it can delay the next write. Unfinished cleanup is retried by
	// the next write.
	secretCleanupTimeout = 5 * time.Second
)

var (
	// ErrStateNotProvisioned reports a state secret that is missing, has no
	// version, or holds no wrapped key. It is deliberately not
	// ErrEnvelopeNotFound: a missing envelope makes the workload generate a
	// pool key, which this store never permits.
	ErrStateNotProvisioned = errors.New(
		"state secret holds no provisioned wrapped key",
	)
	// ErrStateCreateRefused reports an attempt to create a wrapped key in the
	// state secret.
	ErrStateCreateRefused = errors.New(
		"the state secret store never creates a wrapped key",
	)
	// ErrStateNotEmpty reports an import into a state secret that already
	// holds data.
	ErrStateNotEmpty = errors.New("state secret is not empty")
	// ErrStateStopped reports a counter call after a failed save.
	ErrStateStopped = errors.New(
		"state secret store stopped after a failed save; restart the workload",
	)
)

var stateSecretPattern = regexp.MustCompile(
	`^projects/[^/]+/secrets/[^/]+$`,
)

// secretVersionIterator is the iterator ListSecretVersions returns.
type secretVersionIterator interface {
	Next() (*secretmanagerpb.SecretVersion, error)
}

// secretStateClient is the part of Secret Manager the state store uses.
type secretStateClient interface {
	AccessSecretVersion(
		context.Context,
		*secretmanagerpb.AccessSecretVersionRequest,
	) (*secretmanagerpb.AccessSecretVersionResponse, error)
	AddSecretVersion(
		context.Context,
		*secretmanagerpb.AddSecretVersionRequest,
	) (*secretmanagerpb.SecretVersion, error)
	ListSecretVersions(
		context.Context,
		*secretmanagerpb.ListSecretVersionsRequest,
	) secretVersionIterator
	DestroySecretVersion(
		context.Context,
		*secretmanagerpb.DestroySecretVersionRequest,
	) (*secretmanagerpb.SecretVersion, error)
	Close() error
}

type cloudSecretStateClient struct {
	*secretmanagerclient.Client
}

func (c cloudSecretStateClient) AccessSecretVersion(
	ctx context.Context,
	req *secretmanagerpb.AccessSecretVersionRequest,
) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	return c.Client.AccessSecretVersion(ctx, req)
}

func (c cloudSecretStateClient) AddSecretVersion(
	ctx context.Context,
	req *secretmanagerpb.AddSecretVersionRequest,
) (*secretmanagerpb.SecretVersion, error) {
	return c.Client.AddSecretVersion(ctx, req)
}

func (c cloudSecretStateClient) ListSecretVersions(
	ctx context.Context,
	req *secretmanagerpb.ListSecretVersionsRequest,
) secretVersionIterator {
	return c.Client.ListSecretVersions(ctx, req)
}

func (c cloudSecretStateClient) DestroySecretVersion(
	ctx context.Context,
	req *secretmanagerpb.DestroySecretVersionRequest,
) (*secretmanagerpb.SecretVersion, error) {
	return c.Client.DestroySecretVersion(ctx, req)
}

// stateDocument is the payload of every version of the state secret. Envelope
// holds the wrapped-key envelope byte for byte, since EnvelopeStore.Replace
// compares exact bytes. Counters maps a profile ("" for the unprofiled state)
// to its sealed counter record.
type stateDocument struct {
	Version  string            `json:"version"`
	Envelope []byte            `json:"envelope"`
	Counters map[string][]byte `json:"counters,omitempty"`
}

// SecretStateStore keeps the wrapped key and the issue counters of every
// profile in one existing Secret Manager secret. It is the EnvelopeStore, and
// Counter returns the CounterStore of each profile.
//
// The state is read once, at Load, and memory is authoritative from then on:
// every request computes the next state, adds it as a new secret version, and
// only then advances memory. Nothing rereads the secret, so a version written
// behind the workload's back can never lower the counter. There is no
// compare-and-swap: one workload may use a secret, and the signer's watermark
// is the authority against a rolled-back secret.
//
// A failed save stops the store: its outcome is unknown, so every later
// counter call fails until restart, which reloads the newest version.
//
// Bursa never creates or deletes the secret.
type SecretStateStore struct {
	client  secretStateClient
	secret  string
	kmsKey  string
	wrapper KeyWrapper
	// base is the context of the RPCs that take no caller context.
	base context.Context

	mu     sync.Mutex
	loaded bool
	// parent is the secret as the service names it, read at Load. It names
	// the project by number even when secret names it by ID.
	parent   string
	stopped  error
	envelope []byte
	pub      ed25519.PublicKey
	hash     backend.KeyHash
	sealKey  []byte
	states   map[string]counterState

	// pendingKeep is the version of the newest write whose older versions
	// are not yet destroyed, 0 if none.
	pendingKeep uint64
	// cleanups counts the cleanup goroutines in flight.
	cleanups sync.WaitGroup
}

// NewSecretStateStore creates a state store over the existing secret using
// the measured workload's external-account credentials. wrapper unwraps the
// envelope's data-encryption key, from which the counter sealing key derives.
func NewSecretStateStore(
	ctx context.Context,
	secret, kmsKey string,
	wrapper KeyWrapper,
	credentialFile string,
) (*SecretStateStore, error) {
	if err := validateStateSecret(secret); err != nil {
		return nil, err
	}
	if err := validateWIFCredentials(credentialFile); err != nil {
		return nil, err
	}
	client, err := secretmanagerclient.NewClient(
		ctx,
		option.WithAuthCredentialsFile(option.ExternalAccount, credentialFile),
	)
	if err != nil {
		return nil, fmt.Errorf("create Secret Manager client: %w", err)
	}
	return newSecretStateStore(
		ctx,
		cloudSecretStateClient{Client: client},
		secret,
		kmsKey,
		wrapper,
	)
}

func validateStateSecret(secret string) error {
	if !stateSecretPattern.MatchString(secret) {
		return errors.New(
			"state secret must be projects/<project>/secrets/<secret>",
		)
	}
	return nil
}

func newSecretStateStore(
	ctx context.Context,
	client secretStateClient,
	secret, kmsKey string,
	wrapper KeyWrapper,
) (*SecretStateStore, error) {
	if err := validateStateSecret(secret); err != nil {
		return nil, err
	}
	if kmsKey == "" || wrapper == nil {
		return nil, errors.New(
			"state secret store requires a KMS key and wrapper",
		)
	}
	return &SecretStateStore{
		client:  client,
		secret:  secret,
		kmsKey:  kmsKey,
		wrapper: wrapper,
		base:    ctx,
		states:  make(map[string]counterState),
	}, nil
}

// Close waits for the cleanup in flight, releases the Secret Manager client
// and wipes the sealing key.
func (s *SecretStateStore) Close() error {
	s.cleanups.Wait()
	s.mu.Lock()
	wipe(s.sealKey)
	s.mu.Unlock()
	return s.client.Close()
}

// Counter returns the counter store of profile, "" for the unprofiled state.
func (s *SecretStateStore) Counter(
	profile string,
) (*SecretCounterStore, error) {
	if profile != "" {
		if err := ValidateProfile(profile); err != nil {
			return nil, err
		}
	}
	return &SecretCounterStore{state: s, profile: profile}, nil
}

func (s *SecretStateStore) rpcContext(
	parent context.Context,
) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, secretRPCTimeout)
}

// Load returns the stored envelope. The first call reads and authenticates the
// whole state; later calls return memory. A missing secret, a secret without
// a version, or an empty payload is ErrStateNotProvisioned.
func (s *SecretStateStore) Load() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded {
		if err := s.loadLocked(); err != nil {
			return nil, err
		}
	}
	return bytes.Clone(s.envelope), nil
}

// Create always refuses: provisioning writes the envelope.
func (*SecretStateStore) Create([]byte) error {
	return ErrStateCreateRefused
}

// Replace activates a new envelope of the same key. expected must be the
// envelope in memory, and data must open under the same data-encryption key,
// or the sealed counters could no longer be read after a restart.
func (s *SecretStateStore) Replace(expected, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded {
		return errors.New("state secret has not been loaded")
	}
	if s.stopped != nil {
		return s.stopped
	}
	if !bytes.Equal(s.envelope, expected) {
		return ErrEnvelopeChanged
	}
	e, err := parseStateEnvelope(data, s.kmsKey)
	if err != nil {
		return err
	}
	if !s.pub.Equal(ed25519.PublicKey(e.PublicKey)) {
		return errors.New("replacement envelope has another public key")
	}
	key, err := s.deriveSealKey(s.base, e)
	if err != nil {
		return err
	}
	defer wipe(key)
	if subtle.ConstantTimeCompare(key, s.sealKey) != 1 {
		return errors.New(
			"replacement envelope has another data-encryption key",
		)
	}
	if err := s.saveLocked(s.base, data, s.states); err != nil {
		return err
	}
	s.envelope = bytes.Clone(data)
	return nil
}

// Import writes envelope and the starting counter of each profile into an
// empty state secret: one whose newest version is enabled or absent and whose
// every enabled version has an empty payload. It refuses any other state, so
// an existing envelope is never replaced or destroyed. nextIssue maps each
// profile to the next issue number its explicit path accepts. The store is not
// loaded afterwards; a normal start loads what Import wrote.
func (s *SecretStateStore) Import(
	ctx context.Context,
	envelopeBytes []byte,
	nextIssue map[string]uint64,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loaded || s.stopped != nil {
		return errors.New("state secret store is already in use")
	}
	e, err := parseStateEnvelope(envelopeBytes, s.kmsKey)
	if err != nil {
		return err
	}
	// A pending envelope would make a start create the counters of every
	// profile it serves, which a starting counter must never be replaced by.
	if e.Version != envelopeVersion || e.Phase != envelopeActive {
		return errors.New("imported envelope must be active")
	}
	readCtx, cancel := s.rpcContext(ctx)
	resp, err := s.readNewest(readCtx)
	cancel()
	switch {
	case errors.Is(err, ErrStateNotProvisioned):
	case err != nil:
		return err
	case len(resp.GetPayload().GetData()) != 0:
		return ErrStateNotEmpty
	}
	if err := s.requireEnabledVersionsEmpty(ctx); err != nil {
		return err
	}
	sealKey, err := s.deriveSealKey(ctx, e)
	if err != nil {
		return err
	}
	pub := ed25519.PublicKey(bytes.Clone(e.PublicKey))
	hash := backend.HashPublicKey(pub)
	states := make(map[string]counterState, len(nextIssue))
	for profile, next := range nextIssue {
		if err := ValidateProfile(profile); err != nil {
			wipe(sealKey)
			return err
		}
		if next >= math.MaxUint64-1 {
			wipe(sealKey)
			return ErrCounterRegression
		}
		states[profile] = seededCounterState(hash, profile, next)
	}
	s.sealKey, s.pub = sealKey, pub
	defer func() {
		wipe(s.sealKey)
		s.sealKey, s.pub = nil, nil
	}()
	return s.saveLocked(ctx, envelopeBytes, states)
}

// requireEnabledVersionsEmpty refuses unless every enabled version of the
// secret has an empty payload. The cleanup after a write destroys every older
// enabled version, so one holding a wrapped key would be lost. Versions are
// read by number, which unlike the version list is strongly consistent.
func (s *SecretStateStore) requireEnabledVersionsEmpty(
	parent context.Context,
) error {
	ctx, cancel := s.rpcContext(parent)
	defer cancel()
	for n := uint64(1); ; n++ {
		resp, err := s.accessVersion(ctx, n)
		if status.Code(err) == codes.NotFound {
			return nil
		}
		// Disabled or destroyed: the cleanup destroys only enabled ones.
		if status.Code(err) == codes.FailedPrecondition {
			continue
		}
		if err != nil {
			return fmt.Errorf("read state secret version %d: %w", n, err)
		}
		if len(resp.GetPayload().GetData()) != 0 {
			return ErrStateNotEmpty
		}
	}
}

// seededCounterState is the counter record of an imported pool whose next
// issue number is next. The pool's on-chain counter is the number before it:
// it is both the last issued number and the opcert-next floor, so a lower
// chain report cannot reissue the on-chain number at an unrecorded KES period.
func seededCounterState(
	hash backend.KeyHash,
	profile string,
	next uint64,
) counterState {
	state := counterState{
		Version:         counterStateVersion,
		KeyHash:         hash.String(),
		NextIssueNumber: next,
		Profile:         profile,
	}
	if next > 0 {
		state.LastIssued, state.OpCertFloor = next-1, next-1
	}
	return state
}

func (s *SecretStateStore) loadLocked() error {
	ctx, cancel := s.rpcContext(s.base)
	defer cancel()
	resp, err := s.readNewest(ctx)
	if err != nil {
		return err
	}
	payload := resp.GetPayload()
	data := payload.GetData()
	if len(data) == 0 {
		return ErrStateNotProvisioned
	}
	if len(data) > maxStateDocumentSize {
		return errors.New("state secret exceeds size limit")
	}
	// Presence matters: an absent checksum is not a zero one.
	if payload.DataCrc32C != nil && //nolint:protogetter
		*payload.DataCrc32C != checksumValue(data) { //nolint:protogetter
		return errors.New("state secret failed integrity check")
	}
	var doc stateDocument
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("decode state secret: %w", err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return fmt.Errorf("decode state secret: %w", err)
	}
	if doc.Version != stateDocumentVersion {
		return errors.New("state secret has an unsupported version")
	}
	if len(doc.Envelope) == 0 {
		return ErrStateNotProvisioned
	}
	e, err := parseStateEnvelope(doc.Envelope, s.kmsKey)
	if err != nil {
		return err
	}
	sealKey, err := s.deriveSealKey(s.base, e)
	if err != nil {
		return err
	}
	pub := ed25519.PublicKey(bytes.Clone(e.PublicKey))
	hash := backend.HashPublicKey(pub)
	states := make(map[string]counterState, len(doc.Counters))
	for profile, sealed := range doc.Counters {
		if profile != "" {
			if err := ValidateProfile(profile); err != nil {
				wipe(sealKey)
				return err
			}
		}
		state, err := openSealedCounter(
			sealKey, pub, s.kmsKey, profile, hash.String(), sealed,
		)
		if err != nil {
			wipe(sealKey)
			return err
		}
		states[profile] = state
	}
	s.parent, _, _ = strings.Cut(resp.GetName(), "/versions/")
	s.envelope = bytes.Clone(doc.Envelope)
	s.pub = pub
	s.hash = hash
	s.sealKey = sealKey
	s.states = states
	s.loaded = true
	return nil
}

// readNewest reads the newest version of the state secret. The latest alias
// and the version list are eventually consistent, so after a restart either
// can still name a version older than the last one added. Only a read by
// version number is strongly consistent, and version numbers are dense, so
// reads continue past the newest listed version until one is not found. The
// newest version must be enabled: an older one may hold a lower counter.
func (s *SecretStateStore) readNewest(
	ctx context.Context,
) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	newest, err := s.newestListed(ctx)
	if err != nil {
		return nil, err
	}
	var resp *secretmanagerpb.AccessSecretVersionResponse
	var respErr error
	if newest > 0 {
		resp, respErr = s.accessVersion(ctx, newest)
	}
	for {
		next, err := s.accessVersion(ctx, newest+1)
		if status.Code(err) == codes.NotFound {
			break
		}
		// A disabled or destroyed version still holds its number.
		if err != nil && status.Code(err) != codes.FailedPrecondition {
			return nil, fmt.Errorf("read state secret: %w", err)
		}
		newest++
		resp, respErr = next, err
	}
	if newest == 0 || status.Code(respErr) == codes.NotFound {
		return nil, ErrStateNotProvisioned
	}
	if respErr != nil {
		return nil, fmt.Errorf(
			"read state secret version %d: %w", newest, respErr,
		)
	}
	if n, ok := s.versionNumber(resp.GetName()); !ok || n != newest {
		return nil, errors.New("state secret version has an unexpected name")
	}
	return resp, nil
}

// newestListed returns the highest enabled version number the version list
// shows, or 0.
func (s *SecretStateStore) newestListed(ctx context.Context) (uint64, error) {
	it := s.client.ListSecretVersions(
		ctx,
		&secretmanagerpb.ListSecretVersionsRequest{
			Parent: s.secret,
			Filter: "state:ENABLED",
		},
	)
	var newest uint64
	for {
		v, err := it.Next()
		if errors.Is(err, iterator.Done) {
			return newest, nil
		}
		if status.Code(err) == codes.NotFound {
			return 0, ErrStateNotProvisioned
		}
		if err != nil {
			return 0, fmt.Errorf("list state secret versions: %w", err)
		}
		if n, ok := s.versionNumber(v.GetName()); ok && n > newest {
			newest = n
		}
	}
}

func (s *SecretStateStore) accessVersion(
	ctx context.Context,
	n uint64,
) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	return s.client.AccessSecretVersion(
		ctx,
		&secretmanagerpb.AccessSecretVersionRequest{
			Name: s.secret + "/versions/" + strconv.FormatUint(n, 10),
		},
	)
}

// versionNumber returns the number of a version of the state secret. Secret
// Manager names the project by number in the names it returns, even for a
// request that named it by ID, so the project is not compared.
func (s *SecretStateStore) versionNumber(name string) (uint64, bool) {
	parent, number, ok := strings.Cut(name, "/versions/")
	if !ok || !stateSecretPattern.MatchString(parent) ||
		secretID(parent) != secretID(s.secret) {
		return 0, false
	}
	n, err := strconv.ParseUint(number, 10, 64)
	if err != nil || n == 0 {
		return 0, false
	}
	return n, true
}

// canonicalVersion returns the number of a version named exactly under the
// parent read at Load.
func (s *SecretStateStore) canonicalVersion(name string) (uint64, bool) {
	n, ok := s.versionNumber(name)
	if !ok || name != s.parent+"/versions/"+strconv.FormatUint(n, 10) {
		return 0, false
	}
	return n, true
}

func secretID(secret string) string {
	return secret[strings.LastIndex(secret, "/")+1:]
}

// parseStateEnvelope reads the metadata of an envelope the store must be able
// to unwrap. The workload authenticates the ciphertext itself.
func parseStateEnvelope(data []byte, kmsKey string) (envelope, error) {
	var e envelope
	if len(data) > maxRequestBody {
		return envelope{}, errors.New("wrapped key exceeds size limit")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return envelope{}, fmt.Errorf("decode wrapped key: %w", err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return envelope{}, fmt.Errorf("decode wrapped key: %w", err)
	}
	if !validEnvelopePhase(e) || e.Role != backend.KeyTypePool ||
		e.KMSKey != kmsKey {
		return envelope{}, errors.New(
			"wrapped key metadata does not match workload configuration",
		)
	}
	if len(e.PublicKey) != ed25519.PublicKeySize || len(e.WrappedDEK) == 0 {
		return envelope{}, errors.New("wrapped key is incomplete")
	}
	return e, nil
}

// deriveSealKey unwraps the envelope's data-encryption key and derives the
// counter sealing key from it. Only the workload can unwrap the key, so only
// the workload can seal or open counter state.
func (s *SecretStateStore) deriveSealKey(
	parent context.Context,
	e envelope,
) ([]byte, error) {
	ctx, cancel := s.rpcContext(parent)
	defer cancel()
	dek, err := s.wrapper.Unwrap(ctx, e.WrappedDEK, envelopeAAD(e))
	if err != nil {
		return nil, fmt.Errorf("unwrap data-encryption key: %w", err)
	}
	defer wipe(dek)
	if len(dek) != 32 {
		return nil, errors.New(
			"unwrapped data-encryption key has invalid length",
		)
	}
	return hkdf.Key(sha256.New, dek, nil, counterSealLabel, sealKeySize)
}

// sealedCounterAAD binds a sealed record to one pool key, KMS key and profile,
// so a record moved to another profile's slot does not open.
func sealedCounterAAD(pub []byte, kmsKey, profile string) []byte {
	var aad []byte
	for _, field := range [][]byte{
		[]byte(sealedCounterVersion),
		pub,
		[]byte(kmsKey),
		[]byte(profile),
	} {
		var size [4]byte
		// #nosec G115 -- every field is bounded well below 4 GiB.
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		aad = append(aad, size[:]...)
		aad = append(aad, field...)
	}
	return aad
}

func counterGCM(sealKey []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(sealKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *SecretStateStore) sealCounter(
	profile string,
	state counterState,
) ([]byte, error) {
	gcm, err := counterGCM(s.sealKey)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("encode counter state: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate counter nonce: %w", err)
	}
	return gcm.Seal(
		nonce, nonce, plain, sealedCounterAAD(s.pub, s.kmsKey, profile),
	), nil
}

// openSealedCounter authenticates a sealed record of profile and returns its
// state, which must be a current-version state of that profile and key.
func openSealedCounter(
	sealKey []byte,
	pub []byte,
	kmsKey, profile, keyHash string,
	sealed []byte,
) (counterState, error) {
	errAuth := errors.New("counter state failed authentication")
	gcm, err := counterGCM(sealKey)
	if err != nil {
		return counterState{}, err
	}
	if len(sealed) < gcm.NonceSize() {
		return counterState{}, errAuth
	}
	plain, err := gcm.Open(
		nil,
		sealed[:gcm.NonceSize()],
		sealed[gcm.NonceSize():],
		sealedCounterAAD(pub, kmsKey, profile),
	)
	if err != nil {
		return counterState{}, errAuth
	}
	var wire counterStateWire
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil {
		return counterState{}, fmt.Errorf("decode counter state: %w", err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return counterState{}, fmt.Errorf("decode counter state: %w", err)
	}
	if wire.Profile != profile {
		return counterState{}, errors.New(
			"counter state does not match the profile",
		)
	}
	state, migrate, err := normalizeCounterState(wire, keyHash)
	if err != nil {
		return counterState{}, err
	}
	if migrate {
		return counterState{}, errors.New(
			"counter state has an unsupported version",
		)
	}
	return state, nil
}

// saveLocked adds the document as a new secret version and, once that
// succeeded, destroys the older ones. The caller advances memory only on a
// nil return. Any failure stops the store: whether the version was added is
// unknown.
func (s *SecretStateStore) saveLocked(
	ctx context.Context,
	envelopeBytes []byte,
	states map[string]counterState,
) error {
	err := s.addVersion(ctx, envelopeBytes, states)
	if err != nil {
		s.stopped = fmt.Errorf("%w: %w", ErrStateStopped, err)
		return err
	}
	return nil
}

func (s *SecretStateStore) addVersion(
	ctx context.Context,
	envelopeBytes []byte,
	states map[string]counterState,
) error {
	doc := stateDocument{
		Version:  stateDocumentVersion,
		Envelope: envelopeBytes,
		Counters: make(map[string][]byte, len(states)),
	}
	for profile, state := range states {
		sealed, err := s.sealCounter(profile, state)
		if err != nil {
			return err
		}
		doc.Counters[profile] = sealed
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encode state secret: %w", err)
	}
	if len(data) > maxStateDocumentSize {
		return errors.New("state secret would exceed size limit")
	}
	crc := checksumValue(data)
	s.cleanupLocked()
	// A cancelled request must not abandon a write half way: its outcome
	// would be unknown. Only the RPC timeout and the request's own deadline
	// bound it: the deadline sits below the server's write timeout, so a
	// write that commits can still be answered.
	addCtx, cancel := s.rpcContext(context.WithoutCancel(ctx))
	defer cancel()
	if deadline, ok := ctx.Deadline(); ok {
		var cancelDeadline context.CancelFunc
		addCtx, cancelDeadline = context.WithDeadline(addCtx, deadline)
		defer cancelDeadline()
	}
	added, err := s.client.AddSecretVersion(
		addCtx,
		&secretmanagerpb.AddSecretVersionRequest{
			Parent: s.secret,
			Payload: &secretmanagerpb.SecretPayload{
				Data:       data,
				DataCrc32C: &crc,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("add state secret version: %w", err)
	}
	if s.parent == "" {
		// The first version of an empty secret: Load never ran, so the
		// service's name for the secret is learned from this response.
		if _, ok := s.versionNumber(added.GetName()); ok {
			s.parent, _, _ = strings.Cut(added.GetName(), "/versions/")
		}
	}
	keep, ok := s.canonicalVersion(added.GetName())
	if !ok {
		return errors.New("state secret version has an unexpected name")
	}
	s.scheduleCleanup(keep)
	return nil
}

// scheduleCleanup destroys the versions older than keep after the caller
// releases the lock, so the response of a committed write does not wait for
// it. The caller holds s.mu. A write that takes the lock first runs the
// pending cleanup before its own add.
func (s *SecretStateStore) scheduleCleanup(keep uint64) {
	s.pendingKeep = max(s.pendingKeep, keep)
	s.cleanups.Go(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.cleanupLocked()
	})
}

// cleanupLocked runs the pending cleanup, if any. The caller holds s.mu.
func (s *SecretStateStore) cleanupLocked() {
	if s.pendingKeep == 0 {
		return
	}
	keep := s.pendingKeep
	s.pendingKeep = 0
	s.destroyOlder(s.base, keep)
}

// destroyOlder destroys every enabled version numbered below keep, never a
// newer one, within secretCleanupTimeout. A failure is logged and retried by
// the next save: the version that was added is already durable.
func (s *SecretStateStore) destroyOlder(
	parent context.Context,
	keep uint64,
) {
	ctx, cancel := context.WithTimeout(parent, secretCleanupTimeout)
	defer cancel()
	it := s.client.ListSecretVersions(
		ctx,
		&secretmanagerpb.ListSecretVersionsRequest{
			Parent: s.secret,
			Filter: "state:ENABLED",
		},
	)
	var older []string
	for {
		v, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			slog.Warn(
				"list older state secret versions failed",
				"error", err,
			)
			return
		}
		n, ok := s.canonicalVersion(v.GetName())
		if ok && n < keep &&
			v.GetState() == secretmanagerpb.SecretVersion_ENABLED {
			older = append(older, v.GetName())
		}
	}
	for _, name := range older {
		if _, err := s.client.DestroySecretVersion(
			ctx,
			&secretmanagerpb.DestroySecretVersionRequest{Name: name},
		); err != nil {
			slog.Warn(
				"destroy older state secret version failed",
				"version", name,
				"error", err,
			)
		}
	}
}

// SecretCounterStore is the CounterStore of one profile of a SecretStateStore.
// Every accept or refuse decision is the opcertrule logic the Cloud Storage
// counter uses; only persistence differs.
type SecretCounterStore struct {
	state   *SecretStateStore
	profile string
}

// counterProfile is the profile whose state the store holds, "" for the
// unprofiled state.
func (c *SecretCounterStore) counterProfile() string { return c.profile }

// begin checks the preconditions common to every counter call and returns the
// current state of the profile, if it has one. The caller holds s.mu.
func (c *SecretCounterStore) begin(
	ctx context.Context,
	key backend.KeyHash,
) (counterState, bool, error) {
	s := c.state
	if err := ctx.Err(); err != nil {
		return counterState{}, false, err
	}
	if s.stopped != nil {
		return counterState{}, false, s.stopped
	}
	if !s.loaded {
		return counterState{}, false, errors.New(
			"state secret has not been loaded",
		)
	}
	if key != s.hash {
		return counterState{}, false, errors.New(
			"counter state does not match the pool cold key",
		)
	}
	state, ok := s.states[c.profile]
	return state, ok, nil
}

// commit saves next as the state of the profile and advances memory.
func (c *SecretCounterStore) commit(
	ctx context.Context,
	next counterState,
) error {
	s := c.state
	states := maps.Clone(s.states)
	states[c.profile] = next
	if err := s.saveLocked(ctx, s.envelope, states); err != nil {
		return err
	}
	s.states = states
	return nil
}

// Prepare binds the store to key. A missing record is created only while the
// wrapped key identity is being created.
func (c *SecretCounterStore) Prepare(
	ctx context.Context,
	key backend.KeyHash,
	allowCreate bool,
) error {
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	_, exists, err := c.begin(ctx, key)
	if err != nil || exists {
		return err
	}
	if !allowCreate {
		return errors.New("counter state is missing for the pool cold key")
	}
	return c.commit(ctx, counterState{
		Version: counterStateVersion,
		KeyHash: key.String(),
		Profile: c.profile,
	})
}

// CheckAndAdvance commits issueNumber only when it is the next sequential
// value for key, and records period as that certificate's KES period.
func (c *SecretCounterStore) CheckAndAdvance(
	ctx context.Context,
	key backend.KeyHash,
	issueNumber, period uint64,
) error {
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	current, exists, err := c.begin(ctx, key)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("counter state is missing for the pool cold key")
	}
	if err := checkCounterSequence(
		current.NextIssueNumber,
		issueNumber,
	); err != nil {
		return err
	}
	return c.commit(ctx, current.withRule(
		opcertrule.Record(current.rule(), issueNumber, period),
	))
}

// NextOpCert chooses the issue number for an opcert-next request with the
// armory device's rules and persists the raised floor, the issue number and
// the KES period before returning it. A repeat of the recorded request writes
// nothing.
func (c *SecretCounterStore) NextOpCert(
	ctx context.Context,
	key backend.KeyHash,
	chain, period uint64,
) (uint64, error) {
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	current, exists, err := c.begin(ctx, key)
	if err != nil {
		return 0, err
	}
	if !exists {
		return 0, errors.New("counter state is missing for the pool cold key")
	}
	next, issue, err := applyOpCertNext(current, chain, period)
	if err != nil {
		return 0, err
	}
	if next == current {
		return issue, nil
	}
	if err := c.commit(ctx, next); err != nil {
		return 0, err
	}
	return issue, nil
}
