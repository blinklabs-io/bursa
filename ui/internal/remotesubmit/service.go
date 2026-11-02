// Package remotesubmit exposes a capability-scoped, approval-gated Cardano
// transaction submission endpoint for standard clients.
package remotesubmit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/blinklabs-io/bursa/ui/internal/connector"
	"github.com/blinklabs-io/bursa/ui/internal/spend"
)

const (
	MaxTransactionBytes  = 64 * 1024
	maxRequestsPerMinute = 12
	maxConcurrent        = 4
	replayWindow         = 10 * time.Minute
	maxReplayEntries     = 1024
)

var (
	ErrDisabled      = errors.New("remote submission is disabled")
	ErrUnauthorized  = errors.New("remote submission capability is invalid")
	ErrRateLimited   = errors.New("remote submission rate limit exceeded")
	ErrDuplicate     = errors.New("transaction was already submitted for approval")
	ErrIncomplete    = errors.New("transaction is not fully signed")
	ErrStaleApproval = errors.New("remote submission access was revoked")
)

type Submitter interface {
	DecodeTx(context.Context, string) (spend.TxSummary, error)
	SubmitTxCbor(context.Context, string) (spend.TxResult, error)
}

type Approver interface {
	ApproveSubmission(context.Context, string, json.RawMessage, func(context.Context) (string, error)) (string, error)
}

type state struct {
	Enabled bool   `json:"enabled"`
	Token   string `json:"token,omitempty"`
}

type Status struct {
	Available bool   `json:"available"`
	Enabled   bool   `json:"enabled"`
	Endpoint  string `json:"endpoint,omitempty"`
}

type Service struct {
	path      string
	publicURL string
	submitter Submitter
	approver  Approver
	now       func() time.Time
	random    func() (string, error)

	mu         sync.Mutex
	state      state
	generation uint64
	window     time.Time
	requests   int
	inFlight   int
	seen       map[[sha256.Size]byte]time.Time
	active     map[uint64]context.CancelFunc
	nextActive uint64
}

func New(path, publicURL string, submitter Submitter, approver Approver) (*Service, error) {
	u, err := url.Parse(publicURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("remote submission public URL must be an HTTPS origin")
	}
	if strings.TrimRight(u.Path, "/") != "" {
		return nil, errors.New("remote submission public URL must not contain a path")
	}
	if submitter == nil || approver == nil {
		return nil, errors.New("remote submission requires a submitter and approval service")
	}
	s := &Service{
		path: path, publicURL: strings.TrimRight(publicURL, "/"), submitter: submitter,
		approver: approver, now: time.Now, random: newToken, seen: map[[sha256.Size]byte]time.Time{},
		active: map[uint64]context.CancelFunc{},
	}
	if blob, err := os.ReadFile(path); err == nil {
		var loaded state
		if err := json.Unmarshal(blob, &loaded); err != nil {
			return nil, fmt.Errorf("parse remote submission state: %w", err)
		}
		if loaded.Enabled && !validToken(loaded.Token) {
			return nil, errors.New("remote submission state has an invalid capability")
		}
		s.state = loaded
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read remote submission state: %w", err)
	}
	return s, nil
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("remote submission token entropy: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func validToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	_, err := hex.DecodeString(token)
	return err == nil
}

func (s *Service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statusLocked()
}

func (s *Service) statusLocked() Status {
	status := Status{Available: true, Enabled: s.state.Enabled}
	if s.state.Enabled {
		status.Endpoint = s.publicURL + "/" + s.state.Token + "/api/submit/tx"
	}
	return status
}

func (s *Service) Enable() (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Enabled {
		return s.statusLocked(), nil
	}
	token, err := s.random()
	if err != nil {
		return Status{}, err
	}
	next := state{Enabled: true, Token: token}
	if err := s.persistLocked(next); err != nil {
		return Status{}, err
	}
	s.state = next
	s.generation++
	return s.statusLocked(), nil
}

func (s *Service) Disable() (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Revoke memory first so a persistence error cannot leave the live listener
	// accepting requests while the user believes disablement was attempted.
	s.state = state{}
	s.generation++
	s.cancelActiveLocked()
	err := s.persistLocked(s.state)
	if err != nil {
		// Removing the prior enabled snapshot preserves revocation across a
		// restart when the atomic replacement itself could not be completed.
		if removeErr := os.Remove(s.path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, removeErr)
		}
	}
	return s.statusLocked(), err
}

func (s *Service) Rotate() (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.state.Enabled {
		return Status{}, ErrDisabled
	}
	token, err := s.random()
	if err != nil {
		return Status{}, err
	}
	next := state{Enabled: true, Token: token}
	if err := s.persistLocked(next); err != nil {
		return Status{}, err
	}
	s.state = next
	s.generation++
	s.cancelActiveLocked()
	return s.statusLocked(), nil
}

func (s *Service) persistLocked(next state) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	blob, err := json.Marshal(next)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".remote-submission-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(blob); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, s.path)
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if r.TLS == nil {
		writeError(w, http.StatusUpgradeRequired, "TLS is required")
		return
	}
	token, ok := tokenFromPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	generation, err := s.authorize(token)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if mediaType := strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]); mediaType != "application/cbor" {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/cbor")
		return
	}
	if r.ContentLength > MaxTransactionBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "transaction exceeds size limit")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxTransactionBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not read transaction")
		return
	}
	if len(body) == 0 {
		writeError(w, http.StatusBadRequest, "transaction is empty")
		return
	}
	if len(body) > MaxTransactionBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "transaction exceeds size limit")
		return
	}

	digest := sha256.Sum256(body)
	if err := s.admit(digest); err != nil {
		switch {
		case errors.Is(err, ErrDuplicate):
			writeError(w, http.StatusConflict, err.Error())
		default:
			writeError(w, http.StatusTooManyRequests, err.Error())
		}
		return
	}
	defer s.release()

	txHex := hex.EncodeToString(body)
	summary, err := s.submitter.DecodeTx(r.Context(), txHex)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid transaction")
		return
	}
	if !summary.IsComplete {
		writeError(w, http.StatusBadRequest, ErrIncomplete.Error())
		return
	}
	params, err := json.Marshal(map[string]any{
		"transaction_id": hex.EncodeToString(digest[:]),
		"size_bytes":     len(body),
		"summary":        summary,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not prepare approval")
		return
	}
	origin := "Remote transaction submission"
	hash, err := s.approver.ApproveSubmission(r.Context(), origin, params, func(ctx context.Context) (string, error) {
		submitCtx, activeID, ok := s.beginSubmission(ctx, generation, token)
		if !ok {
			return "", ErrStaleApproval
		}
		result, err := s.submitter.SubmitTxCbor(submitCtx, txHex)
		if !s.finishSubmission(activeID, generation, token) {
			return "", ErrStaleApproval
		}
		return result.TxHash, err
	})
	if err != nil {
		switch {
		case errors.Is(err, connector.ErrUserDeclined), errors.Is(err, ErrStaleApproval):
			writeError(w, http.StatusForbidden, err.Error())
		case errors.Is(err, connector.ErrTimeout):
			writeError(w, http.StatusRequestTimeout, "approval timed out")
		case errors.Is(err, connector.ErrQueueFull), errors.Is(err, ErrRateLimited):
			writeError(w, http.StatusTooManyRequests, err.Error())
		default:
			writeError(w, http.StatusBadGateway, "transaction submission failed")
		}
		return
	}
	writeJSON(w, http.StatusOK, hash)
}

func tokenFromPath(path string) (string, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 4 || parts[1] != "api" || parts[2] != "submit" || parts[3] != "tx" || !validToken(parts[0]) {
		return "", false
	}
	return parts[0], true
}

func (s *Service) authorize(token string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.state.Enabled {
		return 0, ErrDisabled
	}
	if len(token) != len(s.state.Token) || subtle.ConstantTimeCompare([]byte(token), []byte(s.state.Token)) != 1 {
		return 0, ErrUnauthorized
	}
	return s.generation, nil
}

func (s *Service) beginSubmission(parent context.Context, generation uint64, token string) (context.Context, uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.generationActiveLocked(generation, token) {
		return nil, 0, false
	}
	ctx, cancel := context.WithCancel(parent)
	s.nextActive++
	s.active[s.nextActive] = cancel
	return ctx, s.nextActive, true
}

func (s *Service) finishSubmission(id, generation uint64, token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cancel, ok := s.active[id]; ok {
		cancel()
		delete(s.active, id)
	}
	return s.generationActiveLocked(generation, token)
}

func (s *Service) generationActiveLocked(generation uint64, token string) bool {
	return s.state.Enabled && s.generation == generation && len(token) == len(s.state.Token) &&
		subtle.ConstantTimeCompare([]byte(token), []byte(s.state.Token)) == 1
}

func (s *Service) cancelActiveLocked() {
	for id, cancel := range s.active {
		cancel()
		delete(s.active, id)
	}
}

func (s *Service) admit(digest [sha256.Size]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for key, expiry := range s.seen {
		if !expiry.After(now) {
			delete(s.seen, key)
		}
	}
	if expiry, exists := s.seen[digest]; exists && expiry.After(now) {
		return ErrDuplicate
	}
	if now.Sub(s.window) >= time.Minute || s.window.IsZero() {
		s.window, s.requests = now, 0
	}
	if s.requests >= maxRequestsPerMinute || s.inFlight >= maxConcurrent {
		return ErrRateLimited
	}
	if len(s.seen) >= maxReplayEntries {
		return ErrRateLimited
	}
	s.requests++
	s.inFlight++
	s.seen[digest] = now.Add(replayWindow)
	return nil
}

func (s *Service) release() {
	s.mu.Lock()
	if s.inFlight > 0 {
		s.inFlight--
	}
	s.mu.Unlock()
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "response encoding failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n'))
}
