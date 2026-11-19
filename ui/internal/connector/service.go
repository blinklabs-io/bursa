package connector

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"path/filepath"
	"sync"
	"time"

	"github.com/blinklabs-io/bursa/ui/internal/spend"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
)

// Sentinel errors returned by Service.
var (
	ErrChallengeCapacity   = errors.New("connector: challenge capacity reached")
	ErrRefused             = errors.New("connector: refused")
	ErrUserDeclined        = errors.New("connector: user declined")
	ErrNotGranted          = errors.New("connector: origin not granted")
	ErrPairCodeMismatch    = errors.New("connector: pair code mismatch")
	ErrInvalidParams       = errors.New("connector: invalid request params")
	ErrInvalidOrigin       = errors.New("connector: invalid origin")
	ErrTooManyPairings     = errors.New("connector: too many pending pairings")
	ErrAddressUsageUnknown = errors.New(
		"connector: address usage is unavailable",
	)
	// ErrInvalidExtensionID is defined in token.go.
)

const (
	pairCodeDigits = 12
	pairCodeMax    = 1_000_000_000_000
	// pairCodeTTL bounds how long a generated pairing code stays valid. A code
	// is a short-lived bootstrap secret; expiring it caps the brute-force window.
	pairCodeTTL = 5 * time.Minute
	// pairCodeMaxAttempts caps confirmation tries per code before it is discarded,
	// forcing the user to re-initiate rather than letting a local process grind
	// the 10^12 keyspace.
	pairCodeMaxAttempts = 5
	// maxPendingPairCodes bounds the pending-pairing map so a flood of distinct
	// extension IDs cannot grow it without limit.
	maxPendingPairCodes  = 32
	requestChallengeTTL  = 30 * time.Second
	maxRequestChallenges = 128
)

// pairEntry is a pending pairing code plus the metadata needed to expire it and
// cap confirmation attempts.
type pairEntry struct {
	code      string
	publicKey string
	created   time.Time
	attempts  int
}

// Paginate is used by the Utxos backend method.
type Paginate struct {
	Page  int
	Limit int
}

// Backend is the wallet capability interface that Phase 2 implements.
type Backend interface {
	NetworkID() int
	Utxos(
		ctx context.Context,
		amount string,
		paginate *Paginate,
	) ([]string, error)
	Balance(ctx context.Context) (string, error)
	UsedAddresses(ctx context.Context, paginate *Paginate) ([]string, error)
	UnusedAddresses(ctx context.Context) ([]string, error)
	ChangeAddress(ctx context.Context) (string, error)
	RewardAddresses(ctx context.Context) ([]string, error)
	Collateral(ctx context.Context, amount string) ([]string, error)
	InspectTx(ctx context.Context, txHex string) (spend.TxSummary, error)
	SignTx(
		ctx context.Context,
		txHex string,
		partialSign bool,
		password string,
	) (string, error)
	SignData(addrHex, payloadHex, password string) (sig, key string, err error)
	SubmitTx(ctx context.Context, txHex string) (string, error)
	PubDRepKey(password string) (string, error)
	RegisteredPubStakeKeys(password string) ([]string, error)
	UnregisteredPubStakeKeys(password string) ([]string, error)
}

// Service orchestrates the three connector stores (pairing, grants, queue) and
// routes incoming CIP-30 / CIP-95 method calls to the Backend.
type Service struct {
	tokens *TokenStore
	grants *GrantStore
	queue  *Queue
	be     Backend
	prompt func()
	now    func() time.Time

	// bindingMu keeps the active identity stable from the final grant check
	// through each protected backend call. SetActiveAccount takes the write lock
	// while rebinding the backend, closing the authorization-to-use race.
	bindingMu sync.RWMutex
	identity  accountIdentity
	// pairingMu linearizes key replacement/revocation with admission and final
	// execution of key-bound queued work.
	pairingMu sync.RWMutex

	// pending pair codes: extensionID → entry (code + expiry/attempt metadata)
	pairMu    sync.Mutex
	pairCodes map[string]*pairEntry

	challengeMu sync.Mutex
	challenges  map[string]challengeEntry
}

type challengeEntry struct {
	issuanceNonce string
	authority     string
	redeemed      bool
	extensionID   string
	value         string
	expires       time.Time
}

type pairingAuthority struct {
	extensionID string
	publicKey   string
}

type pairingAuthorityContextKey struct{}

// NewService constructs a Service, creating the three stores under dir.
// networkPrompt is called (if non-nil) after each new request is enqueued so
// that Phase 3 can raise a UI notification.
func NewService(dir string, be Backend, networkPrompt func()) *Service {
	mkID := func() (string, error) {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return "", fmt.Errorf("connector: request id entropy: %w", err)
		}
		return hex.EncodeToString(b), nil
	}
	return &Service{
		tokens: NewTokenStore(
			filepath.Join(dir, "connector-token.json"),
			nil,
		),
		grants:     NewGrantStore(filepath.Join(dir, "connector-grants.json")),
		queue:      NewQueue(time.Now, mkID, 120*time.Second),
		be:         be,
		prompt:     networkPrompt,
		now:        time.Now,
		pairCodes:  map[string]*pairEntry{},
		challenges: map[string]challengeEntry{},
	}
}

// accountRebinder is implemented by backends that track the active wallet
// account (e.g. *WalletBackend). It lets the API layer rebind the connector
// backend whenever the active wallet changes (unlock/activate/add). walletID
// identifies which wallet acct belongs to, so signing paths (WitnessTx) can
// detect a wallet switch that happens between resolving a request and
// executing it, and fail closed instead of using the wrong account.
type accountRebinder interface {
	SetAccount(walletID string, acct *wallet.Account)
}

// SetActiveAccount atomically updates the identity used for grants and rebinds
// the underlying backend when it supports accountRebinder. A nil account or an
// empty wallet ID clears the binding.
func (s *Service) SetActiveAccount(walletID string, acct *wallet.Account) {
	s.bindingMu.Lock()
	defer s.bindingMu.Unlock()

	s.identity = accountIdentity{}
	if walletID != "" && acct != nil {
		s.identity = accountIdentity{
			WalletID:     walletID,
			AccountIndex: acct.AccountIndex,
		}
	}
	if rb, ok := s.be.(accountRebinder); ok {
		rb.SetAccount(walletID, acct)
	}
}

func (s *Service) activeIdentity() (accountIdentity, bool) {
	s.bindingMu.RLock()
	defer s.bindingMu.RUnlock()
	return s.identity, s.identity.valid()
}

func (s *Service) grantedIdentity(origin string) (accountIdentity, bool) {
	s.bindingMu.RLock()
	defer s.bindingMu.RUnlock()
	if !s.identity.valid() || !s.grants.IsGranted(origin, s.identity) {
		return accountIdentity{}, false
	}
	return s.identity, true
}

func (s *Service) withCurrentGrant(
	ctx context.Context,
	origin string,
	fn func() (json.RawMessage, error),
) (json.RawMessage, error) {
	return s.withPairingAuthority(ctx, func() (json.RawMessage, error) {
		s.bindingMu.RLock()
		defer s.bindingMu.RUnlock()
		if !s.identity.valid() || !s.grants.IsGranted(origin, s.identity) {
			return nil, ErrNotGranted
		}
		return fn()
	})
}

func (s *Service) withExpectedIdentity(
	ctx context.Context,
	expected accountIdentity,
	origin string,
	requireGrant bool,
	fn func() (json.RawMessage, error),
) (json.RawMessage, error) {
	return s.withPairingAuthority(ctx, func() (json.RawMessage, error) {
		s.bindingMu.RLock()
		defer s.bindingMu.RUnlock()
		if !expected.valid() || s.identity != expected {
			return nil, ErrNotGranted
		}
		if requireGrant && !s.grants.IsGranted(origin, expected) {
			return nil, ErrNotGranted
		}
		return fn()
	})
}

// BeginPair generates a numeric pairing code for the given extensionID and
// caches it. The code is returned for display in the Bursa UI. It rejects a
// malformed extension ID and refuses to grow the pending map past
// maxPendingPairCodes (after pruning expired entries), so a flood of distinct
// IDs cannot exhaust memory. Repeated initiation for an unexpired extension
// returns its existing code, so a competing claimant cannot invalidate an
// in-progress browser pairing.
func (s *Service) BeginPair(extensionID string) (string, error) {
	extensionID = NormalizeExtensionID(extensionID)
	if !validExtensionID(extensionID) {
		return "", ErrInvalidExtensionID
	}
	s.pairMu.Lock()
	defer s.pairMu.Unlock()
	s.prunePairCodesLocked()
	if existing, exists := s.pairCodes[extensionID]; exists {
		return existing.code, nil
	}
	if len(s.pairCodes) >= maxPendingPairCodes {
		return "", ErrTooManyPairings
	}
	n, err := rand.Int(rand.Reader, big.NewInt(pairCodeMax))
	if err != nil {
		// A CSPRNG failure is a fatal system condition; never fall back to a
		// predictable code.
		panic(
			"connector: crypto/rand failure generating pair code: " + err.Error(),
		)
	}
	code := fmt.Sprintf("%0*d", pairCodeDigits, n.Int64())
	s.pairCodes[extensionID] = &pairEntry{code: code, created: s.now()}
	return code, nil
}

// BeginKeyPair binds a pending request to the extension key. The verification
// code must be compared in the extension and confirmed on the control surface.
func (s *Service) BeginKeyPair(extensionID, publicKey string) error {
	extensionID = NormalizeExtensionID(extensionID)
	if !validExtensionID(extensionID) {
		return ErrInvalidExtensionID
	}
	if _, err := parsePublicKey(publicKey); err != nil {
		return err
	}
	digest := sha256.Sum256([]byte("bursa-pair-v1\n" + publicKey))
	code := hex.EncodeToString(digest[:16])
	s.pairMu.Lock()
	defer s.pairMu.Unlock()
	s.prunePairCodesLocked()
	if entry, ok := s.pairCodes[extensionID]; ok {
		if entry.publicKey != publicKey {
			return ErrRefused
		}
		return nil
	}
	if len(s.pairCodes) >= maxPendingPairCodes {
		return ErrTooManyPairings
	}
	s.pairCodes[extensionID] = &pairEntry{code: code, publicKey: publicKey, created: s.now()}
	return nil
}

// ConfirmDesktopPair approves the exact key whose verification code the user
// compared with the independently displayed code in the extension.
func (s *Service) ConfirmDesktopPair(extensionID, code string) error {
	s.pairMu.Lock()
	entry := s.pairCodes[NormalizeExtensionID(extensionID)]
	key := ""
	if entry != nil {
		key = entry.publicKey
	}
	s.pairMu.Unlock()
	if key == "" {
		return ErrPairCodeMismatch
	}
	_, err := s.ConfirmPair(extensionID, code, key)
	return err
}

// TrustedPairingOrigin reports whether origin is the extension origin that
// extensionID names, after the same normalization BeginPair applies.
func (s *Service) TrustedPairingOrigin(origin, extensionID string) bool {
	extensionID = NormalizeExtensionID(extensionID)
	return validExtensionID(extensionID) && origin == extensionID
}

// ConfirmPair validates the code for extensionID, then binds the supplied
// public key to the extension. Returns ErrPairCodeMismatch if the code is wrong, expired, or
// has exhausted its attempt budget. The code is compared in constant time so a
// caller cannot learn a prefix from response timing.
func (s *Service) ConfirmPair(
	extensionID, code, publicKey string,
) (string, error) {
	extensionID = NormalizeExtensionID(extensionID)
	if _, err := parsePublicKey(publicKey); err != nil {
		return "", err
	}
	s.pairMu.Lock()
	entry, ok := s.pairCodes[extensionID]
	match := false
	if ok {
		if entry.publicKey != "" && entry.publicKey != publicKey {
			s.pairMu.Unlock()
			return "", ErrPairCodeMismatch
		}
		if s.now().Sub(entry.created) > pairCodeTTL {
			delete(s.pairCodes, extensionID)
		} else {
			entry.attempts++
			match = subtle.ConstantTimeCompare([]byte(entry.code), []byte(code)) == 1
			// Discard the code once it succeeds or exhausts its attempt budget so
			// it can be used at most once and cannot be ground down.
			if match || entry.attempts >= pairCodeMaxAttempts {
				delete(s.pairCodes, extensionID)
			}
		}
	}
	s.pairMu.Unlock()
	if !match {
		return "", ErrPairCodeMismatch
	}
	s.pairingMu.Lock()
	defer s.pairingMu.Unlock()
	oldExtensionID, _, paired := s.tokens.Pair()
	oldPublicKey := s.tokens.Authority()
	_, committed, err := s.tokens.mint(extensionID, publicKey)
	if committed {
		s.clearChallenges(oldExtensionID)
		if paired {
			s.queue.cancelAuthority(pairingAuthority{
				extensionID: oldExtensionID,
				publicKey:   oldPublicKey,
			})
		}
	}
	if err != nil {
		return "", err
	}
	return s.tokens.Authority(), nil
}

func (s *Service) clearChallenges(extensionID string) {
	s.challengeMu.Lock()
	defer s.challengeMu.Unlock()
	for value, entry := range s.challenges {
		if entry.extensionID == extensionID {
			entry.redeemed = true
			s.challenges[value] = entry
		}
	}
}

// IssueChallenge creates a short-lived, single-use request challenge for the
// currently paired extension.
func (s *Service) IssueChallenge(extensionID string) (string, error) {
	extensionID = NormalizeExtensionID(extensionID)
	pairedID, _, ok := s.tokens.Pair()
	if !ok || pairedID != extensionID {
		return "", ErrRefused
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("connector: challenge entropy: %w", err)
	}
	challenge := base64.RawURLEncoding.EncodeToString(raw)
	s.challengeMu.Lock()
	now := s.now()
	for value, entry := range s.challenges {
		if !entry.expires.After(now) {
			delete(s.challenges, value)
		}
	}
	if len(s.challenges) >= maxRequestChallenges {
		s.challengeMu.Unlock()
		return "", ErrChallengeCapacity
	}
	s.challenges[challenge] = challengeEntry{
		authority:   s.tokens.Authority(),
		extensionID: extensionID,
		value:       challenge,
		expires:     now.Add(requestChallengeTTL),
	}
	s.challengeMu.Unlock()
	return challenge, nil
}

// IssueSignedChallenge requires proof of the paired key before allocating a
// challenge. Repeated issuance proofs reuse their outstanding challenge.
func (s *Service) IssueSignedChallenge(extensionID, nonce, signature string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) != 32 {
		return "", ErrRefused
	}
	issuedMillis := binary.BigEndian.Uint64(raw[:8])
	if issuedMillis > math.MaxInt64 {
		return "", ErrRefused
	}
	issued := time.UnixMilli(int64(issuedMillis))
	if issued.After(s.now().Add(time.Second)) || !issued.Add(requestChallengeTTL).After(s.now()) {
		return "", ErrRefused
	}
	authority, valid := s.tokens.VerifySignature(extensionID, nonce, "POST", "/connector/challenge", nil, signature)
	if !valid {
		return "", ErrRefused
	}
	s.challengeMu.Lock()
	defer s.challengeMu.Unlock()
	now := s.now()
	for value, entry := range s.challenges {
		if !entry.expires.After(now) {
			delete(s.challenges, value)
		}
	}
	for _, entry := range s.challenges {
		if entry.issuanceNonce != nonce {
			continue
		}
		if entry.redeemed || entry.authority != authority {
			return "", ErrRefused
		}
		return entry.value, nil
	}
	if len(s.challenges) >= maxRequestChallenges {
		return "", ErrChallengeCapacity
	}
	randomChallenge := make([]byte, 32)
	if _, err := rand.Read(randomChallenge); err != nil {
		return "", fmt.Errorf("connector: challenge entropy: %w", err)
	}
	challenge := base64.RawURLEncoding.EncodeToString(randomChallenge)
	s.challenges[challenge] = challengeEntry{issuanceNonce: nonce, authority: authority, extensionID: NormalizeExtensionID(extensionID), value: challenge, expires: issued.Add(requestChallengeTTL)}
	return challenge, nil
}

// AuthorizeRequest verifies and consumes an extension request challenge. A
// challenge is valid for one exact method, path, and body only.
func (s *Service) AuthorizeRequest(
	extensionID, challenge, method, path string,
	body []byte,
	signature string,
) (string, bool) {
	extensionID = NormalizeExtensionID(extensionID)
	s.challengeMu.Lock()
	defer s.challengeMu.Unlock()
	entry, ok := s.challenges[challenge]
	if !ok {
		return "", false
	}
	if entry.redeemed {
		return "", false
	}
	entry.redeemed = true
	s.challenges[challenge] = entry
	if entry.extensionID != extensionID || entry.value != challenge || !entry.expires.After(s.now()) {
		return "", false
	}
	authority, valid := s.tokens.VerifySignature(
		extensionID, challenge, method, path, body, signature,
	)
	return authority, valid && authority == entry.authority
}

// prunePairCodesLocked removes expired pairing codes. Callers must hold pairMu.
func (s *Service) prunePairCodesLocked() {
	now := s.now()
	for id, entry := range s.pairCodes {
		if now.Sub(entry.created) > pairCodeTTL {
			delete(s.pairCodes, id)
		}
	}
}

// VerifyAuthority checks whether an admitted binding is still current.
func (s *Service) VerifyAuthority(publicKey, extensionID string) bool {
	return s.tokens.VerifyAuthority(publicKey, NormalizeExtensionID(extensionID))
}

// PairedExtensionID returns the currently paired extension ID and whether a
// pairing exists. It delegates to the token store's Pair method.
func (s *Service) PairedExtensionID() (string, bool) {
	extID, _, ok := s.tokens.Pair()
	return extID, ok
}

// Unpair clears the paired key, effectively disconnecting the extension.
func (s *Service) Unpair() error {
	s.pairingMu.Lock()
	defer s.pairingMu.Unlock()
	extensionID, _, paired := s.tokens.Pair()
	publicKey := s.tokens.Authority()
	err := s.tokens.Clear()
	s.clearChallenges(extensionID)
	if paired {
		s.queue.cancelAuthority(pairingAuthority{
			extensionID: extensionID,
			publicKey:   publicKey,
		})
	}
	return err
}

// Pending returns all requests currently awaiting a decision.
func (s *Service) Pending() []Request {
	return s.queue.Pending()
}

// Subscribe returns coalesced queue state-change notifications and an
// unsubscribe function. Consumers must refresh from Pending on notification.
func (s *Service) Subscribe() (<-chan struct{}, func()) {
	return s.queue.Subscribe()
}

// Decide resolves a pending request with the given Decision.
func (s *Service) Decide(id string, d Decision) error {
	return s.queue.Decide(id, d)
}

// Grants returns all currently granted origins.
func (s *Service) Grants() []string {
	s.bindingMu.RLock()
	defer s.bindingMu.RUnlock()
	return s.grants.List(s.identity)
}

// RevokeGrant removes the grant for the given origin.
func (s *Service) RevokeGrant(origin string) error {
	s.bindingMu.RLock()
	defer s.bindingMu.RUnlock()
	return s.grants.Revoke(origin, s.identity)
}

// PendingPairing holds an extension ID and its associated pairing code.
type PendingPairing struct {
	ExtensionID string `json:"extension_id"`
	Code        string `json:"code"`
}

// PendingPairings returns all pending (unconfirmed) pairing codes, dropping any
// that have expired.
func (s *Service) PendingPairings() []PendingPairing {
	s.pairMu.Lock()
	defer s.pairMu.Unlock()
	s.prunePairCodesLocked()
	out := make([]PendingPairing, 0, len(s.pairCodes))
	for extID, entry := range s.pairCodes {
		out = append(out, PendingPairing{ExtensionID: extID, Code: entry.code})
	}
	return out
}

// Handle is the primary dispatch method. It routes a CIP-30/CIP-95 method call
// to either an immediate Backend read (for granted origins) or a queued approval
// flow (for enable and signing methods).
func (s *Service) Handle(
	ctx context.Context,
	origin, method string,
	params json.RawMessage,
) (json.RawMessage, error) {
	if !validDAppOrigin(origin) {
		return nil, ErrInvalidOrigin
	}
	switch method {
	// isEnabled is a special case: returns a bool without requiring a grant.
	case "isEnabled":
		return s.withPairingAuthority(ctx, func() (json.RawMessage, error) {
			if _, ok := s.grantedIdentity(origin); ok {
				return json.RawMessage(`true`), nil
			}
			return json.RawMessage(`false`), nil
		})

	// enable: capture the identity being presented for consent, enqueue, then
	// grant only if that exact identity remains active after approval.
	case "enable":
		identity, ok := s.activeIdentity()
		if !ok {
			return nil, ErrNotGranted
		}
		return s.enqueueAndAwait(
			ctx,
			origin,
			method,
			params,
			func(d Decision) (json.RawMessage, error) {
				if !d.Approved {
					return nil, ErrUserDeclined
				}
				return s.withExpectedIdentity(
					ctx,
					identity,
					origin,
					false,
					func() (json.RawMessage, error) {
						if err := s.grants.Grant(origin, identity); err != nil {
							return nil, err
						}
						return json.RawMessage(`true`), nil
					},
				)
			},
		)

	// Read methods: require grant, call Backend immediately.
	case "getNetworkId":
		return s.withCurrentGrant(ctx, origin, func() (json.RawMessage, error) {
			return json.Marshal(s.be.NetworkID())
		})

	case "getBalance":
		return s.withCurrentGrant(ctx, origin, func() (json.RawMessage, error) {
			v, err := s.be.Balance(ctx)
			if err != nil {
				return nil, err
			}
			return json.Marshal(v)
		})

	case "getUtxos":
		identity, ok := s.grantedIdentity(origin)
		if !ok {
			return nil, ErrNotGranted
		}
		var p struct {
			Amount   string    `json:"amount"`
			Paginate *Paginate `json:"paginate"`
		}
		if err := unmarshalParams(params, &p); err != nil {
			return nil, err
		}
		return s.withExpectedIdentity(
			ctx,
			identity,
			origin,
			true,
			func() (json.RawMessage, error) {
				v, err := s.be.Utxos(ctx, p.Amount, p.Paginate)
				if err != nil {
					return nil, err
				}
				return json.Marshal(v)
			},
		)

	case "getCollateral":
		identity, ok := s.grantedIdentity(origin)
		if !ok {
			return nil, ErrNotGranted
		}
		var p struct {
			Amount string `json:"amount"`
		}
		if err := unmarshalParams(params, &p); err != nil {
			return nil, err
		}
		return s.withExpectedIdentity(
			ctx,
			identity,
			origin,
			true,
			func() (json.RawMessage, error) {
				v, err := s.be.Collateral(ctx, p.Amount)
				if err != nil {
					return nil, err
				}
				return json.Marshal(v)
			},
		)

	case "getUsedAddresses":
		identity, ok := s.grantedIdentity(origin)
		if !ok {
			return nil, ErrNotGranted
		}
		var p struct {
			Paginate *Paginate `json:"paginate"`
		}
		if err := unmarshalParams(params, &p); err != nil {
			return nil, err
		}
		return s.withExpectedIdentity(
			ctx,
			identity,
			origin,
			true,
			func() (json.RawMessage, error) {
				v, err := s.be.UsedAddresses(ctx, p.Paginate)
				if err != nil {
					return nil, err
				}
				return json.Marshal(v)
			},
		)

	case "getUnusedAddresses":
		return s.withCurrentGrant(ctx, origin, func() (json.RawMessage, error) {
			v, err := s.be.UnusedAddresses(ctx)
			if err != nil {
				return nil, err
			}
			return json.Marshal(v)
		})

	case "getChangeAddress":
		return s.withCurrentGrant(ctx, origin, func() (json.RawMessage, error) {
			v, err := s.be.ChangeAddress(ctx)
			if err != nil {
				return nil, err
			}
			return json.Marshal(v)
		})

	case "getRewardAddresses":
		return s.withCurrentGrant(ctx, origin, func() (json.RawMessage, error) {
			v, err := s.be.RewardAddresses(ctx)
			if err != nil {
				return nil, err
			}
			return json.Marshal(v)
		})

	// CIP-95 read methods.
	// NOTE: the injected.ts provider sends the "cip95." prefixed names below
	// (e.g. "cip95.getPubDRepKey"). These cases MUST match the exact strings
	// emitted by the provider; the bare-name aliases are kept for robustness.
	case "cip95.getPubDRepKey", "getPubDRepKey":
		identity, ok := s.grantedIdentity(origin)
		if !ok {
			return nil, ErrNotGranted
		}
		return s.enqueueAndAwait(
			ctx,
			origin,
			method,
			params,
			func(d Decision) (json.RawMessage, error) {
				if !d.Approved {
					return nil, ErrUserDeclined
				}
				return s.withExpectedIdentity(
					ctx,
					identity,
					origin,
					true,
					func() (json.RawMessage, error) {
						v, err := s.be.PubDRepKey(d.Password)
						if err != nil {
							return nil, err
						}
						return json.Marshal(v)
					},
				)
			},
		)

	case "cip95.getRegisteredPubStakeKeys", "getRegisteredPubStakeKeys":
		identity, ok := s.grantedIdentity(origin)
		if !ok {
			return nil, ErrNotGranted
		}
		return s.enqueueAndAwait(
			ctx,
			origin,
			method,
			params,
			func(d Decision) (json.RawMessage, error) {
				if !d.Approved {
					return nil, ErrUserDeclined
				}
				return s.withExpectedIdentity(
					ctx,
					identity,
					origin,
					true,
					func() (json.RawMessage, error) {
						v, err := s.be.RegisteredPubStakeKeys(d.Password)
						if err != nil {
							return nil, err
						}
						return json.Marshal(v)
					},
				)
			},
		)

	case "cip95.getUnregisteredPubStakeKeys", "getUnregisteredPubStakeKeys":
		identity, ok := s.grantedIdentity(origin)
		if !ok {
			return nil, ErrNotGranted
		}
		return s.enqueueAndAwait(
			ctx,
			origin,
			method,
			params,
			func(d Decision) (json.RawMessage, error) {
				if !d.Approved {
					return nil, ErrUserDeclined
				}
				return s.withExpectedIdentity(
					ctx,
					identity,
					origin,
					true,
					func() (json.RawMessage, error) {
						v, err := s.be.UnregisteredPubStakeKeys(d.Password)
						if err != nil {
							return nil, err
						}
						return json.Marshal(v)
					},
				)
			},
		)

	// Sign/submit methods: always enqueue (password required).
	case "signTx":
		identity, ok := s.grantedIdentity(origin)
		if !ok {
			return nil, ErrNotGranted
		}
		var p struct {
			Tx          string `json:"tx"`
			PartialSign bool   `json:"partialSign"`
		}
		if err := unmarshalRequiredParams(params, &p); err != nil {
			return nil, err
		}
		if p.Tx == "" {
			return nil, fmt.Errorf("%w: tx is required", ErrInvalidParams)
		}
		return s.inspectEnqueueAndAwait(
			ctx,
			origin,
			method,
			params,
			p.Tx,
			func(d Decision) (json.RawMessage, error) {
				if !d.Approved {
					return nil, ErrUserDeclined
				}
				return s.withExpectedIdentity(
					ctx,
					identity,
					origin,
					true,
					func() (json.RawMessage, error) {
						v, err := s.be.SignTx(
							ctx,
							p.Tx,
							p.PartialSign,
							d.Password,
						)
						if err != nil {
							return nil, err
						}
						return json.Marshal(v)
					},
				)
			},
		)

	case "signData":
		identity, ok := s.grantedIdentity(origin)
		if !ok {
			return nil, ErrNotGranted
		}
		var p struct {
			Addr string `json:"addr"`
			// Payload is a pointer so a present-but-empty value ("") — valid hex
			// for the empty byte sequence, which the backend signs — is accepted,
			// while an absent payload field is still rejected.
			Payload *string `json:"payload"`
		}
		if err := unmarshalRequiredParams(params, &p); err != nil {
			return nil, err
		}
		if p.Addr == "" || p.Payload == nil {
			return nil, fmt.Errorf(
				"%w: addr and payload are required",
				ErrInvalidParams,
			)
		}
		return s.enqueueAndAwait(
			ctx,
			origin,
			method,
			params,
			func(d Decision) (json.RawMessage, error) {
				if !d.Approved {
					return nil, ErrUserDeclined
				}
				return s.withExpectedIdentity(
					ctx,
					identity,
					origin,
					true,
					func() (json.RawMessage, error) {
						sig, key, err := s.be.SignData(
							p.Addr,
							*p.Payload,
							d.Password,
						)
						if err != nil {
							return nil, err
						}
						return json.Marshal(
							map[string]string{"signature": sig, "key": key},
						)
					},
				)
			},
		)

	case "submitTx":
		identity, ok := s.grantedIdentity(origin)
		if !ok {
			return nil, ErrNotGranted
		}
		var p struct {
			Tx string `json:"tx"`
		}
		if err := unmarshalRequiredParams(params, &p); err != nil {
			return nil, err
		}
		if p.Tx == "" {
			return nil, fmt.Errorf("%w: tx is required", ErrInvalidParams)
		}
		return s.enqueueAndAwait(
			ctx,
			origin,
			method,
			params,
			func(d Decision) (json.RawMessage, error) {
				if !d.Approved {
					return nil, ErrUserDeclined
				}
				return s.withExpectedIdentity(
					ctx,
					identity,
					origin,
					true,
					func() (json.RawMessage, error) {
						v, err := s.be.SubmitTx(ctx, p.Tx)
						if err != nil {
							return nil, err
						}
						return json.Marshal(v)
					},
				)
			},
		)

	default:
		return nil, ErrRefused
	}
}

// HandleAuthorized dispatches a connector request under the exact pairing
// key admitted by the HTTP boundary. Queued work revalidates that key after
// approval so unpairing or re-pairing cannot leave an older request executable.
func (s *Service) HandleAuthorized(
	ctx context.Context,
	extensionID, publicKey, origin, method string,
	params json.RawMessage,
) (json.RawMessage, error) {
	extensionID = NormalizeExtensionID(extensionID)
	s.pairingMu.RLock()
	if !s.tokens.VerifyAuthority(publicKey, extensionID) {
		s.pairingMu.RUnlock()
		return nil, ErrRefused
	}
	s.pairingMu.RUnlock()
	ctx = context.WithValue(
		ctx,
		pairingAuthorityContextKey{},
		pairingAuthority{extensionID: extensionID, publicKey: publicKey},
	)
	return s.Handle(ctx, origin, method, params)
}

// unmarshalParams decodes the optional raw JSON params into dst. A nil/empty
// params block is accepted (methods fall back to their zero-value defaults), but
// a non-nil block that fails to unmarshal is rejected with ErrInvalidParams so
// malformed input is never silently coerced into unintended defaults.
func unmarshalParams(params json.RawMessage, dst any) error {
	if len(params) == 0 {
		return nil
	}
	if err := json.Unmarshal(params, dst); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidParams, err)
	}
	return nil
}

func unmarshalRequiredParams(params json.RawMessage, dst any) error {
	if len(params) == 0 || string(params) == "null" {
		return fmt.Errorf("%w: params are required", ErrInvalidParams)
	}
	return unmarshalParams(params, dst)
}

func pairingAuthorityFromContext(
	ctx context.Context,
) (pairingAuthority, bool) {
	authority, ok := ctx.Value(pairingAuthorityContextKey{}).(pairingAuthority)
	return authority, ok
}

func (s *Service) withPairingAuthority(
	ctx context.Context,
	fn func() (json.RawMessage, error),
) (json.RawMessage, error) {
	authority, ok := pairingAuthorityFromContext(ctx)
	if !ok {
		return fn()
	}
	// Keep the read lock through the protected operation so key revocation
	// cannot return while work admitted under that key is still running.
	s.pairingMu.RLock()
	defer s.pairingMu.RUnlock()
	if !s.tokens.VerifyAuthority(authority.publicKey, authority.extensionID) {
		return nil, ErrRefused
	}
	return fn()
}

func (s *Service) submit(
	ctx context.Context,
	origin, method string,
	params json.RawMessage,
) (*Request, error) {
	authority, ok := pairingAuthorityFromContext(ctx)
	if !ok {
		return s.queue.Submit(origin, method, params)
	}
	s.pairingMu.RLock()
	defer s.pairingMu.RUnlock()
	if !s.tokens.VerifyAuthority(authority.publicKey, authority.extensionID) {
		return nil, ErrRefused
	}
	return s.queue.submitAuthorized(origin, method, params, authority)
}

func (s *Service) reserve(
	ctx context.Context,
	origin, method string,
	params json.RawMessage,
) (*Request, error) {
	authority, ok := pairingAuthorityFromContext(ctx)
	if !ok {
		return s.queue.reserve(origin, method, params)
	}
	s.pairingMu.RLock()
	defer s.pairingMu.RUnlock()
	if !s.tokens.VerifyAuthority(authority.publicKey, authority.extensionID) {
		return nil, ErrRefused
	}
	return s.queue.reserveAuthorized(origin, method, params, authority)
}

// enqueueAndAwait submits a request to the queue, optionally calls the
// networkPrompt, then blocks until a Decision arrives and passes it to fn.
func (s *Service) enqueueAndAwait(
	ctx context.Context,
	origin, method string,
	params json.RawMessage,
	fn func(Decision) (json.RawMessage, error),
) (json.RawMessage, error) {
	req, err := s.submit(ctx, origin, method, params)
	if err != nil {
		return nil, err
	}
	return s.promptAndAwait(ctx, req, fn)
}

func (s *Service) inspectEnqueueAndAwait(
	ctx context.Context,
	origin, method string,
	params json.RawMessage,
	txHex string,
	fn func(Decision) (json.RawMessage, error),
) (json.RawMessage, error) {
	req, err := s.reserve(ctx, origin, method, params)
	if err != nil {
		return nil, err
	}
	effects, err := s.be.InspectTx(ctx, txHex)
	if err != nil {
		s.queue.cancelReservation(req.ID)
		return nil, fmt.Errorf(
			"%w: transaction effects unavailable: %w",
			ErrInvalidParams,
			err,
		)
	}
	reservedID := req.ID
	req, err = s.queue.publish(reservedID, &effects)
	if err != nil {
		s.queue.cancelReservation(reservedID)
		return nil, err
	}
	return s.promptAndAwait(ctx, req, fn)
}

func (s *Service) promptAndAwait(
	ctx context.Context,
	req *Request,
	fn func(Decision) (json.RawMessage, error),
) (json.RawMessage, error) {
	if s.prompt != nil {
		s.prompt()
	}
	d, err := s.queue.Await(ctx, req.ID)
	if err != nil {
		return nil, err
	}
	return fn(d)
}

// ApproveSubmission places an already-validated, fully signed transaction in
// the wallet's approval queue and runs submit only after an explicit approval.
// This narrow entry point is for Bursa's remote submission listener: it grants
// no wallet identity, read access, signing operation, or key capability.
func (s *Service) ApproveSubmission(
	ctx context.Context,
	origin string,
	params json.RawMessage,
	submit func(context.Context) (string, error),
) (string, error) {
	if submit == nil {
		return "", ErrRefused
	}
	result, err := s.enqueueAndAwait(
		ctx,
		origin,
		"remoteSubmitTx",
		params,
		func(d Decision) (json.RawMessage, error) {
			if !d.Approved {
				return nil, ErrUserDeclined
			}
			hash, err := submit(ctx)
			if err != nil {
				return nil, err
			}
			return json.Marshal(hash)
		},
	)
	if err != nil {
		return "", err
	}
	var hash string
	if err := json.Unmarshal(result, &hash); err != nil {
		return "", err
	}
	return hash, nil
}
