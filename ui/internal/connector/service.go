package connector

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"sync"
	"time"

	"github.com/blinklabs-io/bursa/ui/internal/wallet"
)

// Sentinel errors returned by Service.
var (
	ErrRefused          = errors.New("connector: refused")
	ErrUserDeclined     = errors.New("connector: user declined")
	ErrNotGranted       = errors.New("connector: origin not granted")
	ErrPairCodeMismatch = errors.New("connector: pair code mismatch")
	ErrInvalidParams    = errors.New("connector: invalid request params")
	ErrInvalidOrigin    = errors.New("connector: invalid origin")
)

const (
	pairCodeDigits = 12
	pairCodeMax    = 1_000_000_000_000
)

// Paginate is used by the Utxos backend method.
type Paginate struct {
	Page  int
	Limit int
}

// Backend is the wallet capability interface that Phase 2 implements.
type Backend interface {
	NetworkID() int
	Utxos(ctx context.Context, amount string, paginate *Paginate) ([]string, error)
	Balance(ctx context.Context) (string, error)
	UsedAddresses(ctx context.Context, paginate *Paginate) ([]string, error)
	UnusedAddresses(ctx context.Context) ([]string, error)
	ChangeAddress(ctx context.Context) (string, error)
	RewardAddresses(ctx context.Context) ([]string, error)
	Collateral(ctx context.Context, amount string) ([]string, error)
	SignTx(ctx context.Context, txHex string, partialSign bool, password string) (string, error)
	SignData(addrHex, payloadHex, password string) (sig, key string, err error)
	SubmitTx(ctx context.Context, txHex string) (string, error)
	PubDRepKey(password string) (string, error)
	RegisteredPubStakeKeys(password string) ([]string, error)
	UnregisteredPubStakeKeys(password string) ([]string, error)
}

// Service orchestrates the three connector stores (token, grants, queue) and
// routes incoming CIP-30 / CIP-95 method calls to the Backend.
type Service struct {
	tokens *TokenStore
	grants *GrantStore
	queue  *Queue
	be     Backend
	prompt func()

	// pending pair codes: extensionID → numeric string
	pairMu    sync.Mutex
	pairCodes map[string]string
}

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
		tokens:    NewTokenStore(filepath.Join(dir, "connector-token.json"), nil),
		grants:    NewGrantStore(filepath.Join(dir, "connector-grants.json")),
		queue:     NewQueue(time.Now, mkID, 120*time.Second),
		be:        be,
		prompt:    networkPrompt,
		pairCodes: map[string]string{},
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

// SetActiveAccount rebinds the underlying backend to the active wallet's
// account if the backend supports it (implements accountRebinder). Backends
// that do not track an account (e.g. test fakes) are left untouched. A nil
// account clears the binding.
func (s *Service) SetActiveAccount(walletID string, acct *wallet.Account) {
	if rb, ok := s.be.(accountRebinder); ok {
		rb.SetAccount(walletID, acct)
	}
}

// BeginPair generates a numeric pairing code for the given extensionID and
// caches it. The code is returned for display in the Bursa UI.
func (s *Service) BeginPair(extensionID string) string {
	extensionID = normalizeExtensionID(extensionID)
	n, err := rand.Int(rand.Reader, big.NewInt(pairCodeMax))
	if err != nil {
		// A CSPRNG failure is a fatal system condition; never fall back to a
		// predictable code.
		panic("connector: crypto/rand failure generating pair code: " + err.Error())
	}
	code := fmt.Sprintf("%0*d", pairCodeDigits, n.Int64())
	s.pairMu.Lock()
	s.pairCodes[extensionID] = code
	s.pairMu.Unlock()
	return code
}

// ConfirmPair validates the code for extensionID, then mints and returns a
// bearer token. Returns ErrPairCodeMismatch if the code is wrong.
func (s *Service) ConfirmPair(extensionID, code string) (string, error) {
	extensionID = normalizeExtensionID(extensionID)
	s.pairMu.Lock()
	expected, ok := s.pairCodes[extensionID]
	if ok && expected == code {
		delete(s.pairCodes, extensionID)
	}
	s.pairMu.Unlock()
	if !ok || expected != code {
		return "", ErrPairCodeMismatch
	}
	return s.tokens.Mint(extensionID)
}

// VerifyToken checks whether the bearer token is valid for the given extensionID.
func (s *Service) VerifyToken(token, extensionID string) bool {
	return s.tokens.Verify(token, normalizeExtensionID(extensionID))
}

// PairedExtensionID returns the currently paired extension ID and whether a
// pairing exists. It delegates to the token store's Pair method.
func (s *Service) PairedExtensionID() (string, bool) {
	extID, _, ok := s.tokens.Pair()
	return extID, ok
}

// Unpair clears the paired token, effectively disconnecting the extension.
func (s *Service) Unpair() error {
	return s.tokens.Clear()
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
	return s.grants.List()
}

// RevokeGrant removes the grant for the given origin.
func (s *Service) RevokeGrant(origin string) error {
	return s.grants.Revoke(origin)
}

// PendingPairing holds an extension ID and its associated pairing code.
type PendingPairing struct {
	ExtensionID string `json:"extension_id"`
	Code        string `json:"code"`
}

// PendingPairings returns all pending (unconfirmed) pairing codes.
func (s *Service) PendingPairings() []PendingPairing {
	s.pairMu.Lock()
	defer s.pairMu.Unlock()
	out := make([]PendingPairing, 0, len(s.pairCodes))
	for extID, code := range s.pairCodes {
		out = append(out, PendingPairing{ExtensionID: extID, Code: code})
	}
	return out
}

// Handle is the primary dispatch method. It routes a CIP-30/CIP-95 method call
// to either an immediate Backend read (for granted origins) or a queued approval
// flow (for enable and signing methods).
func (s *Service) Handle(ctx context.Context, origin, method string, params json.RawMessage) (json.RawMessage, error) {
	if !validDAppOrigin(origin) {
		return nil, ErrInvalidOrigin
	}
	switch method {
	// isEnabled is a special case: returns a bool without requiring a grant.
	case "isEnabled":
		if s.grants.IsGranted(origin) {
			return json.RawMessage(`true`), nil
		}
		return json.RawMessage(`false`), nil

	// enable: enqueue, await decision, then grant on approval.
	case "enable":
		return s.enqueueAndAwait(ctx, origin, method, params, func(d Decision) (json.RawMessage, error) {
			if !d.Approved {
				return nil, ErrUserDeclined
			}
			if err := s.grants.Grant(origin); err != nil {
				return nil, err
			}
			return json.RawMessage(`true`), nil
		})

	// Read methods: require grant, call Backend immediately.
	case "getNetworkId":
		if !s.grants.IsGranted(origin) {
			return nil, ErrNotGranted
		}
		return json.Marshal(s.be.NetworkID())

	case "getBalance":
		if !s.grants.IsGranted(origin) {
			return nil, ErrNotGranted
		}
		v, err := s.be.Balance(ctx)
		if err != nil {
			return nil, err
		}
		return json.Marshal(v)

	case "getUtxos":
		if !s.grants.IsGranted(origin) {
			return nil, ErrNotGranted
		}
		var p struct {
			Amount   string    `json:"amount"`
			Paginate *Paginate `json:"paginate"`
		}
		if err := unmarshalParams(params, &p); err != nil {
			return nil, err
		}
		v, err := s.be.Utxos(ctx, p.Amount, p.Paginate)
		if err != nil {
			return nil, err
		}
		return json.Marshal(v)

	case "getCollateral":
		if !s.grants.IsGranted(origin) {
			return nil, ErrNotGranted
		}
		var p struct {
			Amount string `json:"amount"`
		}
		if err := unmarshalParams(params, &p); err != nil {
			return nil, err
		}
		v, err := s.be.Collateral(ctx, p.Amount)
		if err != nil {
			return nil, err
		}
		return json.Marshal(v)

	case "getUsedAddresses":
		if !s.grants.IsGranted(origin) {
			return nil, ErrNotGranted
		}
		var p struct {
			Paginate *Paginate `json:"paginate"`
		}
		if err := unmarshalParams(params, &p); err != nil {
			return nil, err
		}
		v, err := s.be.UsedAddresses(ctx, p.Paginate)
		if err != nil {
			return nil, err
		}
		return json.Marshal(v)

	case "getUnusedAddresses":
		if !s.grants.IsGranted(origin) {
			return nil, ErrNotGranted
		}
		v, err := s.be.UnusedAddresses(ctx)
		if err != nil {
			return nil, err
		}
		return json.Marshal(v)

	case "getChangeAddress":
		if !s.grants.IsGranted(origin) {
			return nil, ErrNotGranted
		}
		v, err := s.be.ChangeAddress(ctx)
		if err != nil {
			return nil, err
		}
		return json.Marshal(v)

	case "getRewardAddresses":
		if !s.grants.IsGranted(origin) {
			return nil, ErrNotGranted
		}
		v, err := s.be.RewardAddresses(ctx)
		if err != nil {
			return nil, err
		}
		return json.Marshal(v)

	// CIP-95 read methods.
	// NOTE: the injected.ts provider sends the "cip95." prefixed names below
	// (e.g. "cip95.getPubDRepKey"). These cases MUST match the exact strings
	// emitted by the provider; the bare-name aliases are kept for robustness.
	case "cip95.getPubDRepKey", "getPubDRepKey":
		if !s.grants.IsGranted(origin) {
			return nil, ErrNotGranted
		}
		return s.enqueueAndAwait(ctx, origin, method, params, func(d Decision) (json.RawMessage, error) {
			if !d.Approved {
				return nil, ErrUserDeclined
			}
			v, err := s.be.PubDRepKey(d.Password)
			if err != nil {
				return nil, err
			}
			return json.Marshal(v)
		})

	case "cip95.getRegisteredPubStakeKeys", "getRegisteredPubStakeKeys":
		if !s.grants.IsGranted(origin) {
			return nil, ErrNotGranted
		}
		return s.enqueueAndAwait(ctx, origin, method, params, func(d Decision) (json.RawMessage, error) {
			if !d.Approved {
				return nil, ErrUserDeclined
			}
			v, err := s.be.RegisteredPubStakeKeys(d.Password)
			if err != nil {
				return nil, err
			}
			return json.Marshal(v)
		})

	case "cip95.getUnregisteredPubStakeKeys", "getUnregisteredPubStakeKeys":
		if !s.grants.IsGranted(origin) {
			return nil, ErrNotGranted
		}
		return s.enqueueAndAwait(ctx, origin, method, params, func(d Decision) (json.RawMessage, error) {
			if !d.Approved {
				return nil, ErrUserDeclined
			}
			v, err := s.be.UnregisteredPubStakeKeys(d.Password)
			if err != nil {
				return nil, err
			}
			return json.Marshal(v)
		})

	// Sign/submit methods: always enqueue (password required).
	case "signTx":
		if !s.grants.IsGranted(origin) {
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
		return s.enqueueAndAwait(ctx, origin, method, params, func(d Decision) (json.RawMessage, error) {
			if !d.Approved {
				return nil, ErrUserDeclined
			}
			v, err := s.be.SignTx(ctx, p.Tx, p.PartialSign, d.Password)
			if err != nil {
				return nil, err
			}
			return json.Marshal(v)
		})

	case "signData":
		if !s.grants.IsGranted(origin) {
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
			return nil, fmt.Errorf("%w: addr and payload are required", ErrInvalidParams)
		}
		return s.enqueueAndAwait(ctx, origin, method, params, func(d Decision) (json.RawMessage, error) {
			if !d.Approved {
				return nil, ErrUserDeclined
			}
			sig, key, err := s.be.SignData(p.Addr, *p.Payload, d.Password)
			if err != nil {
				return nil, err
			}
			return json.Marshal(map[string]string{"signature": sig, "key": key})
		})

	case "submitTx":
		if !s.grants.IsGranted(origin) {
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
		return s.enqueueAndAwait(ctx, origin, method, params, func(d Decision) (json.RawMessage, error) {
			if !d.Approved {
				return nil, ErrUserDeclined
			}
			v, err := s.be.SubmitTx(ctx, p.Tx)
			if err != nil {
				return nil, err
			}
			return json.Marshal(v)
		})

	default:
		return nil, ErrRefused
	}
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

// enqueueAndAwait submits a request to the queue, optionally calls the
// networkPrompt, then blocks until a Decision arrives and passes it to fn.
func (s *Service) enqueueAndAwait(
	ctx context.Context,
	origin, method string,
	params json.RawMessage,
	fn func(Decision) (json.RawMessage, error),
) (json.RawMessage, error) {
	req, err := s.queue.Submit(origin, method, params)
	if err != nil {
		return nil, err
	}
	if s.prompt != nil {
		s.prompt()
	}
	d, err := s.queue.Await(ctx, req.ID)
	if err != nil {
		return nil, err
	}
	return fn(d)
}
