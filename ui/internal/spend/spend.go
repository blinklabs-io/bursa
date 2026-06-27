// Package spend builds and holds unsigned Cardano send transactions using the
// Apollo tx-builder. A two-step Build→Confirm flow lets the caller preview the
// transaction before committing the spend password to decrypt the signing keys.
package spend

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	apollo "github.com/blinklabs-io/apollo/v2"
	"github.com/blinklabs-io/apollo/v2/backend"
	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/bip32"
	"github.com/blinklabs-io/bursa/ui/internal/keystore"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// ErrNoWallet is returned when Build is called without a wallet account configured.
// Sentinel errors. The API layer maps these to HTTP status codes; callers can
// match them with errors.Is. Service methods wrap them with context.
var (
	// ErrNoWallet: no spending wallet configured yet (→ 409).
	ErrNoWallet = errors.New("no wallet set")
	// ErrInvalidRequest: a malformed recipient, amount, or asset (→ 400).
	ErrInvalidRequest = errors.New("invalid send request")
	// ErrInsufficientFunds: coin selection / balancing could not fund the send (→ 422).
	ErrInsufficientFunds = errors.New("insufficient funds")
	// ErrWrongPassword: keystore authentication failed with the supplied password (→ 401).
	ErrWrongPassword = errors.New("incorrect spending password")
	// ErrUnknownPending: no pending transaction for the given id (→ 404).
	ErrUnknownPending = errors.New("unknown pending id")
	// ErrExpiredPending: the pending transaction existed but its TTL elapsed (→ 410).
	ErrExpiredPending = errors.New("expired pending id")
	// ErrSubmitRejected: the node rejected the signed transaction; the wrapped
	// message carries its structured reason (→ 422).
	ErrSubmitRejected = errors.New("transaction rejected by node")
)

// pendingTTL bounds how long a built-but-unconfirmed transaction is held. After
// it elapses the preview's UTxOs/params may be stale, so Confirm rejects it.
const pendingTTL = 5 * time.Minute

// Asset represents a native asset unit + quantity within a send request or output.
type Asset struct {
	Unit string `json:"unit"` // policyId (56 hex chars) + assetName (hex)
	// Quantity is a decimal string, not a JSON number, so uint64 values beyond
	// the JS safe-integer range (2^53) survive the round-trip to the browser
	// without precision loss — matching the read-side balance API.
	Quantity string `json:"quantity"`
}

// SendRequest is the caller-supplied parameters for a single send.
type SendRequest struct {
	To       string  `json:"to"`
	Lovelace string  `json:"lovelace"` // decimal lovelace string; see Asset.Quantity
	Assets   []Asset `json:"assets,omitempty"`
}

// Output is one output as presented in the preview.
type Output struct {
	Address  string  `json:"address"`
	Lovelace string  `json:"lovelace"` // decimal lovelace string; see Asset.Quantity
	Assets   []Asset `json:"assets,omitempty"`
}

// Preview is returned from Build: all data the caller needs to present a
// confirmation screen. PendingID is the opaque token to pass to Confirm.
type Preview struct {
	PendingID string   `json:"pending_id"`
	Inputs    []string `json:"inputs"` // "txhash#index" of selected inputs
	Outputs   []Output `json:"outputs"`
	Fee       string   `json:"fee"`    // decimal lovelace string; see Asset.Quantity
	Change    string   `json:"change"` // decimal lovelace string ("0" if absorbed as fee)
}

// TxResult is returned from Confirm after successful submission.
type TxResult struct {
	TxHash string `json:"tx_hash"`
}

// Keystore is the minimal interface satisfied by *keystore.Keystore. It is
// accepted as an interface so the service can be constructed with a nil keystore
// when only Build is needed, and faked in tests.
type Keystore interface {
	Exists() bool
	Create(mnemonic, password string) error
	Unlock(password string) (mnemonic []byte, err error)
}

// addressWindow is the number of external (receive) addresses derived for a
// spending account. It matches the read-only wallet's default window so the
// derived addresses (and their indices) line up for signing.
const addressWindow = 20

// feePaddingLovelace is added to Apollo's estimated fee to cover the witness
// bytes attached after Complete() (see Build). The observed shortfall is a few
// hundred lovelace; 1000 leaves comfortable headroom while staying negligible.
const feePaddingLovelace = 1000

// pending holds a completed but unsigned tx while awaiting Confirm.
type pending struct {
	tx       *apollo.Apollo
	utxoAddr map[string]string // "txhash#index" → bech32 address (for signing)
	created  time.Time
}

// Service builds and holds pending send transactions.
type Service struct {
	chain   backend.ChainContext
	keys    Keystore // may be nil for build-only usage
	account *wallet.Account
	mkID    func() string    // pending id generator; injectable for tests
	now     func() time.Time // injectable for tests

	mu      sync.Mutex
	pending map[string]*pending
}

// NewService constructs a Service. ks may be nil if only Build (not Confirm) is needed.
func NewService(cc backend.ChainContext, ks Keystore, acct *wallet.Account) *Service {
	return &Service{
		chain:   cc,
		keys:    ks,
		account: acct,
		pending: make(map[string]*pending),
		mkID:    randID,
		now:     time.Now,
	}
}

// SetWallet enables spending: it derives the CIP-1852 account for the mnemonic
// and network, encrypts the mnemonic into the keystore under password, and
// records the account so Build/Confirm can run. If a keystore already exists
// (e.g. after a restart) it is not overwritten - the password must unlock it
// and the supplied mnemonic must match before re-attaching to the existing wallet.
// The derived account is returned for display.
func (s *Service) SetWallet(mnemonic, network, password string) (*wallet.Account, error) {
	if s.keys == nil {
		return nil, errors.New("no keystore configured")
	}
	var acct *wallet.Account
	if s.keys.Exists() {
		mn, err := s.keys.Unlock(password)
		if err != nil {
			return nil, err
		}
		defer func() {
			for i := range mn {
				mn[i] = 0
			}
		}()
		if !bytes.Equal(mn, []byte(mnemonic)) {
			return nil, errors.New("mnemonic does not match existing keystore")
		}
		acct, err = wallet.Derive(string(mn), network, addressWindow)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		acct, err = wallet.Derive(mnemonic, network, addressWindow)
		if err != nil {
			return nil, err
		}
		if err := s.keys.Create(mnemonic, password); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	s.account = acct
	s.mu.Unlock()
	return acct, nil
}

// currentAccount returns the active account under lock (nil if none is set).
func (s *Service) currentAccount() *wallet.Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.account
}

// Build runs coin selection and fee estimation for req using Apollo, stores the
// incomplete tx under a new pending id, and returns a Preview for user approval.
func (s *Service) Build(ctx context.Context, req SendRequest) (Preview, error) {
	acct := s.currentAccount()
	if acct == nil {
		return Preview{}, ErrNoWallet
	}
	if len(acct.ReceiveAddresses) == 0 {
		return Preview{}, errors.New("account has no receive addresses")
	}

	// Parse the change address (first receive address is used for change).
	changeAddr, err := lcommon.NewAddress(acct.ReceiveAddresses[0])
	if err != nil {
		return Preview{}, fmt.Errorf("change address: %w", err)
	}

	// Construct a watch-only Apollo builder with an ExternalWallet.
	// ExternalWallet implements the Wallet interface; Complete() accepts it
	// because it only needs Address() for the change output — it does not call Sign().
	//
	// SetFeePadding: Complete() estimates the fee before the vkey witness is
	// attached at Confirm() time, so the estimate runs a few bytes (and thus a
	// couple hundred lovelace) under the node's calculated minimum — the node
	// then rejects the tx ("fee X is less than the calculated minimum fee Y").
	// A small fixed padding reserves the shortfall during coin selection; it is
	// taken from change, costing the sender a negligible (<0.001 ADA) amount.
	a := apollo.New(s.chain).
		SetWallet(apollo.NewExternalWallet(changeAddr)).
		SetChangeAddress(changeAddr).
		SetFeePadding(feePaddingLovelace)

	// Load spendable UTxOs from every receive address; record txref→address for
	// later signing. We pre-load them so Apollo's coin selection can see them
	// without needing a live chain query inside Complete().
	utxoAddr := make(map[string]string)
	for _, addrStr := range acct.ReceiveAddresses {
		addr, err := lcommon.NewAddress(addrStr)
		if err != nil {
			return Preview{}, fmt.Errorf("address %q: %w", addrStr, err)
		}
		utxos, err := s.chain.Utxos(ctx, addr)
		if err != nil {
			return Preview{}, fmt.Errorf("utxos for %s: %w", addrStr, err)
		}
		if len(utxos) > 0 {
			a = a.AddLoadedUTxOs(utxos...)
			for _, u := range utxos {
				utxoAddr[makeUtxoRef(u)] = addrStr
			}
		}
	}

	// Add the recipient payment.
	recvAddr, err := lcommon.NewAddress(req.To)
	if err != nil {
		return Preview{}, fmt.Errorf("%w: recipient %q: %w", ErrInvalidRequest, req.To, err)
	}
	units, err := assetsToUnits(req.Assets)
	if err != nil {
		return Preview{}, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	lovelace, err := parseAmount(req.Lovelace)
	if err != nil {
		return Preview{}, fmt.Errorf("%w: lovelace: %w", ErrInvalidRequest, err)
	}
	a = a.PayToAddress(recvAddr, int64(lovelace), units...) //nolint:gosec // validated by parseAmount

	// Complete: coin selection + fee estimation.
	a, err = a.CompleteContext(ctx)
	if err != nil {
		if isInsufficientFundsError(err) {
			return Preview{}, fmt.Errorf("%w: %w", ErrInsufficientFunds, err)
		}
		return Preview{}, fmt.Errorf("complete transaction: %w", err)
	}

	// Store the pending entry (sweeping any that have outlived their TTL first).
	id := s.mkID()
	s.mu.Lock()
	s.sweepExpiredLocked()
	s.pending[id] = &pending{tx: a, utxoAddr: utxoAddr, created: s.now()}
	s.mu.Unlock()

	return toPreview(id, a), nil
}

// SignData signs an arbitrary message with the wallet key for one of the
// wallet's own addresses, producing a CIP-8 / CIP-30 signData result: a
// COSE_Sign1 signature and the COSE_Key, both hex-encoded. It requires the
// spending password (to unlock the keystore) but no node — message signing is
// fully offline. The address must be within the wallet's derived address window
// so the matching signing key can be derived; the COSE wrapping itself lives in
// the bursa keys layer (bursa.SignData).
func (s *Service) SignData(addrStr string, message []byte, password string) (signatureHex, keyHex string, err error) {
	if s.keys == nil {
		return "", "", errors.New("no keystore configured")
	}
	acct := s.currentAccount()
	if acct == nil {
		return "", "", ErrNoWallet
	}
	// The address must be one this wallet owns: a derived receive address (signed
	// by the payment key at its window index) or the account's reward/stake
	// address (signed by the staking key). CIP-30 signData is used with both, and
	// bursa.SignData validates the address-vs-vkey correspondence either way.
	idx := -1
	for i, a := range acct.ReceiveAddresses {
		if a == addrStr {
			idx = i
			break
		}
	}
	isStake := addrStr == acct.StakeAddress
	if idx < 0 && !isStake {
		return "", "", fmt.Errorf(
			"%w: address %q is not one this wallet owns",
			ErrInvalidRequest, addrStr,
		)
	}
	addr, err := lcommon.NewAddress(addrStr)
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	addrBytes, err := addr.Bytes()
	if err != nil {
		return "", "", fmt.Errorf("%w: address bytes: %w", ErrInvalidRequest, err)
	}

	mnemonicBytes, err := s.keys.Unlock(password)
	if err != nil {
		if errors.Is(err, keystore.ErrDecryptFailed) {
			return "", "", fmt.Errorf("%w: %w", ErrWrongPassword, err)
		}
		return "", "", fmt.Errorf("unlock keystore: %w", err)
	}
	// The mnemonic and the derived XPrvs (bip32.XPrv is []byte) all hold secret
	// material; zero them on every exit, including the error paths below. lk.SKey
	// aliases signKey, so this also clears the key handed to bursa.SignData.
	var rootKey, acctKey, signKey bip32.XPrv
	defer func() {
		for _, k := range []bip32.XPrv{rootKey, acctKey, signKey} {
			for i := range k {
				k[i] = 0
			}
		}
		for i := range mnemonicBytes {
			mnemonicBytes[i] = 0
		}
	}()

	rootKey, err = bursa.GetRootKeyFromMnemonic(string(mnemonicBytes), "")
	if err != nil {
		return "", "", fmt.Errorf("root key: %w", err)
	}
	acctKey, err = bursa.GetAccountKey(rootKey, 0)
	if err != nil {
		return "", "", fmt.Errorf("account key: %w", err)
	}
	if isStake {
		signKey, err = bursa.GetStakeKey(acctKey, 0)
	} else {
		signKey, err = bursa.GetPaymentKey(acctKey, uint32(idx)) //nolint:gosec // bounded by window size
	}
	if err != nil {
		return "", "", fmt.Errorf("derive signing key: %w", err)
	}
	// signerForKey accepts a 96-byte bip32 XPrv as SKey.
	lk := &bursa.LoadedKey{SKey: []byte(signKey)}
	return bursa.SignData(addrBytes, message, lk)
}

// sweepExpiredLocked drops pending entries past their TTL. Callers hold s.mu.
func (s *Service) sweepExpiredLocked() {
	now := s.now()
	for id, p := range s.pending {
		if now.Sub(p.created) > pendingTTL {
			delete(s.pending, id)
		}
	}
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// makeUtxoRef returns the canonical "txhash#index" reference for a UTxO.
// This mirrors apollo's private utxoRef function.
func makeUtxoRef(u lcommon.Utxo) string {
	return hex.EncodeToString(u.Id.Id().Bytes()) + "#" + strconv.Itoa(int(u.Id.Index()))
}

// assetsToUnits converts the service's Asset slice to Apollo Unit values.
func assetsToUnits(assets []Asset) ([]apollo.Unit, error) {
	if len(assets) == 0 {
		return nil, nil
	}
	units := make([]apollo.Unit, 0, len(assets))
	for _, a := range assets {
		if len(a.Unit) < 56 {
			return nil, fmt.Errorf("asset unit %q is too short (expected ≥56 hex chars)", a.Unit)
		}
		policyHex := a.Unit[:56]
		nameHex := a.Unit[56:]
		if _, err := hex.DecodeString(policyHex); err != nil {
			return nil, fmt.Errorf("asset policy id %q is not valid hex: %w", policyHex, err)
		}
		if _, err := hex.DecodeString(nameHex); err != nil {
			return nil, fmt.Errorf("asset name %q is not valid hex: %w", nameHex, err)
		}
		qty, err := parseAmount(a.Quantity)
		if err != nil {
			return nil, fmt.Errorf("asset quantity: %w", err)
		}
		units = append(units, apollo.NewUnit(policyHex, nameHex, int64(qty))) //nolint:gosec // validated by parseAmount
	}
	return units, nil
}

// parseAmount parses a decimal uint64 amount string (lovelace or asset quantity)
// supplied in a request, rejecting non-numeric input and values beyond the int64
// range Apollo accepts.
func parseAmount(s string) (uint64, error) {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a valid amount", s)
	}
	if v > math.MaxInt64 {
		return 0, fmt.Errorf("amount %s exceeds int64 range", s)
	}
	return v, nil
}

func isInsufficientFundsError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "insufficient UTxOs to cover required value"):
		return true
	case strings.Contains(msg, "insufficient funds: coin underflow"):
		return true
	case strings.Contains(msg, "insufficient funds: asset underflow"):
		return true
	case strings.Contains(msg, "insufficient funds: need ") &&
		strings.Contains(msg, " more lovelace for change output min UTxO"):
		return true
	case strings.Contains(msg, "insufficient assets in inputs to cover burn"):
		return true
	default:
		return false
	}
}

// toPreview extracts human-readable preview data from a completed Apollo builder.
func toPreview(id string, a *apollo.Apollo) Preview {
	tx := a.GetTx()
	if tx == nil {
		return Preview{PendingID: id}
	}

	// Enumerate selected inputs from the built tx body.
	var inputs []string
	for _, inp := range tx.Body.TxInputs.Items() {
		ref := hex.EncodeToString(inp.TxId.Bytes()) + "#" + strconv.Itoa(int(inp.OutputIndex))
		inputs = append(inputs, ref)
	}

	// Enumerate outputs. Amounts are emitted as decimal strings (see the struct
	// docs); lastLov keeps the final output's raw lovelace for the change heuristic.
	var outputs []Output
	var lastLov uint64
	for _, out := range tx.Body.TxOutputs {
		lov := out.OutputAmount.Amount
		lastLov = lov
		var assets []Asset
		if out.OutputAmount.Assets != nil {
			for _, pol := range out.OutputAmount.Assets.Policies() {
				for _, name := range out.OutputAmount.Assets.Assets(pol) {
					qty := out.OutputAmount.Assets.Asset(pol, name)
					if qty != nil && qty.Sign() > 0 {
						assets = append(assets, Asset{
							Unit: hex.EncodeToString(pol.Bytes()) + hex.EncodeToString(name),
							// big.Int.String() preserves the full uint64 range.
							Quantity: qty.String(),
						})
					}
				}
			}
		}
		outputs = append(outputs, Output{
			Address:  out.OutputAddress.String(),
			Lovelace: strconv.FormatUint(lov, 10),
			Assets:   assets,
		})
	}
	// Apollo puts change last; only label it as change when it differs from the
	// first payment output address. This is a display-only heuristic.
	var changeLov uint64
	if len(outputs) > 1 && outputs[len(outputs)-1].Address != outputs[0].Address {
		changeLov = lastLov
	}

	return Preview{
		PendingID: id,
		Inputs:    inputs,
		Outputs:   outputs,
		Fee:       strconv.FormatUint(tx.Body.TxFee, 10),
		Change:    strconv.FormatUint(changeLov, 10),
	}
}

// Confirm signs the held unsigned transaction for every distinct input address and
// submits it to the chain. The pending entry is consumed: a second call with the
// same pendingID will return an error.
//
// Flow:
//  1. Look up and consume the pending entry (error if unknown).
//  2. Unlock the keystore to obtain the mnemonic (auth failure — nothing is signed).
//  3. Derive the account key from the mnemonic.
//  4. Build an index-lookup table from account.ReceiveAddresses.
//  5. Enumerate the distinct input addresses from the held tx via utxoAddr.
//  6. For each distinct address, derive its payment key, set it as the wallet, and call Sign().
//     Sign() APPENDs a VkeyWitness to the existing set (apollo.go:1432-1436) so iterative
//     calls accumulate witnesses — one per distinct signing key.
//  7. Submit the signed tx.
func (s *Service) Confirm(ctx context.Context, pendingID, password string) (TxResult, error) {
	// --- step 1: look up and consume the pending entry (reject unknown / TTL-expired) ---
	s.mu.Lock()
	p, ok := s.pending[pendingID]
	expired := ok && s.now().Sub(p.created) > pendingTTL
	if ok {
		delete(s.pending, pendingID)
	}
	s.mu.Unlock()
	if !ok {
		return TxResult{}, fmt.Errorf("%w: %q", ErrUnknownPending, pendingID)
	}
	if expired {
		return TxResult{}, fmt.Errorf("%w: %q", ErrExpiredPending, pendingID)
	}

	// --- step 2: unlock keystore (auth failure returns here; nothing signed) ---
	if s.keys == nil {
		return TxResult{}, errors.New("no keystore configured")
	}
	mnemonicBytes, err := s.keys.Unlock(password)
	if err != nil {
		if errors.Is(err, keystore.ErrDecryptFailed) {
			return TxResult{}, fmt.Errorf("%w: %w", ErrWrongPassword, err)
		}
		return TxResult{}, fmt.Errorf("unlock keystore: %w", err)
	}
	defer func() {
		// Zero the decrypted mnemonic as best-effort cleanup.
		for i := range mnemonicBytes {
			mnemonicBytes[i] = 0
		}
	}()

	// --- step 3: derive account key ---
	rootKey, err := bursa.GetRootKeyFromMnemonic(string(mnemonicBytes), "")
	if err != nil {
		return TxResult{}, fmt.Errorf("root key: %w", err)
	}
	acctKey, err := bursa.GetAccountKey(rootKey, 0)
	if err != nil {
		return TxResult{}, fmt.Errorf("account key: %w", err)
	}

	// --- step 4: build address → derivation-index lookup ---
	acct := s.currentAccount()
	if acct == nil {
		return TxResult{}, ErrNoWallet
	}
	idxOf := make(map[string]uint32, len(acct.ReceiveAddresses))
	for i, addrStr := range acct.ReceiveAddresses {
		idxOf[addrStr] = uint32(i) //nolint:gosec // bounded by window size
	}

	// --- step 5: enumerate distinct input addresses ---
	tx := p.tx.GetTx()
	if tx == nil {
		return TxResult{}, errors.New("pending tx is nil")
	}
	seen := make(map[string]bool)
	var distinctAddrs []string
	for _, inp := range tx.Body.TxInputs.Items() {
		ref := hex.EncodeToString(inp.TxId.Bytes()) + "#" + strconv.Itoa(int(inp.OutputIndex))
		addrStr, found := p.utxoAddr[ref]
		if !found {
			return TxResult{}, fmt.Errorf("input %s not in utxoAddr map", ref)
		}
		if !seen[addrStr] {
			seen[addrStr] = true
			distinctAddrs = append(distinctAddrs, addrStr)
		}
	}

	// --- step 6: sign once per distinct address ---
	a := p.tx
	for _, addrStr := range distinctAddrs {
		idx, inWindow := idxOf[addrStr]
		if !inWindow {
			return TxResult{}, fmt.Errorf("input address %s is outside the derived address window", addrStr)
		}
		payKey, err := bursa.GetPaymentKey(acctKey, idx)
		if err != nil {
			return TxResult{}, fmt.Errorf("payment key idx %d: %w", idx, err)
		}
		if err := func() error {
			defer func() {
				// Zero the payment key as best-effort cleanup.
				for i := range payKey {
					payKey[i] = 0
				}
			}()
			addr, err := lcommon.NewAddress(addrStr)
			if err != nil {
				return fmt.Errorf("parse address %s: %w", addrStr, err)
			}
			kw, err := apollo.NewKeyPairWallet(addr, payKey)
			if err != nil {
				return fmt.Errorf("key pair wallet idx %d: %w", idx, err)
			}
			a = a.SetWallet(kw)
			a, err = a.Sign()
			if err != nil {
				return fmt.Errorf("sign idx %d: %w", idx, err)
			}
			return nil
		}(); err != nil {
			return TxResult{}, err
		}
	}

	// --- step 7: submit ---
	// The node's structured rejection reason (the failing ledger rule, via the
	// utxorpc backend) rides along in the wrapped message.
	//
	// Detach from the request context: the pending entry has already been
	// consumed and the tx signed, so a client disconnect here must not cancel the
	// broadcast and strand a transaction that can no longer be replayed.
	txHash, err := a.SubmitContext(context.WithoutCancel(ctx))
	if err != nil {
		return TxResult{}, fmt.Errorf("%w: %w", ErrSubmitRejected, err)
	}

	return TxResult{TxHash: hex.EncodeToString(txHash.Bytes())}, nil
}

// randID generates a 16-byte random hex string for pending IDs.
func randID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
