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
	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/conway"
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
	// ErrWalletChanged: the active wallet changed while a transaction was being
	// built, so the preview is discarded instead of storing a stale pending send.
	ErrWalletChanged = errors.New("wallet changed while building transaction")
	// ErrInvalidTx: a supplied transaction CBOR is malformed or could not be
	// loaded (→ 400). Used by the air-gap sign/submit endpoints.
	ErrInvalidTx = errors.New("invalid transaction")
	// ErrInvalidWitness: a supplied witness CBOR is malformed, or none of its
	// witnesses match the transaction's required signers (→ 400).
	ErrInvalidWitness = errors.New("invalid witness")
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

// UnsignedTx is returned from ExportUnsigned: the completed-but-unsigned
// transaction CBOR (hex) plus the key-hashes that must witness it. It is the
// hand-off artifact carried (file or copy/paste) to an offline, keyed instance
// for signing.
type UnsignedTx struct {
	// UnsignedTxCBOR is the hex-encoded CBOR of the completed Conway tx with an
	// empty witness set.
	UnsignedTxCBOR string `json:"unsigned_tx_cbor"`
	// RequiredSigners are the hex-encoded key-hashes (Blake2b-224) that must
	// witness the transaction.
	RequiredSigners []string `json:"required_signers"`
}

// Witness is returned from SignTx: the vkey witness(es) produced offline for an
// unsigned tx. WitnessCBOR is a hex-encoded CBOR array of common.VkeyWitness
// (one per distinct signing key) ready to be attached by SubmitSigned.
type Witness struct {
	WitnessCBOR string `json:"witness_cbor"`
}

// Keystore is the minimal interface satisfied by *keystore.Keystore. It is
// accepted as an interface so the service can be constructed with a nil keystore
// when only Build is needed, and faked in tests.
type Keystore interface {
	Exists() bool
	Create(mnemonic, password string) error
	Unlock(password string) (mnemonic []byte, err error)
}

type walletSeedStore interface {
	UnlockFor(walletID, password string) (mnemonic []byte, err error)
}

// addressWindow is the number of external (receive) addresses derived for a
// spending account. It matches the read-only wallet's default window so the
// derived addresses (and their indices) line up for signing.
const addressWindow = 20

// feePaddingLovelace is a small safety margin on Apollo's estimated fee. The
// air-gap path embeds required signers before fee estimation; this padding is
// only a conservative buffer for serialization/provider variance.
const feePaddingLovelace = 1000

// pending holds a completed but unsigned tx while awaiting Confirm.
type pending struct {
	tx        *apollo.Apollo
	utxoAddr  map[string]string // "txhash#index" → bech32 address (for signing)
	created   time.Time
	walletID  string
	account   *wallet.Account
	certKinds []CertKind // non-nil for delegation txs; drives stake/DRep witness addition at Confirm
}

// Service builds and holds pending send transactions.
type Service struct {
	chain    backend.ChainContext
	keys     Keystore // may be nil for build-only usage
	account  *wallet.Account
	walletID string
	gen      uint64
	chainQ   chainQuerier     // node-backed pool/DRep/account/params queries (delegation); may be nil
	mkID     func() string    // pending id generator; injectable for tests
	now      func() time.Time // injectable for tests

	mu      sync.Mutex
	pending map[string]*pending
}

// NewService constructs a Service. ks may be nil if only Build (not Confirm) is needed.
func NewService(cc backend.ChainContext, ks Keystore, acct *wallet.Account) *Service {
	return &Service{
		chain:   cc,
		keys:    ks,
		account: cloneAccount(acct),
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
	s.account = cloneAccount(acct)
	s.walletID = ""
	s.gen++
	s.pending = make(map[string]*pending)
	s.mu.Unlock()
	return acct, nil
}

// SetAccount sets the active spending account directly, without creating a
// keystore. The vault owns seed encryption now: the active wallet's account is
// pushed here on unlock/activate, and the keystore adapter routes Unlock to that
// wallet's vault-encrypted seed. Pending sends are cleared so a preview built
// against a previous wallet can't be confirmed under the new one.
func (s *Service) SetAccount(walletID string, acct *wallet.Account) {
	s.mu.Lock()
	s.account = cloneAccount(acct)
	if acct == nil {
		s.walletID = ""
	} else {
		s.walletID = walletID
	}
	s.gen++
	s.pending = make(map[string]*pending)
	s.mu.Unlock()
}

// currentBinding returns a stable snapshot of the active account binding.
func (s *Service) currentBinding() (string, *wallet.Account, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.walletID, cloneAccount(s.account), s.gen
}

// currentAccount returns a snapshot of the active account under lock (nil if
// none is set). Used by the delegation flow.
func (s *Service) currentAccount() *wallet.Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneAccount(s.account)
}

// Build runs coin selection and fee estimation for req using Apollo, stores the
// incomplete tx under a new pending id, and returns a Preview for user approval.
func (s *Service) Build(ctx context.Context, req SendRequest) (Preview, error) {
	walletID, acct, gen := s.currentBinding()
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

	// Load spendable UTxOs from every receive address; record txref→address for
	// later signing. We pre-load them so Apollo's coin selection can see them
	// without needing a live chain query inside Complete().
	utxoAddr := make(map[string]string)
	var loaded []lcommon.Utxo
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
			loaded = append(loaded, utxos...)
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
	// Complete with the selected input payment key hashes embedded as Conway
	// required signers. The first pass discovers selected inputs; later passes
	// rebuild the tx with that signer set so fee estimation covers the bound body.
	var a *apollo.Apollo
	var required []lcommon.Blake2b224
	maxAttempts := len(acct.ReceiveAddresses) + 2
	for attempt := 0; attempt < maxAttempts; attempt++ {
		next := apollo.New(s.chain).
			SetWallet(apollo.NewExternalWallet(changeAddr)).
			SetChangeAddress(changeAddr).
			SetFeePadding(feePaddingLovelace).
			AddLoadedUTxOs(loaded...)
		for _, kh := range required {
			next = next.AddRequiredSigner(kh)
		}
		next = next.PayToAddress(recvAddr, int64(lovelace), units...) //nolint:gosec // validated by parseAmount

		next, err = next.CompleteContext(ctx)
		if err != nil {
			if isInsufficientFundsError(err) {
				return Preview{}, fmt.Errorf("%w: %w", ErrInsufficientFunds, err)
			}
			return Preview{}, fmt.Errorf("complete transaction: %w", err)
		}

		tx := next.GetTx()
		if tx == nil {
			return Preview{}, errors.New("completed tx is nil")
		}
		actual, err := requiredPaymentKeyHashesForInputs(tx.Body.Inputs(), utxoAddr)
		if err != nil {
			return Preview{}, err
		}
		if sameKeyHashSet(required, actual) {
			a = next
			break
		}
		required = actual
	}
	if a == nil {
		return Preview{}, errors.New("required signer set did not converge")
	}

	// Store the pending entry (sweeping any that have outlived their TTL first).
	id := s.mkID()
	s.mu.Lock()
	if s.gen != gen || s.walletID != walletID {
		s.mu.Unlock()
		return Preview{}, ErrWalletChanged
	}
	s.sweepExpiredLocked()
	s.pending[id] = &pending{
		tx:       a,
		utxoAddr: utxoAddr,
		created:  s.now(),
		walletID: walletID,
		account:  cloneAccount(acct),
	}
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
	walletID, acct, _ := s.currentBinding()
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

	mnemonicBytes, err := s.unlockSeed(walletID, password)
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

// PubDRepKey unlocks the keystore with the given password, derives the DRep key
// (CIP-0105, derivation role 3: m/1852'/1815'/0'/3/0), and returns the raw
// 32-byte Ed25519 public key. The private key material is zeroed before returning.
func (s *Service) PubDRepKey(password string) ([]byte, error) {
	if s.keys == nil {
		return nil, errors.New("no keystore configured")
	}

	// Bind to the active wallet's seed (not merely the active vault default) so
	// the derived key always matches the account the approval was issued for,
	// even if the active selection changes between approval and unlock.
	walletID, acct, _ := s.currentBinding()
	if acct == nil {
		return nil, ErrNoWallet
	}
	mnemonicBytes, err := s.unlockSeed(walletID, password)
	if err != nil {
		if errors.Is(err, keystore.ErrDecryptFailed) {
			return nil, fmt.Errorf("%w: %w", ErrWrongPassword, err)
		}
		return nil, fmt.Errorf("unlock keystore: %w", err)
	}
	defer func() {
		for i := range mnemonicBytes {
			mnemonicBytes[i] = 0
		}
	}()

	var rootKey, acctKey, drepKey bip32.XPrv
	defer func() {
		for _, k := range []bip32.XPrv{rootKey, acctKey, drepKey} {
			for i := range k {
				k[i] = 0
			}
		}
	}()

	rootKey, err = bursa.GetRootKeyFromMnemonic(string(mnemonicBytes), "")
	if err != nil {
		return nil, fmt.Errorf("root key: %w", err)
	}
	acctKey, err = bursa.GetAccountKey(rootKey, 0)
	if err != nil {
		return nil, fmt.Errorf("account key: %w", err)
	}
	drepKey, err = bursa.GetDRepKey(acctKey, 0)
	if err != nil {
		return nil, fmt.Errorf("drep key: %w", err)
	}

	// Return a copy of the public key before zeroing drepKey.
	pub := bip32.XPrv(drepKey).Public().PublicKey()
	out := make([]byte, len(pub))
	copy(out, pub)
	return out, nil
}

// PubStakeKey unlocks the keystore with the given password, derives the stake key
// (CIP-1852, derivation role 2: m/1852'/1815'/0'/2/0), and returns the raw
// 32-byte Ed25519 public key. The private key material is zeroed before returning.
func (s *Service) PubStakeKey(password string) ([]byte, error) {
	if s.keys == nil {
		return nil, errors.New("no keystore configured")
	}

	// Bind to the active wallet's seed (see PubDRepKey) so the derived stake key
	// matches the account the approval was issued for.
	walletID, acct, _ := s.currentBinding()
	if acct == nil {
		return nil, ErrNoWallet
	}
	mnemonicBytes, err := s.unlockSeed(walletID, password)
	if err != nil {
		if errors.Is(err, keystore.ErrDecryptFailed) {
			return nil, fmt.Errorf("%w: %w", ErrWrongPassword, err)
		}
		return nil, fmt.Errorf("unlock keystore: %w", err)
	}
	defer func() {
		for i := range mnemonicBytes {
			mnemonicBytes[i] = 0
		}
	}()

	var rootKey, acctKey, stakeKey bip32.XPrv
	defer func() {
		for _, k := range []bip32.XPrv{rootKey, acctKey, stakeKey} {
			for i := range k {
				k[i] = 0
			}
		}
	}()

	rootKey, err = bursa.GetRootKeyFromMnemonic(string(mnemonicBytes), "")
	if err != nil {
		return nil, fmt.Errorf("root key: %w", err)
	}
	acctKey, err = bursa.GetAccountKey(rootKey, 0)
	if err != nil {
		return nil, fmt.Errorf("account key: %w", err)
	}
	stakeKey, err = bursa.GetStakeKey(acctKey, 0)
	if err != nil {
		return nil, fmt.Errorf("stake key: %w", err)
	}

	// Return a copy of the public key before zeroing stakeKey.
	pub := bip32.XPrv(stakeKey).Public().PublicKey()
	out := make([]byte, len(pub))
	copy(out, pub)
	return out, nil
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

func inputRef(inp lcommon.TransactionInput) string {
	return hex.EncodeToString(inp.Id().Bytes()) + "#" + strconv.Itoa(int(inp.Index()))
}

func requiredPaymentKeyHashesForInputs(
	inputs []lcommon.TransactionInput,
	utxoAddr map[string]string,
) ([]lcommon.Blake2b224, error) {
	seen := make(map[lcommon.Blake2b224]bool)
	signers := make([]lcommon.Blake2b224, 0, len(inputs))
	for _, inp := range inputs {
		ref := inputRef(inp)
		addrStr, found := utxoAddr[ref]
		if !found {
			return nil, fmt.Errorf("input %s not in utxoAddr map", ref)
		}
		addr, err := lcommon.NewAddress(addrStr)
		if err != nil {
			return nil, fmt.Errorf("parse address %s: %w", addrStr, err)
		}
		kh := addr.PaymentKeyHash()
		if !seen[kh] {
			seen[kh] = true
			signers = append(signers, kh)
		}
	}
	return signers, nil
}

func parseRequiredSignerHashes(requiredSigners []string) ([]lcommon.Blake2b224, error) {
	seen := make(map[lcommon.Blake2b224]bool, len(requiredSigners))
	signers := make([]lcommon.Blake2b224, 0, len(requiredSigners))
	for _, signer := range requiredSigners {
		signer = strings.ToLower(strings.TrimSpace(signer))
		if signer == "" {
			continue
		}
		b, err := hex.DecodeString(signer)
		if err != nil || len(b) != lcommon.Blake2b224Size {
			return nil, fmt.Errorf(
				"%w: required signer %q is not a 28-byte key hash hex",
				ErrInvalidRequest, signer,
			)
		}
		var kh lcommon.Blake2b224
		copy(kh[:], b)
		if !seen[kh] {
			seen[kh] = true
			signers = append(signers, kh)
		}
	}
	return signers, nil
}

func sameKeyHashSet(a, b []lcommon.Blake2b224) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[lcommon.Blake2b224]bool, len(a))
	for _, kh := range a {
		seen[kh] = true
	}
	if len(seen) != len(a) {
		return false
	}
	for _, kh := range b {
		if !seen[kh] {
			return false
		}
	}
	return true
}

func keyHashSetContainsAll(set, subset []lcommon.Blake2b224) bool {
	seen := make(map[lcommon.Blake2b224]bool, len(set))
	for _, kh := range set {
		seen[kh] = true
	}
	for _, kh := range subset {
		if !seen[kh] {
			return false
		}
	}
	return true
}

func keyHashesHex(signers []lcommon.Blake2b224) []string {
	ret := make([]string, 0, len(signers))
	for _, kh := range signers {
		ret = append(ret, hex.EncodeToString(kh.Bytes()))
	}
	return ret
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
	mnemonicBytes, err := s.unlockSeed(p.walletID, password)
	if err != nil {
		if errors.Is(err, keystore.ErrDecryptFailed) {
			return TxResult{}, fmt.Errorf("%w: %w", ErrWrongPassword, err)
		}
		return TxResult{}, fmt.Errorf("unlock keystore: %w", err)
	}
	// rootKey and acctKey hold the account master secret; declare them up front so
	// the deferred cleanup below zeroes them on every exit path (including the
	// derivation errors here), matching the other signing methods.
	var rootKey, acctKey bip32.XPrv
	defer func() {
		// Zero the decrypted mnemonic and derived account keys as best-effort cleanup.
		for _, k := range []bip32.XPrv{rootKey, acctKey} {
			for i := range k {
				k[i] = 0
			}
		}
		for i := range mnemonicBytes {
			mnemonicBytes[i] = 0
		}
	}()

	// --- step 3: derive account key ---
	rootKey, err = bursa.GetRootKeyFromMnemonic(string(mnemonicBytes), "")
	if err != nil {
		return TxResult{}, fmt.Errorf("root key: %w", err)
	}
	acctKey, err = bursa.GetAccountKey(rootKey, 0)
	if err != nil {
		return TxResult{}, fmt.Errorf("account key: %w", err)
	}

	// --- step 4: build address → derivation-index lookup ---
	acct := p.account
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

	// --- step 6b: add stake / DRep key witnesses for delegation certificates ---
	// Cardano requires a vkey witness from the stake key for any cert that touches
	// the stake credential (stake registration, stake delegation, vote delegation,
	// and reward withdrawal). It also requires a witness from the DRep key for a
	// DRep registration. These are in addition to the payment-key witnesses above.
	needsStakeWitness, needsDRepWitness := certKindsRequireWitnesses(p.certKinds)
	if needsStakeWitness {
		stakeKey, err := bursa.GetStakeKey(acctKey, 0)
		if err != nil {
			return TxResult{}, fmt.Errorf("stake key: %w", err)
		}
		a, err = a.SignWithSkey([]byte(stakeKey))
		for i := range stakeKey {
			stakeKey[i] = 0
		}
		if err != nil {
			return TxResult{}, fmt.Errorf("sign stake key: %w", err)
		}
	}
	if needsDRepWitness {
		drepKey, err := bursa.GetDRepKey(acctKey, 0)
		if err != nil {
			return TxResult{}, fmt.Errorf("drep key: %w", err)
		}
		a, err = a.SignWithSkey([]byte(drepKey))
		for i := range drepKey {
			drepKey[i] = 0
		}
		if err != nil {
			return TxResult{}, fmt.Errorf("sign drep key: %w", err)
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

func (s *Service) unlockSeed(walletID, password string) ([]byte, error) {
	if walletID == "" {
		return s.keys.Unlock(password)
	}
	ks, ok := s.keys.(walletSeedStore)
	if !ok {
		return nil, fmt.Errorf("wallet-bound seed unlock requires UnlockFor support for wallet %q", walletID)
	}
	return ks.UnlockFor(walletID, password)
}

func cloneAccount(acct *wallet.Account) *wallet.Account {
	if acct == nil {
		return nil
	}
	cp := *acct
	cp.ReceiveAddresses = append([]string(nil), acct.ReceiveAddresses...)
	cp.ChangeAddresses = append([]string(nil), acct.ChangeAddresses...)
	return &cp
}

func (s *Service) VerifyData(
	signatureHex, keyHex string,
	message []byte,
	hashed bool,
	expectedAddress string,
) (valid bool, address string, err error) {
	signatureHashed, err := bursa.SignaturePayloadHashed(signatureHex)
	if err != nil {
		return false, "", fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	if signatureHashed != hashed {
		return false, "", fmt.Errorf(
			"%w: hashed flag %t does not match COSE hashed header %t",
			ErrInvalidRequest, hashed, signatureHashed,
		)
	}
	// bursa.VerifyDataWithAddress treats the COSE "hashed" header as the source
	// of truth when rebuilding the Sig_structure. The UI flag is validated above
	// so request shape mistakes do not silently verify.
	valid, address, err = bursa.VerifyDataWithAddress(signatureHex, keyHex, message)
	if err != nil {
		return false, "", fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	if expectedAddress != "" && address != expectedAddress {
		// The signature may itself be cryptographically valid, but it does not
		// attest the address the caller expected: report it as not valid.
		return false, address, nil
	}
	return valid, address, nil
}

// ExportUnsigned returns the completed-but-UNSIGNED transaction CBOR for a
// pending send plus the payment key-hashes that must witness it. It is the first
// step of the air-gap flow: the returned artifact is carried to an offline, keyed
// instance (file download or copy/paste) which produces the witness via SignTx.
//
// Unlike Confirm it does NOT consume the pending entry — the user may still
// Confirm online instead, or re-export — but it is subject to the same TTL.
func (s *Service) ExportUnsigned(pendingID string) (UnsignedTx, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[pendingID]
	expired := ok && s.now().Sub(p.created) > pendingTTL
	if !ok {
		return UnsignedTx{}, fmt.Errorf("%w: %q", ErrUnknownPending, pendingID)
	}
	if expired {
		return UnsignedTx{}, fmt.Errorf("%w: %q", ErrExpiredPending, pendingID)
	}

	tx := p.tx.GetTx()
	if tx == nil {
		return UnsignedTx{}, errors.New("pending tx is nil")
	}
	// Payment signer hashes are derived from the same utxoAddr map Confirm uses.
	// Delegation transactions may also bind stake/DRep certificate signers in the
	// body; export the full body-bound signer set after confirming the selected
	// payment keys are represented.
	paymentSignerHashes, err := requiredPaymentKeyHashesForInputs(tx.Body.Inputs(), p.utxoAddr)
	if err != nil {
		return UnsignedTx{}, err
	}
	bodySignerHashes := tx.Body.RequiredSigners()
	if !keyHashSetContainsAll(bodySignerHashes, paymentSignerHashes) {
		return UnsignedTx{}, fmt.Errorf(
			"%w: unsigned tx required signers do not include selected input signers",
			ErrInvalidTx,
		)
	}
	cborBytes, err := p.tx.GetTxCbor()
	if err != nil {
		return UnsignedTx{}, fmt.Errorf("encode unsigned tx: %w", err)
	}

	return UnsignedTx{
		UnsignedTxCBOR:  hex.EncodeToString(cborBytes),
		RequiredSigners: keyHashesHex(bodySignerHashes),
	}, nil
}

// SignTx is the air-gapped step: it decrypts the seed with the spending password,
// derives the wallet's signing keys, and produces vkey witness(es) over the
// supplied unsigned transaction's body. The result is a CBOR array of
// common.VkeyWitness (one per derived key) which SubmitSigned attaches to the
// same unsigned tx on the online instance.
//
// It needs only the unsigned tx CBOR, the required signer key hashes exported
// with that tx, and the password - no node, no UTxO set. The signer list is
// accepted only as redundancy for the hand-off artifact: it must exactly match
// the required signer set embedded in the transaction body before any key is
// unlocked. SignTx then derives the wallet's address window but emits only
// witnesses whose vkey hash is in the body-bound signer set.
func (s *Service) SignTx(unsignedTxCBOR, password string, requiredSigners []string) (Witness, error) {
	if s.keys == nil {
		return Witness{}, errors.New("no keystore configured")
	}
	walletID, acct, _ := s.currentBinding()
	if acct == nil {
		return Witness{}, ErrNoWallet
	}

	// Load the unsigned tx and hash its body — this is what each witness signs.
	loader, err := apollo.New(s.chain).LoadTxCbor(unsignedTxCBOR)
	if err != nil {
		return Witness{}, fmt.Errorf("%w: %w", ErrInvalidTx, err)
	}
	tx := loader.GetTx()
	if tx == nil {
		return Witness{}, fmt.Errorf("%w: no transaction body", ErrInvalidTx)
	}
	// Witnesses sign the hash of the body bytes exactly as carried by the
	// unsigned transaction. Re-encoding can drift while preserving semantics.
	bodyCbor := tx.Body.Cbor()
	if bodyCbor == nil {
		bodyCbor, err = cbor.Encode(&tx.Body)
		if err != nil {
			return Witness{}, fmt.Errorf("encode tx body: %w", err)
		}
	}
	bodyHash := lcommon.Blake2b256Hash(bodyCbor)

	bodyRequired := tx.Body.RequiredSigners()
	if len(bodyRequired) == 0 {
		return Witness{}, fmt.Errorf("%w: unsigned tx does not declare required signers", ErrInvalidTx)
	}
	requested, err := parseRequiredSignerHashes(requiredSigners)
	if err != nil {
		return Witness{}, err
	}
	if len(requested) == 0 {
		return Witness{}, fmt.Errorf("%w: required_signers is required", ErrInvalidRequest)
	}
	if !sameKeyHashSet(requested, bodyRequired) {
		return Witness{}, fmt.Errorf(
			"%w: required_signers does not match the unsigned transaction body",
			ErrInvalidRequest,
		)
	}

	needed := make(map[string]bool, len(bodyRequired))
	for _, signer := range bodyRequired {
		needed[hex.EncodeToString(signer.Bytes())] = true
	}

	mnemonicBytes, err := s.unlockSeed(walletID, password)
	if err != nil {
		if errors.Is(err, keystore.ErrDecryptFailed) {
			return Witness{}, fmt.Errorf("%w: %w", ErrWrongPassword, err)
		}
		return Witness{}, fmt.Errorf("unlock keystore: %w", err)
	}
	var rootKey, acctKey bip32.XPrv
	defer func() {
		for _, k := range []bip32.XPrv{rootKey, acctKey} {
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
		return Witness{}, fmt.Errorf("root key: %w", err)
	}
	acctKey, err = bursa.GetAccountKey(rootKey, 0)
	if err != nil {
		return Witness{}, fmt.Errorf("account key: %w", err)
	}

	// Walk the same derived keys as the former candidate loop, but only sign and
	// emit keys whose vkey hash is required by the exported tx.
	seenKeyHash := make(map[string]bool)
	var witnesses []lcommon.VkeyWitness
	addCandidate := func(signKey bip32.XPrv) error {
		defer func() {
			for i := range signKey {
				signKey[i] = 0
			}
		}()
		kh := hex.EncodeToString(lcommon.Blake2b224Hash(signKey.PublicKey()).Bytes())
		if !needed[kh] || seenKeyHash[kh] {
			return nil
		}
		w, err := apollo.NewVkeyWitnessFromSkey(bodyHash, []byte(signKey))
		if err != nil {
			return err
		}
		seenKeyHash[kh] = true
		witnesses = append(witnesses, w)
		return nil
	}
	for i := range acct.ReceiveAddresses {
		payKey, err := bursa.GetPaymentKey(acctKey, uint32(i)) //nolint:gosec // bounded by window size
		if err != nil {
			return Witness{}, fmt.Errorf("payment key idx %d: %w", i, err)
		}
		if err := addCandidate(payKey); err != nil {
			return Witness{}, fmt.Errorf("witness payment idx %d: %w", i, err)
		}
	}
	if stakeKey, err := bursa.GetStakeKey(acctKey, 0); err == nil {
		if err := addCandidate(stakeKey); err != nil {
			return Witness{}, fmt.Errorf("witness stake key: %w", err)
		}
	}
	if drepKey, err := bursa.GetDRepKey(acctKey, 0); err == nil {
		if err := addCandidate(drepKey); err != nil {
			return Witness{}, fmt.Errorf("witness drep key: %w", err)
		}
	}
	if len(witnesses) == 0 {
		return Witness{}, fmt.Errorf(
			"%w: none of this wallet's keys match the transaction's required signers",
			ErrInvalidWitness,
		)
	}
	if len(witnesses) < len(needed) {
		return Witness{}, fmt.Errorf(
			"%w: transaction needs %d distinct signers but this wallet produced %d",
			ErrInvalidWitness, len(needed), len(witnesses),
		)
	}

	encoded, err := cbor.Encode(witnesses)
	if err != nil {
		return Witness{}, fmt.Errorf("encode witnesses: %w", err)
	}
	return Witness{WitnessCBOR: hex.EncodeToString(encoded)}, nil
}

// SubmitSigned is the final air-gap step, run on the online instance: it loads
// the unsigned tx, decodes the witness array produced offline by SignTx, attaches
// only the witnesses the transaction's inputs actually require (resolved against
// the chain), and submits. The tx body is never mutated, so the body hash the
// witnesses signed still matches the submitted transaction.
func (s *Service) SubmitSigned(ctx context.Context, unsignedTxCBOR, witnessCBOR string) (TxResult, error) {
	a, err := apollo.New(s.chain).LoadTxCbor(unsignedTxCBOR)
	if err != nil {
		return TxResult{}, fmt.Errorf("%w: %w", ErrInvalidTx, err)
	}
	tx := a.GetTx()
	if tx == nil {
		return TxResult{}, fmt.Errorf("%w: no transaction body", ErrInvalidTx)
	}

	witBytes, err := hex.DecodeString(witnessCBOR)
	if err != nil {
		return TxResult{}, fmt.Errorf("%w: witness hex: %w", ErrInvalidWitness, err)
	}
	var witnesses []lcommon.VkeyWitness
	if _, err := cbor.Decode(witBytes, &witnesses); err != nil {
		return TxResult{}, fmt.Errorf("%w: %w", ErrInvalidWitness, err)
	}
	if len(witnesses) == 0 {
		return TxResult{}, fmt.Errorf("%w: no witnesses supplied", ErrInvalidWitness)
	}

	// Determine which key-hashes the transaction requires: input payment hashes
	// resolved against the chain plus any hashes explicitly required by the body.
	needed := make(map[string]bool)
	for _, signer := range tx.Body.RequiredSigners() {
		needed[hex.EncodeToString(signer.Bytes())] = true
	}
	for _, inp := range tx.Body.Inputs() {
		u, err := s.chain.UtxoByRef(ctx, inp.Id(), inp.Index())
		if err != nil {
			return TxResult{}, fmt.Errorf("resolve input %s#%d: %w",
				hex.EncodeToString(inp.Id().Bytes()), inp.Index(), err)
		}
		if u == nil || u.Output == nil {
			return TxResult{}, fmt.Errorf("%w: input %s#%d not found on chain (already spent?)",
				ErrInvalidTx, hex.EncodeToString(inp.Id().Bytes()), inp.Index())
		}
		inAddr := u.Output.Address() // addressable copy: PaymentKeyHash has a pointer receiver
		needed[hex.EncodeToString(inAddr.PaymentKeyHash().Bytes())] = true
	}

	// Attach only the witnesses whose vkey hashes a required signer, deduped.
	attached := make(map[string]bool)
	count := 0
	for _, w := range witnesses {
		kh := hex.EncodeToString(lcommon.Blake2b224Hash(w.Vkey).Bytes())
		if !needed[kh] || attached[kh] {
			continue
		}
		attached[kh] = true
		if a, err = a.AddVerificationKeyWitness(w); err != nil {
			return TxResult{}, fmt.Errorf("attach witness: %w", err)
		}
		count++
	}
	if count == 0 {
		return TxResult{}, fmt.Errorf(
			"%w: none of the supplied witnesses match the transaction's required signers",
			ErrInvalidWitness,
		)
	}
	if count < len(needed) {
		return TxResult{}, fmt.Errorf(
			"%w: transaction needs %d distinct signers but only %d were supplied",
			ErrInvalidWitness, len(needed), count,
		)
	}

	// LoadTxCbor cached the decoded transaction's raw CBOR; ConwayTransaction
	// (and its witness set) re-emit that cache on encode, which would drop the
	// witnesses we just attached. Clear the transaction-level and witness-set
	// caches so SubmitContext re-serializes from the mutated struct. The BODY
	// cache is deliberately left intact: the witnesses signed over the original
	// body bytes, so re-encoding the body must reproduce them exactly.
	tx.SetCbor(nil)
	tx.WitnessSet.SetCbor(nil)

	// Detach from the request context: once submitted the inputs are consumed, so
	// a client disconnect must not strand a broadcast (mirrors Confirm).
	txHash, err := a.SubmitContext(context.WithoutCancel(ctx))
	if err != nil {
		return TxResult{}, fmt.Errorf("%w: %w", ErrSubmitRejected, err)
	}
	return TxResult{TxHash: hex.EncodeToString(txHash.Bytes())}, nil
}

// certKindsRequireWitnesses returns which additional witnesses a delegation tx
// needs beyond the payment-input witnesses. Stake-touching certs (registration,
// stake delegation, vote delegation, withdrawal) each require the stake key to
// be a witness; DRep registration requires the DRep key.
func certKindsRequireWitnesses(kinds []CertKind) (needsStake, needsDRep bool) {
	for _, k := range kinds {
		switch k {
		case CertStakeRegistration, CertStakeDelegation, CertVoteDelegation, CertWithdrawal:
			needsStake = true
		case CertDRepRegistration:
			needsDRep = true
		}
	}
	return
}

// Submit submits a fully-signed transaction (raw CBOR bytes) to the chain.
// It returns the tx hash as a hex string. This is the SubmitTx path for
// externally-signed transactions (CIP-30 connector); it reuses the same
// backend.ChainContext the spend service uses for its own Confirm flow.
func (s *Service) Submit(ctx context.Context, txBytes []byte) (string, error) {
	txHash, err := s.chain.SubmitTx(context.WithoutCancel(ctx), txBytes)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrSubmitRejected, err)
	}
	return hex.EncodeToString(txHash.Bytes()), nil
}

// WitnessTx derives the wallet's signing keys and builds a CBOR witness set
// for an external transaction.  The caller provides:
//   - txBodyCbor: the raw CBOR of the transaction body (used to compute the hash
//     that is signed; must equal the body embedded in the original tx).
//   - requiredSignerHashes: the Blake2b224 key hashes from the tx body's
//     required-signers field (key 14). WitnessTx also reads the body directly
//     for certificate and withdrawal credentials.
//   - inputAddrs: the bech32 addresses of the transaction's inputs that the
//     wallet may own (resolved by the caller using its address window).
//   - password: unlocks the keystore.
//   - partialSign: when false, WitnessTx returns an error if any explicitly
//     required key credential cannot be matched; when true, a partial or empty
//     witness set is acceptable.
//
// Returns the CBOR-encoded ConwayTransactionWitnessSet containing only the
// VkeyWitnesses this wallet can provide.
func (s *Service) WitnessTx(
	walletID string,
	txBodyCbor []byte,
	requiredSignerHashes []lcommon.Blake2b224,
	inputAddrs []string,
	password string,
	partialSign bool,
) ([]byte, error) {
	if s.keys == nil {
		return nil, errors.New("no keystore configured")
	}
	curWalletID, acct, _ := s.currentBinding()
	if acct == nil {
		return nil, ErrNoWallet
	}
	// walletID is the binding the caller (connector.WalletBackend.SignTx)
	// captured when it resolved inputAddrs/requiredSignerHashes. If the active
	// wallet has since changed (e.g. the user switched wallets while a dApp
	// signing approval was pending), fail closed instead of deriving witnesses
	// from the newly active wallet against a transaction resolved under the old
	// one.
	if curWalletID != walletID {
		return nil, ErrWalletChanged
	}

	var txBody conway.ConwayTransactionBody
	if _, err := cbor.Decode(txBodyCbor, &txBody); err != nil {
		return nil, fmt.Errorf("%w: decode transaction body: %w", ErrInvalidTx, err)
	}

	// Unlock the active wallet's seed (walletID-bound), not merely the active
	// vault default, so the witnesses are produced from the same account whose
	// address window was used to resolve which keys to sign with.
	mnemonicBytes, err := s.unlockSeed(walletID, password)
	if err != nil {
		if errors.Is(err, keystore.ErrDecryptFailed) {
			return nil, fmt.Errorf("%w: %w", ErrWrongPassword, err)
		}
		return nil, fmt.Errorf("unlock keystore: %w", err)
	}
	defer func() {
		for i := range mnemonicBytes {
			mnemonicBytes[i] = 0
		}
	}()

	// Derive account key.
	var rootKey, acctKey bip32.XPrv
	defer func() {
		for _, k := range []bip32.XPrv{rootKey, acctKey} {
			for i := range k {
				k[i] = 0
			}
		}
	}()

	rootKey, err = bursa.GetRootKeyFromMnemonic(string(mnemonicBytes), "")
	if err != nil {
		return nil, fmt.Errorf("root key: %w", err)
	}
	acctKey, err = bursa.GetAccountKey(rootKey, 0)
	if err != nil {
		return nil, fmt.Errorf("account key: %w", err)
	}

	// Hash the tx body to get the signing target.
	txBodyHash := lcommon.Blake2b256Hash(txBodyCbor)

	witnesses, err := s.deriveWitnesses(
		acctKey,
		txBodyHash,
		requiredSignerHashes,
		&txBody,
		inputAddrs,
		acct,
		partialSign,
	)
	if err != nil {
		return nil, err
	}

	// Encode witness set as CBOR using the ConwayTransactionWitnessSet type,
	// which serialises as a map with integer keys (key 0 = vkey witnesses).
	ws := conway.ConwayTransactionWitnessSet{}
	if len(witnesses) > 0 {
		ws.VkeyWitnesses = cbor.NewSetType(witnesses, true)
	}
	wsCbor, err := cbor.Encode(ws)
	if err != nil {
		return nil, fmt.Errorf("encode witness set: %w", err)
	}
	return wsCbor, nil
}

// deriveWitnesses derives the vkey witnesses this wallet can provide for a
// transaction, given the already-derived account key. It matches required
// signers (key-14 plus certificate/withdrawal credentials) and owned input
// addresses to the wallet's payment/stake/DRep keys, deriving each candidate
// key from acctKey and zeroing it locally once it has served its purpose.
// Both WitnessTx and CosignTx call this so the derivation logic never drifts
// between the two entry points.
func (s *Service) deriveWitnesses(
	acctKey bip32.XPrv,
	txBodyHash lcommon.Blake2b256,
	requiredSignerHashes []lcommon.Blake2b224,
	txBody *conway.ConwayTransactionBody,
	inputAddrs []string,
	acct *wallet.Account,
	partialSign bool,
) ([]lcommon.VkeyWitness, error) {
	// Build a map from every owned payment address to its CIP-1852 role/index.
	// Receive addresses use role 0 and change addresses use role 1. An address
	// absent from this map MUST NOT be signed — defaulting to role/index 0 would
	// attach a witness from the wrong key.
	type paymentKeyPath struct {
		role  uint32
		index uint32
	}
	pathOf := make(map[string]paymentKeyPath, len(acct.ReceiveAddresses)+len(acct.ChangeAddresses))
	for i, addrStr := range acct.ReceiveAddresses {
		pathOf[addrStr] = paymentKeyPath{
			role:  0,
			index: uint32(i), //nolint:gosec // bounded by window size
		}
	}
	for i, addrStr := range acct.ChangeAddresses {
		pathOf[addrStr] = paymentKeyPath{
			role:  1,
			index: uint32(i), //nolint:gosec // bounded by window size
		}
	}

	// Build the complete set of explicit key credentials that require witnesses:
	// key-14 required signers plus credentials referenced by certificates and
	// reward withdrawals. The latter are not redundantly required to appear in
	// key 14.
	reqSet := make(map[lcommon.Blake2b224]bool, len(requiredSignerHashes))
	for _, h := range requiredSignerHashes {
		reqSet[h] = true
	}
	for _, h := range txBody.RequiredSigners() {
		reqSet[h] = true
	}
	addCredential := func(cred *lcommon.Credential) {
		if cred != nil && cred.CredType == lcommon.CredentialTypeAddrKeyHash {
			reqSet[cred.Credential] = true
		}
	}
	for _, cert := range txBody.Certificates() {
		switch c := cert.(type) {
		case *lcommon.StakeRegistrationCertificate:
			addCredential(&c.StakeCredential)
		case *lcommon.StakeDeregistrationCertificate:
			addCredential(&c.StakeCredential)
		case *lcommon.StakeDelegationCertificate:
			addCredential(c.StakeCredential)
		case *lcommon.RegistrationCertificate:
			addCredential(&c.StakeCredential)
		case *lcommon.DeregistrationCertificate:
			addCredential(&c.StakeCredential)
		case *lcommon.VoteDelegationCertificate:
			addCredential(&c.StakeCredential)
		case *lcommon.StakeVoteDelegationCertificate:
			addCredential(&c.StakeCredential)
		case *lcommon.StakeRegistrationDelegationCertificate:
			addCredential(&c.StakeCredential)
		case *lcommon.VoteRegistrationDelegationCertificate:
			addCredential(&c.StakeCredential)
		case *lcommon.StakeVoteRegistrationDelegationCertificate:
			addCredential(&c.StakeCredential)
		case *lcommon.RegistrationDrepCertificate:
			addCredential(&c.DrepCredential)
		case *lcommon.DeregistrationDrepCertificate:
			addCredential(&c.DrepCredential)
		case *lcommon.UpdateDrepCertificate:
			addCredential(&c.DrepCredential)
		case *lcommon.AuthCommitteeHotCertificate:
			// Authorising a committee hot key is witnessed by the member's cold
			// credential. The wallet does not derive committee keys, so a key-hash
			// cold credential remains unmatched below and, with partialSign=false,
			// correctly fails the completeness check rather than returning a
			// witness set that silently omits the required committee witness.
			addCredential(&c.ColdCredential)
		case *lcommon.ResignCommitteeColdCertificate:
			// Resigning is witnessed by the member's cold credential.
			addCredential(&c.ColdCredential)
		}
	}
	for addr := range txBody.TxWithdrawals {
		if addr == nil {
			continue
		}
		if payload, ok := addr.StakingPayload().(lcommon.AddressPayloadKeyHash); ok {
			reqSet[payload.Hash] = true
		}
	}

	// Collect each payment derivation path we must sign for. Only addresses
	// present in pathOf are eligible (no silent role/index-0 fallback):
	// - Inputs at addresses the wallet owns.
	// - Addresses whose payment key matches a required signer.
	signPaths := make(map[paymentKeyPath]bool)
	for _, addrStr := range inputAddrs {
		if path, owned := pathOf[addrStr]; owned {
			signPaths[path] = true
		}
	}
	signStake := false
	signDRep := false

	derivePaymentKey := func(path paymentKeyPath) (bip32.XPrv, error) {
		switch path.role {
		case 0:
			return bursa.GetPaymentKey(acctKey, path.index)
		case 1:
			if path.index >= 0x80000000 {
				return nil, fmt.Errorf("invalid change key index %d", path.index)
			}
			roleKey := acctKey.Derive(1)
			defer func() {
				for i := range roleKey {
					roleKey[i] = 0
				}
			}()
			return roleKey.Derive(path.index), nil
		default:
			return nil, fmt.Errorf("unsupported payment key role %d", path.role)
		}
	}

	// For required signers: iterate all owned signing keys to find matches. This
	// includes receive/change payment keys plus non-payment wallet witnesses such
	// as stake and DRep keys.
	if len(reqSet) > 0 {
		for _, path := range pathOf {
			payKey, err := derivePaymentKey(path)
			if err != nil {
				continue
			}
			vkeyHash := lcommon.Blake2b224Hash(bip32.XPrv(payKey).Public().PublicKey())
			if reqSet[vkeyHash] {
				signPaths[path] = true
				delete(reqSet, vkeyHash)
			}
			for j := range payKey {
				payKey[j] = 0
			}
		}
		stakeKey, err := bursa.GetStakeKey(acctKey, 0)
		if err != nil {
			return nil, fmt.Errorf("stake key: %w", err)
		}
		stakeVkeyHash := lcommon.Blake2b224Hash(bip32.XPrv(stakeKey).Public().PublicKey())
		if reqSet[stakeVkeyHash] {
			signStake = true
			delete(reqSet, stakeVkeyHash)
		}
		for j := range stakeKey {
			stakeKey[j] = 0
		}

		drepKey, err := bursa.GetDRepKey(acctKey, 0)
		if err != nil {
			return nil, fmt.Errorf("drep key: %w", err)
		}
		drepVkeyHash := lcommon.Blake2b224Hash(bip32.XPrv(drepKey).Public().PublicKey())
		if reqSet[drepVkeyHash] {
			signDRep = true
			delete(reqSet, drepVkeyHash)
		}
		for j := range drepKey {
			drepKey[j] = 0
		}
	}

	if len(reqSet) > 0 && !partialSign {
		return nil, fmt.Errorf(
			"%w: wallet cannot provide %d required key witness(es)",
			ErrInvalidRequest,
			len(reqSet),
		)
	}
	if len(signPaths) == 0 && !signStake && !signDRep && !partialSign {
		return nil, fmt.Errorf(
			"%w: no wallet key matches any required signer or input address in this transaction",
			ErrInvalidRequest,
		)
	}

	// Build vkey witnesses for all matched addresses using each address's own
	// derivation index.
	var witnesses []lcommon.VkeyWitness
	appendWitness := func(key bip32.XPrv) {
		witnesses = append(witnesses, lcommon.VkeyWitness{
			Vkey:      bip32.XPrv(key).Public().PublicKey(),
			Signature: bip32.XPrv(key).Sign(txBodyHash.Bytes()),
		})
	}
	for path := range signPaths {
		payKey, err := derivePaymentKey(path)
		if err != nil {
			return nil, fmt.Errorf("payment key role %d idx %d: %w", path.role, path.index, err)
		}
		func() {
			defer func() {
				for j := range payKey {
					payKey[j] = 0
				}
			}()
			appendWitness(payKey)
		}()
	}
	if signStake {
		stakeKey, err := bursa.GetStakeKey(acctKey, 0)
		if err != nil {
			return nil, fmt.Errorf("stake key: %w", err)
		}
		func() {
			defer func() {
				for j := range stakeKey {
					stakeKey[j] = 0
				}
			}()
			appendWitness(stakeKey)
		}()
	}
	if signDRep {
		drepKey, err := bursa.GetDRepKey(acctKey, 0)
		if err != nil {
			return nil, fmt.Errorf("drep key: %w", err)
		}
		func() {
			defer func() {
				for j := range drepKey {
					drepKey[j] = 0
				}
			}()
			appendWitness(drepKey)
		}()
	}

	return witnesses, nil
}

// HardwareSignRequest is the structured signing request the SPA passes to the
// Ledger device (via ledgerjs). It contains decoded tx fields (NOT raw CBOR)
// so the device can display them to the user and sign without parsing CBOR.
//
// Scope: payment transactions (inputs/outputs/fee/ttl/change) only.
// Certificates and withdrawals are guarded — the caller must check Unsupported
// before constructing a SignTransactionRequest.
type HardwareSignRequest struct {
	// Network: "mainnet", "preprod", or "preview".
	Network string `json:"network"`
	// NetworkID: 1 for mainnet, 0 for testnet.
	NetworkID int `json:"network_id"`
	// ProtocolMagic: 764824073 for mainnet, 1 for preprod, 2 for preview.
	ProtocolMagic uint32 `json:"protocol_magic"`
	// Inputs: one entry per tx input the wallet owns.
	Inputs []HWInput `json:"inputs"`
	// Outputs: all tx outputs.
	Outputs []HWOutput `json:"outputs"`
	// Fee: lovelace as decimal string.
	Fee string `json:"fee"`
	// TTL: slot number as decimal string, empty if absent.
	TTL string `json:"ttl,omitempty"`
	// RequiredSigners are the key hashes embedded in the transaction body. The
	// Ledger request must include the identical set or it will sign a different
	// body from UnsignedTxCBOR.
	RequiredSigners []string `json:"required_signers"`
	// IncludeNetworkID preserves body key 15 when it was present in the pending
	// transaction, so Ledger reconstructs and signs the identical body.
	IncludeNetworkID bool `json:"include_network_id,omitempty"`
	// UnsignedTxCBOR: the raw tx hex, used by SubmitSigned.
	UnsignedTxCBOR string `json:"unsigned_tx_cbor"`
	// Unsupported: non-empty means this tx cannot be signed on hardware yet.
	// The SPA MUST show this message and refuse to sign.
	Unsupported string `json:"unsupported,omitempty"`
}

// HWInput is one transaction input in the hardware sign request.
type HWInput struct {
	TxHashHex   string `json:"tx_hash_hex"`
	OutputIndex uint32 `json:"output_index"`
	// Path is the CIP-1852 derivation path ("1852'/1815'/0'/0/3") for the
	// payment key that must sign this input, or "" if the input is not ours.
	Path string `json:"path,omitempty"`
}

// HWOutput is one transaction output in the hardware sign request.
type HWOutput struct {
	// AddressHex is the hex-encoded address bytes. It is used by the SPA for
	// third-party outputs; device-owned outputs are reconstructed from paths.
	AddressHex string `json:"address_hex"`
	// AddressBech32 for display.
	AddressBech32 string `json:"address_bech32"`
	// Lovelace as decimal string.
	Lovelace string `json:"lovelace"`
	// PaymentPath and StakePath identify an output owned by this wallet. They
	// are both set for our base addresses and omitted for third-party outputs.
	PaymentPath string `json:"payment_path,omitempty"`
	StakePath   string `json:"stake_path,omitempty"`
	// Assets: native assets (NOT SUPPORTED yet — guard triggers if non-empty).
	Assets []HWAsset `json:"assets,omitempty"`
}

// HWAsset is a native asset within an output.
type HWAsset struct {
	PolicyIDHex  string `json:"policy_id_hex"`
	AssetNameHex string `json:"asset_name_hex"`
	Amount       string `json:"amount"` // decimal string
}

// HardwareSignRequest returns the structured signing request the SPA passes to
// the Ledger device. It decodes the pending transaction into discrete fields so
// the device can display and sign them without parsing raw CBOR.
//
// Unlike Confirm it does NOT consume the pending entry — it is subject to the
// same TTL. When an unsupported feature is detected the struct is still returned
// with Unsupported set (and UnsignedTxCBOR populated) so the SPA can show the
// user what was attempted.
func (s *Service) HardwareSignRequest(pendingID string) (HardwareSignRequest, error) {
	// Held for the whole function (like ExportUnsigned) so every structured
	// field and UnsignedTxCBOR are read from the same consistent snapshot of
	// the pending entry - not released partway through and re-read after a
	// concurrent Confirm/sweep could touch it.
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[pendingID]
	expired := ok && s.now().Sub(p.created) > pendingTTL
	if !ok {
		return HardwareSignRequest{}, fmt.Errorf("%w: %q", ErrUnknownPending, pendingID)
	}
	if expired {
		return HardwareSignRequest{}, fmt.Errorf("%w: %q", ErrExpiredPending, pendingID)
	}

	tx := p.tx.GetTx()
	if tx == nil {
		return HardwareSignRequest{}, errors.New("pending tx is nil")
	}

	cborBytes, err := p.tx.GetTxCbor()
	if err != nil {
		return HardwareSignRequest{}, fmt.Errorf("encode unsigned tx: %w", err)
	}
	unsignedTxCBOR := hex.EncodeToString(cborBytes)

	// Determine network parameters.
	acct := p.account
	if acct == nil {
		return HardwareSignRequest{}, ErrNoWallet
	}
	networkName := acct.Network
	networkID := 0
	var protocolMagic uint32
	switch networkName {
	case "mainnet":
		networkID = 1
		protocolMagic = 764824073
	case "preprod":
		protocolMagic = 1
	default: // preview; the account network is validated when it is derived.
		protocolMagic = 2
	}

	result := HardwareSignRequest{
		Network:          networkName,
		NetworkID:        networkID,
		ProtocolMagic:    protocolMagic,
		RequiredSigners:  keyHashesHex(tx.Body.RequiredSigners()),
		UnsignedTxCBOR:   unsignedTxCBOR,
		IncludeNetworkID: tx.Body.TxNetworkId != nil,
	}
	if tx.Body.TxNetworkId != nil && int(*tx.Body.TxNetworkId) != networkID {
		result.Unsupported = "transaction network id does not match the active wallet"
		return result, nil
	}

	// Guard unsupported features — still populate UnsignedTxCBOR so the SPA can
	// show the user what was attempted.
	if len(tx.Body.TxCertificates) > 0 {
		result.Unsupported = "certificates are not supported on hardware yet"
		return result, nil
	}
	if len(tx.Body.TxWithdrawals) > 0 {
		result.Unsupported = "withdrawals are not supported on hardware yet"
		return result, nil
	}
	// Note: TxWithdrawals is a map[*Address]uint64; len works on nil maps (returns 0).
	var unsupportedBodyFeature string
	switch {
	case tx.Body.Update != nil:
		unsupportedBodyFeature = "protocol update"
	case tx.Body.TxAuxDataHash != nil:
		unsupportedBodyFeature = "auxiliary data"
	case tx.Body.TxValidityIntervalStart != 0:
		unsupportedBodyFeature = "validity interval start"
	case tx.Body.TxMint != nil:
		unsupportedBodyFeature = "minting"
	case tx.Body.TxScriptDataHash != nil:
		unsupportedBodyFeature = "script data"
	case len(tx.Body.TxCollateral.Items()) > 0:
		unsupportedBodyFeature = "collateral inputs"
	case tx.Body.TxCollateralReturn != nil:
		unsupportedBodyFeature = "collateral return"
	case tx.Body.TxTotalCollateral != 0:
		unsupportedBodyFeature = "total collateral"
	case len(tx.Body.TxReferenceInputs.Items()) > 0:
		unsupportedBodyFeature = "reference inputs"
	case len(tx.Body.TxVotingProcedures) > 0:
		unsupportedBodyFeature = "voting procedures"
	case len(tx.Body.TxProposalProcedures) > 0:
		unsupportedBodyFeature = "proposal procedures"
	case tx.Body.TxCurrentTreasuryValue != 0:
		unsupportedBodyFeature = "current treasury value"
	case tx.Body.TxDonation != 0:
		unsupportedBodyFeature = "treasury donation"
	}
	if unsupportedBodyFeature != "" {
		result.Unsupported = unsupportedBodyFeature + " is not supported on hardware yet"
		return result, nil
	}

	// Guard: native assets in outputs are not supported yet. Check before
	// building inputs so no signing paths are leaked (symmetric with the cert
	// and withdrawal guards above).
	for _, out := range tx.Body.TxOutputs {
		if out.OutputAmount.Assets != nil {
			result.Unsupported = "outputs with native assets are not supported on hardware yet"
			return result, nil
		}
		if out.DatumOption != nil || out.TxOutScriptRef != nil {
			result.Unsupported = "outputs with datum or script references are not supported on hardware yet"
			return result, nil
		}
	}

	// Build address → derivation path lookups for input signing and owned
	// outputs. Although Build currently sends change to receive address 0, keep
	// both roles here so future change-address selection remains correctly
	// represented to the device.
	accountNum := acct.AccountIndex
	idxOf := make(map[string]int, len(acct.ReceiveAddresses))
	pathOf := make(map[string]string, len(acct.ReceiveAddresses)+len(acct.ChangeAddresses))
	for i, addr := range acct.ReceiveAddresses {
		idxOf[addr] = i
		pathOf[addr] = fmt.Sprintf("1852'/%d'/%d'/0/%d", 1815, accountNum, i)
	}
	for i, addr := range acct.ChangeAddresses {
		pathOf[addr] = fmt.Sprintf("1852'/%d'/%d'/1/%d", 1815, accountNum, i)
	}
	stakePath := fmt.Sprintf("1852'/%d'/%d'/2/0", 1815, accountNum)

	// Build inputs with paths.
	// Every owned input gets its correct derivation path; the Ledger tolerates
	// repeated paths. Dedup of witnessPathsNumeric happens on the SPA side.
	inputs := make([]HWInput, 0, len(tx.Body.TxInputs.Items()))
	for _, inp := range tx.Body.TxInputs.Items() {
		ref := hex.EncodeToString(inp.TxId.Bytes()) + "#" + strconv.Itoa(int(inp.OutputIndex))
		hwInp := HWInput{
			TxHashHex:   hex.EncodeToString(inp.TxId.Bytes()),
			OutputIndex: inp.OutputIndex,
		}
		addrStr, found := p.utxoAddr[ref]
		if found {
			if idx, owned := idxOf[addrStr]; owned {
				hwInp.Path = fmt.Sprintf("1852'/%d'/%d'/0/%d", 1815, accountNum, idx)
			}
		}
		inputs = append(inputs, hwInp)
	}
	result.Inputs = inputs

	// Build outputs.
	outputs := make([]HWOutput, 0, len(tx.Body.TxOutputs))
	for _, out := range tx.Body.TxOutputs {
		addr := out.OutputAddress
		addrBytes, bytesErr := addr.Bytes()
		if bytesErr != nil {
			return HardwareSignRequest{}, fmt.Errorf("output address bytes: %w", bytesErr)
		}
		hwOut := HWOutput{
			AddressHex:    hex.EncodeToString(addrBytes),
			AddressBech32: addr.String(),
			Lovelace:      strconv.FormatUint(out.OutputAmount.Amount, 10),
		}
		if paymentPath, owned := pathOf[addr.String()]; owned {
			hwOut.PaymentPath = paymentPath
			hwOut.StakePath = stakePath
		}
		outputs = append(outputs, hwOut)
	}
	result.Outputs = outputs

	// Fee and TTL.
	result.Fee = strconv.FormatUint(tx.Body.TxFee, 10)
	if tx.Body.Ttl > 0 {
		result.TTL = strconv.FormatUint(tx.Body.Ttl, 10)
	}

	return result, nil
}

// randID generates a 16-byte random hex string for pending IDs.
func randID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
