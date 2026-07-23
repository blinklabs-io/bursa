package multisig

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	apollo "github.com/blinklabs-io/apollo/v2"
	"github.com/blinklabs-io/apollo/v2/backend"
	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/bip32"
	"github.com/blinklabs-io/bursa/ui/internal/cardanonet"
	"github.com/blinklabs-io/bursa/ui/internal/keystore"
	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/conway"
)

// Sentinel errors. The API layer maps these to HTTP status codes via errors.Is.
var (
	// ErrInvalidRequest: a malformed policy, participant, recipient, or amount (→ 400).
	ErrInvalidRequest = errors.New("invalid multisig request")
	// ErrUnknownAccount: no saved multi-sig account for the given id (→ 404).
	ErrUnknownAccount = errors.New("unknown multisig account")
	// ErrNoKeystore: the active wallet is read-only (no keystore) so it cannot
	// derive its own participant key or co-sign (→ 409).
	ErrNoKeystore = errors.New("no keystore configured")
	// ErrWrongPassword: keystore authentication failed (→ 401).
	ErrWrongPassword = errors.New("incorrect spending password")
	// ErrInsufficientFunds: coin selection could not fund the spend (→ 422).
	ErrInsufficientFunds = errors.New("insufficient funds")
	// ErrInvalidTx: a supplied transaction CBOR is malformed (→ 400).
	ErrInvalidTx = errors.New("invalid transaction")
	// ErrInvalidWitness: a supplied witness CBOR is malformed, or the collected
	// witnesses do not satisfy the script's threshold (→ 400).
	ErrInvalidWitness = errors.New("invalid witness")
	// ErrSubmitRejected: the node rejected the signed transaction (→ 422).
	ErrSubmitRejected = errors.New("transaction rejected by node")
)

// Participant is one signer in a multi-sig policy. KeyHashHex (Blake2b-224 of the
// CIP-1854 multi-sig vkey, 28 bytes / 56 hex chars) is the only field the script
// needs; VKeyHex (the 32-byte vkey) is optional and carried for display/sharing.
type Participant struct {
	Label      string `json:"label,omitempty"`
	KeyHashHex string `json:"key_hash_hex"`
	VKeyHex    string `json:"vkey_hex,omitempty"`
}

// Policy is the spending rule: a threshold of M participants must sign, optionally
// inside a validity interval bounded by InvalidBefore / InvalidAfter slots.
type Policy struct {
	// Threshold is N in "N-of-M": the number of participant signatures required.
	Threshold int `json:"threshold"`
	// Participants are the M candidate signers.
	Participants []Participant `json:"participants"`
	// InvalidBefore, when non-nil, makes the script invalid before this slot
	// (NewScriptAfter / IntervalBefore: the tx must set validity start ≥ slot).
	InvalidBefore *uint64 `json:"invalid_before,omitempty"`
	// InvalidAfter, when non-nil, makes the script invalid from this slot onward
	// (NewScriptBefore / TTL: the tx must set TTL ≤ slot).
	InvalidAfter *uint64 `json:"invalid_after,omitempty"`
}

// Account is a saved, reusable multi-sig account: a label + policy, plus the
// derived native script (CBOR) and its address. It holds only public material.
type Account struct {
	ID            string `json:"id"`
	Label         string `json:"label"`
	Network       string `json:"network"`
	Policy        Policy `json:"policy"`
	ScriptCBOR    string `json:"script_cbor"`    // hex-encoded native-script CBOR
	ScriptAddress string `json:"script_address"` // bech32 script address (receive)
}

// MyKey is the active wallet's own CIP-1854 multi-sig participant identity, to
// share so others can include it in a policy and so the user can add themselves.
type MyKey struct {
	VKeyHex    string `json:"vkey_hex"`     // 32-byte multi-sig vkey
	KeyHashHex string `json:"key_hash_hex"` // Blake2b-224 of the vkey (28 bytes)
}

// UnsignedTx is the export artifact for a multi-sig spend: the completed-but-
// unsigned tx CBOR plus everything a co-signer / collector needs to coordinate
// signatures off-band (the script's candidate key-hashes and the threshold).
type UnsignedTx struct {
	UnsignedTxCBOR  string   `json:"unsigned_tx_cbor"`
	RequiredSigners []string `json:"required_signers"` // candidate key-hashes (hex) in the script
	Threshold       int      `json:"threshold"`        // how many of them must sign
}

// Witness is one co-signer's vkey witness over an unsigned tx (hex CBOR array of
// common.VkeyWitness, normally length 1 — this co-signer's multi-sig key).
type Witness struct {
	WitnessCBOR string `json:"witness_cbor"`
}

// TxParticipant is one candidate signer of an inspected transaction's policy,
// together with whether a vkey witness for it is already attached.
type TxParticipant struct {
	KeyHash string `json:"key_hash"`
	Label   string `json:"label,omitempty"`
	Signed  bool   `json:"signed"`
}

// TxInfo is the classification of a pasted transaction produced by InspectTx:
// whether it is a native-script multi-sig spend, its recovered policy (if
// any), and per-participant signed status so the UI can show co-signing
// progress.
type TxInfo struct {
	IsMultiSig     bool            `json:"is_multisig"`
	Label          string          `json:"label,omitempty"`
	ScriptHash     string          `json:"script_hash,omitempty"`
	Threshold      int             `json:"threshold,omitempty"`
	Participants   []TxParticipant `json:"participants,omitempty"`
	SignedCount    int             `json:"signed_count"`
	ScriptEmbedded bool            `json:"script_embedded"`
}

// Keystore is the minimal interface the service needs of *keystore.Keystore.
type Keystore interface {
	Exists() bool
	Unlock(password string) (mnemonic []byte, err error)
}

// feePaddingLovelace reserves the few-hundred-lovelace shortfall between Apollo's
// pre-witness fee estimate and the node's minimum once witnesses are attached;
// it mirrors the send path. A multi-sig tx carries several vkey witnesses plus
// the native script, so the headroom matters more here — see
// multisigFeePadding, which scales this baseline for the extra witnesses.
const feePaddingLovelace = 2000

// vkeyWitnessCBORBytes is the CBOR-encoded size of one common.VkeyWitness: a
// 2-element array header (1 byte) plus a 32-byte vkey and a 64-byte signature,
// each prefixed by a 2-byte bstr length header (both exceed the 1-byte
// short-form length threshold of 23 bytes).
const vkeyWitnessCBORBytes = 1 + (2 + 32) + (2 + 64)

// Service manages saved multi-sig accounts and builds/signs/submits their spends.
// It is node-local: spend ops query the embedded node's chain context, signing is
// pure crypto over the keystore. There is no in-memory pending state — a multi-sig
// spend is exported as CBOR and coordinated off-band, so build returns the
// unsigned tx directly (like the air-gap export) rather than holding it.
type Service struct {
	chain backend.ChainContext
	keys  Keystore // may be nil; then my-key and signing are unavailable
	store *store
	mkID  func() string
}

// NewService constructs a Service backed by the JSON store at storePath.
func NewService(cc backend.ChainContext, ks Keystore, storePath string) *Service {
	return &Service{
		chain: cc,
		keys:  ks,
		store: newStore(storePath),
		mkID:  randID,
	}
}

// ---------------------------------------------------------------------------
// Script composition
// ---------------------------------------------------------------------------

// composeScript builds the native script for a policy: an N-of-M threshold over
// the participant key-hashes, wrapped in an "all" with the time-lock clause(s)
// when a validity bound is set. The composition is:
//
//	threshold := NewMultiSigScript(N, keyHash...)            // NofK over pubkey sigs
//	if invalidBefore: after  := NewScriptAfter(invalidBefore) // type 4
//	if invalidAfter:  before := NewScriptBefore(invalidAfter) // type 5
//	script := NewScriptAll(after?, before?, threshold)        // all clauses required
//
// With no time-lock the script is just the threshold script.
func composeScript(p Policy) (*bursa.NativeScript, error) {
	if p.Threshold < 1 {
		return nil, fmt.Errorf("%w: threshold must be at least 1", ErrInvalidRequest)
	}
	if p.Threshold > len(p.Participants) {
		return nil, fmt.Errorf(
			"%w: threshold %d exceeds participant count %d",
			ErrInvalidRequest, p.Threshold, len(p.Participants),
		)
	}
	keyHashes := make([][]byte, 0, len(p.Participants))
	seen := make(map[string]bool, len(p.Participants))
	for _, part := range p.Participants {
		kh, err := hex.DecodeString(strings.TrimSpace(part.KeyHashHex))
		if err != nil {
			return nil, fmt.Errorf("%w: key hash %q is not valid hex: %w", ErrInvalidRequest, part.KeyHashHex, err)
		}
		if len(kh) != 28 {
			return nil, fmt.Errorf(
				"%w: key hash %q must be 28 bytes (Blake2b-224), got %d",
				ErrInvalidRequest, part.KeyHashHex, len(kh),
			)
		}
		if seen[string(kh)] {
			return nil, fmt.Errorf("%w: duplicate participant key hash %s", ErrInvalidRequest, part.KeyHashHex)
		}
		seen[string(kh)] = true
		keyHashes = append(keyHashes, kh)
	}
	if len(keyHashes) == 0 {
		return nil, fmt.Errorf("%w: at least one participant required", ErrInvalidRequest)
	}
	if p.InvalidBefore != nil && p.InvalidAfter != nil && *p.InvalidBefore >= *p.InvalidAfter {
		return nil, fmt.Errorf(
			"%w: invalid_before (%d) must be less than invalid_after (%d)",
			ErrInvalidRequest, *p.InvalidBefore, *p.InvalidAfter,
		)
	}

	threshold, err := bursa.NewMultiSigScript(p.Threshold, keyHashes...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}

	if p.InvalidBefore == nil && p.InvalidAfter == nil {
		return threshold, nil
	}

	clauses := make([]bursa.Script, 0, 3)
	if p.InvalidBefore != nil {
		after, err := bursa.NewScriptAfter(*p.InvalidBefore)
		if err != nil {
			return nil, fmt.Errorf("invalid-before clause: %w", err)
		}
		clauses = append(clauses, after)
	}
	if p.InvalidAfter != nil {
		before, err := bursa.NewScriptBefore(*p.InvalidAfter)
		if err != nil {
			return nil, fmt.Errorf("invalid-after clause: %w", err)
		}
		clauses = append(clauses, before)
	}
	clauses = append(clauses, threshold)
	all, err := bursa.NewScriptAll(clauses...)
	if err != nil {
		return nil, fmt.Errorf("compose timelocked script: %w", err)
	}
	return all, nil
}

// PolicyFromScript recovers a Policy from a decoded native script — the inverse
// of composeScript. It walks the script's node tree looking for exactly the
// shapes composeScript produces: a bare NativeScriptNofK (threshold clause
// only), or a NativeScriptAll wrapping optional time-lock clauses
// (NativeScriptInvalidBefore / NativeScriptInvalidHereafter) plus the NofK.
// Every sub-script under the NofK must be a NativeScriptPubkey — that's the
// only leaf composeScript ever emits there.
//
// Any other shape (including NativeScriptAny, which composeScript never
// produces) is rejected as ErrInvalidTx rather than silently accepted or
// panicked on.
func PolicyFromScript(ns *bursa.NativeScript) (Policy, error) {
	var p Policy
	// composeScript emits exactly one threshold clause and at most one clause of
	// each time-lock type. A non-canonical script (multiple N-of-K clauses, or
	// repeated time-locks) is rejected rather than silently collapsed to the
	// last one seen: the node validates ALL clauses of an `all`, so showing and
	// threshold-checking only one would let cosigning report readiness while the
	// node still rejects the tx.
	var nofk, invalidBefore, invalidAfter int
	var walk func(node *lcommon.NativeScript) error
	walk = func(node *lcommon.NativeScript) error {
		switch v := node.Item().(type) {
		case *lcommon.NativeScriptNofK:
			nofk++
			if nofk > 1 {
				return fmt.Errorf("%w: native script has more than one threshold clause", ErrInvalidTx)
			}
			parts := make([]Participant, 0, len(v.Scripts))
			for i := range v.Scripts {
				pk, ok := v.Scripts[i].Item().(*lcommon.NativeScriptPubkey)
				if !ok {
					return fmt.Errorf("%w: threshold clause holds a non-pubkey sub-script", ErrInvalidTx)
				}
				parts = append(parts, Participant{KeyHashHex: hex.EncodeToString(pk.Hash)})
			}
			p.Threshold = int(v.N)
			p.Participants = parts
		case *lcommon.NativeScriptInvalidBefore:
			invalidBefore++
			if invalidBefore > 1 {
				return fmt.Errorf("%w: native script has more than one invalid-before clause", ErrInvalidTx)
			}
			slot := v.Slot
			p.InvalidBefore = &slot
		case *lcommon.NativeScriptInvalidHereafter:
			invalidAfter++
			if invalidAfter > 1 {
				return fmt.Errorf("%w: native script has more than one invalid-hereafter clause", ErrInvalidTx)
			}
			slot := v.Slot
			p.InvalidAfter = &slot
		case *lcommon.NativeScriptAll:
			for i := range v.Scripts {
				if err := walk(&v.Scripts[i]); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("%w: unsupported native-script shape for a multisig policy", ErrInvalidTx)
		}
		return nil
	}
	if err := walk(ns); err != nil {
		return Policy{}, err
	}
	if p.Threshold == 0 || len(p.Participants) == 0 {
		return Policy{}, fmt.Errorf("%w: script has no threshold clause", ErrInvalidTx)
	}
	return p, nil
}

// scriptAddress derives the canonical Cardano script address for a native script.
//
// IMPORTANT: this does NOT use bursa.GetScriptAddress, which hashes only the bare
// script CBOR (RawScriptBytes) and so produces a credential the ledger never
// agrees with — funds sent there would be unspendable. The ledger (and apollo's
// AttachScript dedup) hash Blake2b-224(0x00 || scriptCBOR), which is exactly what
// NativeScript.Hash() computes. We build the address from that hash so the
// payment credential matches the script the ledger validates on spend.
func scriptAddress(script *bursa.NativeScript, network string) (string, error) {
	netID, err := cardanonet.AddressNetworkID(network)
	if err != nil {
		return "", err
	}
	hash := script.Hash() // Blake2b-224(0x00 || cbor); the canonical native-script hash
	addr, err := lcommon.NewAddressFromParts(lcommon.AddressTypeScriptNone, netID, hash.Bytes(), nil)
	if err != nil {
		return "", fmt.Errorf("script address: %w", err)
	}
	return addr.String(), nil
}

// ---------------------------------------------------------------------------
// Account CRUD
// ---------------------------------------------------------------------------

// List returns the saved multi-sig accounts.
func (s *Service) List() ([]Account, error) {
	accts, err := s.store.list()
	if err != nil {
		return nil, err
	}
	if accts == nil {
		accts = []Account{}
	}
	return accts, nil
}

// Get returns one saved account by id.
func (s *Service) Get(id string) (Account, error) {
	return s.store.get(id)
}

// Delete removes a saved account by id.
func (s *Service) Delete(id string) error {
	return s.store.remove(id)
}

// FindByScriptHash searches the saved accounts for one whose native script
// hashes to scriptHashHex (as produced by NativeScript.Hash). It returns
// (Account{}, false, nil) when no account matches. A saved account whose
// ScriptCBOR fails to decode is skipped rather than aborting the search —
// one corrupt record must not hide every other account.
func (s *Service) FindByScriptHash(scriptHashHex string) (Account, bool, error) {
	accts, err := s.store.list()
	if err != nil {
		return Account{}, false, err
	}
	want := strings.ToLower(strings.TrimSpace(scriptHashHex))
	for _, a := range accts {
		script, err := decodeScript(a.ScriptCBOR)
		if err != nil {
			continue
		}
		if strings.ToLower(hex.EncodeToString(script.Hash().Bytes())) == want {
			return a, true, nil
		}
	}
	return Account{}, false, nil
}

// CreateRequest is the input to Create: a label, the network, and the policy.
type CreateRequest struct {
	Label   string `json:"label"`
	Network string `json:"network"`
	Policy  Policy `json:"policy"`
}

// Create composes the script for the policy, derives its address, persists the
// account, and returns it. The network must be a supported Cardano network.
func (s *Service) Create(req CreateRequest) (Account, error) {
	label := strings.TrimSpace(req.Label)
	if label == "" {
		return Account{}, fmt.Errorf("%w: label is required", ErrInvalidRequest)
	}
	if !cardanonet.ValidNetwork(req.Network) {
		return Account{}, fmt.Errorf("%w: unknown network %q", ErrInvalidRequest, req.Network)
	}
	script, err := composeScript(req.Policy)
	if err != nil {
		return Account{}, err
	}
	addr, err := scriptAddress(script, req.Network)
	if err != nil {
		return Account{}, err
	}
	acct := Account{
		ID:            s.mkID(),
		Label:         label,
		Network:       req.Network,
		Policy:        req.Policy,
		ScriptCBOR:    hex.EncodeToString(script.Cbor()),
		ScriptAddress: addr,
	}
	if err := s.store.add(acct); err != nil {
		return Account{}, err
	}
	return acct, nil
}

// ---------------------------------------------------------------------------
// The wallet's own participant key (CIP-1854)
// ---------------------------------------------------------------------------

// MyKey derives the active wallet's CIP-1854 multi-sig participant identity from
// the keystore seed: multi-sig account key 0 → multi-sig payment key 0 → its
// 32-byte vkey and the Blake2b-224 key-hash used in scripts. It needs the
// spending password (to unlock the seed) but no node. The user shares the
// key-hash (and/or vkey) so co-signers can include them in a policy.
func (s *Service) MyKey(password string) (MyKey, error) {
	if s.keys == nil || !s.keys.Exists() {
		return MyKey{}, ErrNoKeystore
	}
	mnemonicBytes, err := s.keys.Unlock(password)
	if err != nil {
		if errors.Is(err, keystore.ErrDecryptFailed) {
			return MyKey{}, fmt.Errorf("%w: %w", ErrWrongPassword, err)
		}
		return MyKey{}, fmt.Errorf("unlock keystore: %w", err)
	}
	var rootKey, acctKey, payKey bip32.XPrv
	defer func() {
		for _, k := range []bip32.XPrv{rootKey, acctKey, payKey} {
			zero(k)
		}
		zeroBytes(mnemonicBytes)
	}()

	rootKey, err = bursa.GetRootKeyFromMnemonic(string(mnemonicBytes), "")
	if err != nil {
		return MyKey{}, fmt.Errorf("root key: %w", err)
	}
	acctKey, err = bursa.GetMultiSigAccountKey(rootKey, 0)
	if err != nil {
		return MyKey{}, fmt.Errorf("multisig account key: %w", err)
	}
	payKey, err = bursa.GetMultiSigPaymentKey(acctKey, 0)
	if err != nil {
		return MyKey{}, fmt.Errorf("multisig payment key: %w", err)
	}
	vkey := payKey.Public().PublicKey() // 32-byte ed25519 vkey
	keyHash := lcommon.Blake2b224Hash(vkey)
	return MyKey{
		VKeyHex:    hex.EncodeToString(vkey),
		KeyHashHex: hex.EncodeToString(keyHash.Bytes()),
	}, nil
}

// ---------------------------------------------------------------------------
// Spend: build → (collect witnesses) → submit
// ---------------------------------------------------------------------------

// Balance returns the lovelace held at the account's script address as a decimal
// string (uint64-safe, matching the read-side balance API).
func (s *Service) Balance(ctx context.Context, id string) (string, error) {
	acct, err := s.store.get(id)
	if err != nil {
		return "", err
	}
	addr, err := lcommon.NewAddress(acct.ScriptAddress)
	if err != nil {
		return "", fmt.Errorf("script address: %w", err)
	}
	utxos, err := s.chain.Utxos(ctx, addr)
	if err != nil {
		return "", fmt.Errorf("utxos for %s: %w", acct.ScriptAddress, err)
	}
	var total uint64
	for _, u := range utxos {
		if u.Output == nil {
			continue
		}
		amt := u.Output.Amount()
		if amt != nil {
			total += amt.Uint64()
		}
	}
	return strconv.FormatUint(total, 10), nil
}

// BuildRequest is the input to Build: where to send and how much.
type BuildRequest struct {
	To       string `json:"to"`
	Lovelace string `json:"lovelace"` // decimal lovelace string (uint64-safe)
}

// multisigFeePadding returns the fee padding for a Build spend. Apollo's fee
// estimator sizes its dummy tx for exactly one vkey witness (see its
// estimateFee docs), but Submit may ultimately attach anywhere from the
// policy's threshold up to all participantCount candidate key-hashes —
// co-signers are free to add a witness beyond what the threshold strictly
// needs, and Submit keeps every valid one it is given (see Submit). Pad for
// the worst case (every participant signs) using the network's actual
// per-byte fee coefficient, on top of the flat feePaddingLovelace shortfall
// margin that mirrors the single-sig send path. Overpaying a little is
// harmless — change returns to the script address — but underpaying causes a
// hard FeeTooSmallUTxO node rejection once the extra witnesses are attached.
func (s *Service) multisigFeePadding(ctx context.Context, participantCount int) (int64, error) {
	extraWitnesses := participantCount - 1
	if extraWitnesses < 1 {
		return feePaddingLovelace, nil
	}
	pp, err := s.chain.ProtocolParams(ctx)
	if err != nil {
		return 0, err
	}
	return feePaddingLovelace + int64(extraWitnesses)*vkeyWitnessCBORBytes*pp.MinFeeCoefficient, nil
}

// Build composes a transaction spending UTxOs at the account's script address.
// It loads the script-address UTxOs, pays the recipient (change returns to the
// script address), attaches the native script to the witness set, and — when the
// policy is time-locked — sets the tx validity interval so the script's bounds
// are satisfied. The completed-but-unsigned tx CBOR is returned along with the
// script's candidate key-hashes and threshold, so co-signers can be coordinated.
//
// Unlike the send path there is no in-memory pending entry: the unsigned tx is
// the durable artifact, carried/collected off-band and handed back to Submit.
func (s *Service) Build(ctx context.Context, id string, req BuildRequest) (UnsignedTx, error) {
	acct, err := s.store.get(id)
	if err != nil {
		return UnsignedTx{}, err
	}
	script, err := decodeScript(acct.ScriptCBOR)
	if err != nil {
		return UnsignedTx{}, err
	}

	scriptAddr, err := lcommon.NewAddress(acct.ScriptAddress)
	if err != nil {
		return UnsignedTx{}, fmt.Errorf("script address: %w", err)
	}
	recvAddr, err := lcommon.NewAddress(strings.TrimSpace(req.To))
	if err != nil {
		return UnsignedTx{}, fmt.Errorf("%w: recipient %q: %w", ErrInvalidRequest, req.To, err)
	}
	lovelace, err := parseAmount(req.Lovelace)
	if err != nil {
		return UnsignedTx{}, fmt.Errorf("%w: lovelace: %w", ErrInvalidRequest, err)
	}

	keyHashes, err := scriptKeyHashes(acct.Policy)
	if err != nil {
		return UnsignedTx{}, err
	}
	padding, err := s.multisigFeePadding(ctx, len(keyHashes))
	if err != nil {
		return UnsignedTx{}, fmt.Errorf("protocol params: %w", err)
	}

	// Change returns to the script address so the account stays funded.
	a := apollo.New(s.chain).
		SetWallet(apollo.NewExternalWallet(scriptAddr)).
		SetChangeAddress(scriptAddr).
		SetFeePadding(padding)

	utxos, err := s.chain.Utxos(ctx, scriptAddr)
	if err != nil {
		return UnsignedTx{}, fmt.Errorf("utxos for %s: %w", acct.ScriptAddress, err)
	}
	if len(utxos) == 0 {
		return UnsignedTx{}, fmt.Errorf("%w: no UTxOs at script address", ErrInsufficientFunds)
	}
	a = a.AddLoadedUTxOs(utxos...)

	a = a.PayToAddress(recvAddr, int64(lovelace)) //nolint:gosec // validated by parseAmount

	// Attach the native script so the witness set carries it (the ledger needs
	// the script that hashes to the input's payment credential). We deliberately
	// do NOT register the participant key-hashes as tx-level required signers:
	// the ledger enforces reqSignerHashes unconditionally, on top of (not instead
	// of) the native script's own threshold check, so listing every candidate
	// there would force all M participants to sign even when the policy only
	// needs N-of-M. The script's threshold, evaluated against whichever vkey
	// witnesses Submit ultimately attaches, is what enforces the policy — see
	// multisigFeePadding for how the fee still accounts for those witnesses.
	a = a.AttachScript(*script)

	// Time-locks: a "before" bound (InvalidAfter) sets the tx TTL; an "after"
	// bound (InvalidBefore) sets the validity start. The interval must lie inside
	// the script's bounds or the ledger rejects the spend.
	if acct.Policy.InvalidBefore != nil {
		start := *acct.Policy.InvalidBefore
		if start > math.MaxInt64 {
			return UnsignedTx{}, fmt.Errorf("%w: invalid_before slot out of range", ErrInvalidRequest)
		}
		a = a.SetValidityStart(int64(start)) //nolint:gosec // bounded above
	}
	if acct.Policy.InvalidAfter != nil {
		ttl := *acct.Policy.InvalidAfter
		if ttl > math.MaxInt64 {
			return UnsignedTx{}, fmt.Errorf("%w: invalid_after slot out of range", ErrInvalidRequest)
		}
		a = a.SetTtl(int64(ttl)) //nolint:gosec // bounded above
	}

	a, err = a.CompleteContext(ctx)
	if err != nil {
		if isInsufficientFundsError(err) {
			return UnsignedTx{}, fmt.Errorf("%w: %w", ErrInsufficientFunds, err)
		}
		return UnsignedTx{}, fmt.Errorf("complete transaction: %w", err)
	}

	cborBytes, err := a.GetTxCbor()
	if err != nil {
		return UnsignedTx{}, fmt.Errorf("encode unsigned tx: %w", err)
	}

	signers := make([]string, len(keyHashes))
	for i, kh := range keyHashes {
		signers[i] = hex.EncodeToString(kh)
	}
	return UnsignedTx{
		UnsignedTxCBOR:  hex.EncodeToString(cborBytes),
		RequiredSigners: signers,
		Threshold:       acct.Policy.Threshold,
	}, nil
}

// InspectTx classifies a pasted transaction CBOR: whether it is a native-
// script multi-sig spend, its recovered policy, and per-participant signed
// status. It prefers an embedded native script (Build attaches one to the
// witness set); when found, it also tries to match a saved account by script
// hash to recover a friendly label and any saved participant labels. A native
// script that isn't a recognizable N-of-M policy is still reported as
// multi-sig (with the script hash set) but leaves the policy fields empty so
// the UI can warn, rather than erroring. A tx with no embedded native script
// at all — without chain resolution of its inputs there is nothing to match
// against — is reported as not multi-sig.
//
// A native script rides in the witness set for exactly one of two reasons:
// (a) it authorizes minting under its policy ID, or (b) it satisfies a
// script-locked spend input. An ordinary vkey-signed payment that also mints
// an NFT/token under a native-script policy (a common DApp-built tx) carries
// a native script for reason (a) only and must NOT be classified as a
// multisig spend. InspectTx tells the two apart: it collects the tx body's
// mint policy IDs and, among the embedded scripts, selects the first one that
// either matches a saved multisig account (definitely a spend) or whose hash
// is not a mint policy (so it must be there for a spend). If every embedded
// script is purely a mint policy, the tx is reported as not multi-sig so it
// routes to the ordinary vkey path.
func (s *Service) InspectTx(txCbor string) (TxInfo, error) {
	txBytes, err := hex.DecodeString(strings.TrimSpace(txCbor))
	if err != nil {
		return TxInfo{}, fmt.Errorf("%w: tx hex: %w", ErrInvalidTx, err)
	}
	var tx conway.ConwayTransaction
	if _, err := cbor.Decode(txBytes, &tx); err != nil {
		return TxInfo{}, fmt.Errorf("%w: %w", ErrInvalidTx, err)
	}

	scripts := tx.WitnessSet.NativeScripts()
	if len(scripts) == 0 {
		return TxInfo{IsMultiSig: false}, nil
	}

	mintPolicies := make(map[string]bool)
	if mint := tx.Body.AssetMint(); mint != nil {
		for _, pol := range mint.Policies() {
			mintPolicies[hex.EncodeToString(pol.Bytes())] = true
		}
	}

	// An embedded native script is present for one of two reasons: it authorizes
	// minting under its policy ID, or it satisfies a script-locked spend input.
	// A script whose hash is a mint policy MAY be there only for minting, so its
	// presence — even matching a saved account — is NOT proof of a spend
	// (resolving the inputs would be required to know, and that needs a node).
	// A script that is not a mint policy can only be there to satisfy a spend,
	// so those are the candidate spend scripts.
	var candidates []*lcommon.NativeScript
	for i := range scripts {
		hash := hex.EncodeToString(scripts[i].Hash().Bytes())
		if !mintPolicies[hash] {
			candidates = append(candidates, &scripts[i])
		}
	}
	switch len(candidates) {
	case 0:
		// Every embedded native script is a mint policy: without resolving the
		// inputs there is no evidence of a script-locked spend, so this is an
		// ordinary tx that mints under a native-script policy — route to the
		// vkey path. (A mint policy that also happens to be saved as a multisig
		// account in this wallet is NOT treated as a spend on that basis alone.)
		return TxInfo{IsMultiSig: false}, nil
	case 1:
		// Exactly one candidate spend script — the supported case.
	default:
		// The spend is protected by more than one native script. Only a single
		// policy can be inspected and threshold-checked here; classifying against
		// just the first would let the UI report readiness while another script
		// stays unsatisfied. Report multi-sig but leave the policy fields empty
		// (Threshold stays 0), so CosignImported/SubmitImported refuse it rather
		// than guess.
		return TxInfo{IsMultiSig: true, ScriptEmbedded: true}, nil
	}
	ns := candidates[0]
	scriptHash := hex.EncodeToString(ns.Hash().Bytes())

	policy, err := PolicyFromScript(ns)
	if err != nil {
		// Not a recognizable N-of-M policy: report multi-sig + the script hash
		// so the UI can warn, but leave the policy fields empty. Deliberately
		// not an error — this is a classification result, not a failure.
		return TxInfo{IsMultiSig: true, ScriptEmbedded: true, ScriptHash: scriptHash}, nil //nolint:nilerr // classification, not failure — see comment above
	}

	info := TxInfo{
		IsMultiSig:     true,
		ScriptEmbedded: true,
		ScriptHash:     scriptHash,
		Threshold:      policy.Threshold,
	}
	if acct, ok, _ := s.FindByScriptHash(scriptHash); ok {
		info.Label = acct.Label
		policy = mergeParticipantLabels(policy, acct.Policy)
	}

	// Signed participants = vkey witnesses already attached whose key-hash is a
	// policy participant AND whose signature verifies over the tx body bytes.
	// Key-hashes are compared case-insensitively. Verifying the signature is
	// essential: a pasted tx can carry a bogus witness for a participant's key,
	// and counting it toward the threshold would let SubmitImported broadcast a
	// tx the node then rejects.
	bodyCbor := tx.Body.Cbor()
	if bodyCbor == nil {
		bodyCbor, err = cbor.Encode(&tx.Body)
		if err != nil {
			return TxInfo{}, fmt.Errorf("encode tx body: %w", err)
		}
	}
	bodyHash := lcommon.Blake2b256Hash(bodyCbor)
	signed := make(map[string]bool, len(tx.WitnessSet.VkeyWitnesses.Items()))
	for _, w := range tx.WitnessSet.VkeyWitnesses.Items() {
		if !vkeyWitnessValid(w, bodyHash.Bytes()) {
			continue
		}
		kh := strings.ToLower(hex.EncodeToString(lcommon.Blake2b224Hash(w.Vkey).Bytes()))
		signed[kh] = true
	}
	info.Participants = make([]TxParticipant, 0, len(policy.Participants))
	for _, part := range policy.Participants {
		kh := strings.ToLower(part.KeyHashHex)
		p := TxParticipant{KeyHash: kh, Label: part.Label, Signed: signed[kh]}
		if p.Signed {
			info.SignedCount++
		}
		info.Participants = append(info.Participants, p)
	}
	return info, nil
}

// Sign is a co-signer's step: it decrypts the seed, derives the wallet's CIP-1854
// multi-sig key (NOT the CIP-1852 payment key used for ordinary sends), and emits
// that key's vkey witness over the unsigned tx body. The witness is collected with
// the others and handed to Submit. It needs only the unsigned tx CBOR and the
// password — no node.
func (s *Service) Sign(unsignedTxCBOR, password string) (Witness, error) {
	if s.keys == nil || !s.keys.Exists() {
		return Witness{}, ErrNoKeystore
	}
	loader, err := apollo.New(s.chain).LoadTxCbor(unsignedTxCBOR)
	if err != nil {
		return Witness{}, fmt.Errorf("%w: %w", ErrInvalidTx, err)
	}
	tx := loader.GetTx()
	if tx == nil {
		return Witness{}, fmt.Errorf("%w: no transaction body", ErrInvalidTx)
	}
	// Witnesses sign the exact body bytes carried by the unsigned transaction.
	// Re-encoding can drift while preserving semantics.
	bodyCbor := tx.Body.Cbor()
	if bodyCbor == nil {
		bodyCbor, err = cbor.Encode(&tx.Body)
		if err != nil {
			return Witness{}, fmt.Errorf("encode tx body: %w", err)
		}
	}
	bodyHash := lcommon.Blake2b256Hash(bodyCbor)

	mnemonicBytes, err := s.keys.Unlock(password)
	if err != nil {
		if errors.Is(err, keystore.ErrDecryptFailed) {
			return Witness{}, fmt.Errorf("%w: %w", ErrWrongPassword, err)
		}
		return Witness{}, fmt.Errorf("unlock keystore: %w", err)
	}
	var rootKey, acctKey, payKey bip32.XPrv
	defer func() {
		for _, k := range []bip32.XPrv{rootKey, acctKey, payKey} {
			zero(k)
		}
		zeroBytes(mnemonicBytes)
	}()

	rootKey, err = bursa.GetRootKeyFromMnemonic(string(mnemonicBytes), "")
	if err != nil {
		return Witness{}, fmt.Errorf("root key: %w", err)
	}
	acctKey, err = bursa.GetMultiSigAccountKey(rootKey, 0)
	if err != nil {
		return Witness{}, fmt.Errorf("multisig account key: %w", err)
	}
	payKey, err = bursa.GetMultiSigPaymentKey(acctKey, 0)
	if err != nil {
		return Witness{}, fmt.Errorf("multisig payment key: %w", err)
	}

	w, err := apollo.NewVkeyWitnessFromSkey(bodyHash, []byte(payKey))
	if err != nil {
		return Witness{}, fmt.Errorf("sign with multisig key: %w", err)
	}
	encoded, err := cbor.Encode([]lcommon.VkeyWitness{w})
	if err != nil {
		return Witness{}, fmt.Errorf("encode witness: %w", err)
	}
	return Witness{WitnessCBOR: hex.EncodeToString(encoded)}, nil
}

// Submit is the final step: it loads the unsigned tx, attaches the account's
// native script, decodes and attaches the collected co-signer vkey witnesses,
// verifies that at least `threshold` of the script's participant key-hashes are
// covered, and submits. Witnesses are deduped by key-hash and only those that
// belong to the script's participants are attached; the tx body is never mutated
// so the witnesses' body hash still matches.
//
// witnessCBORs is the list of per-co-signer witness blobs (each a hex CBOR array
// of common.VkeyWitness) collected during the multi-party flow.
func (s *Service) Submit(ctx context.Context, id, unsignedTxCBOR string, witnessCBORs []string) (TxResult, error) {
	acct, err := s.store.get(id)
	if err != nil {
		return TxResult{}, err
	}
	script, err := decodeScript(acct.ScriptCBOR)
	if err != nil {
		return TxResult{}, err
	}
	participants, err := scriptKeyHashes(acct.Policy)
	if err != nil {
		return TxResult{}, err
	}
	participantSet := make(map[string]bool, len(participants))
	for _, kh := range participants {
		participantSet[hex.EncodeToString(kh)] = true
	}

	a, err := apollo.New(s.chain).LoadTxCbor(unsignedTxCBOR)
	if err != nil {
		return TxResult{}, fmt.Errorf("%w: %w", ErrInvalidTx, err)
	}
	tx := a.GetTx()
	if tx == nil {
		return TxResult{}, fmt.Errorf("%w: no transaction body", ErrInvalidTx)
	}

	// Re-attach the native script. LoadTxCbor restores whatever witness set the
	// unsigned tx carried (Build already attached it), but attaching again is
	// idempotent (AttachScript dedups by hash) and makes Submit robust to an
	// unsigned tx assembled elsewhere.
	a = a.AttachScript(*script)

	// Decode and attach every collected witness that belongs to a script
	// participant, deduped by key-hash.
	attached := make(map[string]bool)
	for i, wc := range witnessCBORs {
		witBytes, err := hex.DecodeString(strings.TrimSpace(wc))
		if err != nil {
			return TxResult{}, fmt.Errorf("%w: witness %d hex: %w", ErrInvalidWitness, i, err)
		}
		var witnesses []lcommon.VkeyWitness
		if _, err := cbor.Decode(witBytes, &witnesses); err != nil {
			return TxResult{}, fmt.Errorf("%w: witness %d: %w", ErrInvalidWitness, i, err)
		}
		for _, wit := range witnesses {
			kh := hex.EncodeToString(lcommon.Blake2b224Hash(wit.Vkey).Bytes())
			if !participantSet[kh] || attached[kh] {
				continue
			}
			attached[kh] = true
			if a, err = a.AddVerificationKeyWitness(wit); err != nil {
				return TxResult{}, fmt.Errorf("attach witness: %w", err)
			}
		}
	}

	if len(attached) < acct.Policy.Threshold {
		return TxResult{}, fmt.Errorf(
			"%w: have %d of %d required signatures",
			ErrInvalidWitness, len(attached), acct.Policy.Threshold,
		)
	}

	// LoadTxCbor cached the decoded tx's raw CBOR; clear the tx-level and
	// witness-set caches so SubmitContext re-serializes the witnesses + script we
	// attached. The BODY cache stays intact: the witnesses signed the original
	// body bytes (mirrors the send path's SubmitSigned).
	tx.SetCbor(nil)
	tx.WitnessSet.SetCbor(nil)

	txHash, err := a.SubmitContext(context.WithoutCancel(ctx))
	if err != nil {
		return TxResult{}, fmt.Errorf("%w: %w", ErrSubmitRejected, err)
	}
	return TxResult{TxHash: hex.EncodeToString(txHash.Bytes())}, nil
}

// TxResult is returned from Submit after broadcast.
type TxResult struct {
	TxHash string `json:"tx_hash"`
}

// SubmitImported is the "paste a fully co-signed tx, broadcast it" flow: the
// counterpart to CosignImported's off-band CBOR-passing workflow, where
// instead of collecting separate witness blobs (Submit's contract) the
// growing signed tx CBOR itself has been passed from co-signer to co-signer
// and this is the final hop. It classifies the tx via InspectTx, verifies the
// collected witnesses meet the script's threshold, and broadcasts —
// mirroring Submit's byte-safety (clear the tx-level and witness-set CBOR
// caches, leave the body cache intact) and submit call.
func (s *Service) SubmitImported(ctx context.Context, txCbor string) (TxResult, error) {
	info, err := s.InspectTx(txCbor)
	if err != nil {
		return TxResult{}, err
	}
	if !info.IsMultiSig || info.Threshold == 0 {
		return TxResult{}, fmt.Errorf("%w: not a recognizable multisig transaction", ErrInvalidTx)
	}

	a, err := apollo.New(s.chain).LoadTxCbor(strings.TrimSpace(txCbor))
	if err != nil {
		return TxResult{}, fmt.Errorf("%w: %w", ErrInvalidTx, err)
	}
	tx := a.GetTx()
	if tx == nil {
		return TxResult{}, fmt.Errorf("%w: no transaction body", ErrInvalidTx)
	}

	// A multisig tx always carries its native script: Build attaches it and
	// co-signing preserves it, so a tx that reaches here is guaranteed to have
	// an embedded script (the !IsMultiSig guard above rejects any tx without a
	// recognizable embedded native-script policy). Recovering a stripped script
	// from a saved account would require chain-based input resolution and is out
	// of scope; see InspectTx.

	if info.SignedCount < info.Threshold {
		return TxResult{}, fmt.Errorf(
			"%w: have %d of %d required signatures",
			ErrInvalidWitness, info.SignedCount, info.Threshold,
		)
	}

	// LoadTxCbor cached the decoded tx's raw CBOR; clear the tx-level and
	// witness-set caches so SubmitContext re-serializes the (possibly
	// newly-attached) script and witnesses. The BODY cache stays intact: the
	// witnesses signed the original body bytes (mirrors Submit).
	tx.SetCbor(nil)
	tx.WitnessSet.SetCbor(nil)

	txHash, err := a.SubmitContext(context.WithoutCancel(ctx))
	if err != nil {
		return TxResult{}, fmt.Errorf("%w: %w", ErrSubmitRejected, err)
	}
	return TxResult{TxHash: hex.EncodeToString(txHash.Bytes())}, nil
}

// CosignResult is returned from CosignImported: the merged tx CBOR plus
// enough bookkeeping (whether this cosign actually added a new witness, how
// many participant signatures the tx now carries, and the policy threshold)
// for the UI to show cosigning progress and decide whether the tx is ready to
// submit.
type CosignResult struct {
	TxCBOR      string `json:"tx_cbor"`
	Added       bool   `json:"added"`
	SignedCount int    `json:"signed_count"`
	Threshold   int    `json:"threshold"`
}

// CosignImported is the "paste a tx, cosign it, hand back the CBOR" flow: an
// alternative to Sign+Submit's off-band witness collection where instead the
// growing signed tx CBOR itself is passed from co-signer to co-signer. It
// derives this wallet's CIP-1854 multi-sig key exactly as Sign does, verifies
// (via InspectTx's recovered policy) that the wallet's key-hash is actually a
// participant in the tx's script — refusing with ErrInvalidRequest otherwise,
// since signing a script this wallet has no part in cannot help satisfy it —
// then signs the tx's body hash and merges the resulting witness into the
// tx's existing witness set, preserving whatever co-signer witnesses are
// already attached. Merging is deduped by key-hash, so cosigning a tx that
// already carries this wallet's witness is a no-op (Added=false).
func (s *Service) CosignImported(txCbor, password string) (CosignResult, error) {
	if s.keys == nil || !s.keys.Exists() {
		return CosignResult{}, ErrNoKeystore
	}
	info, err := s.InspectTx(txCbor)
	if err != nil {
		return CosignResult{}, err
	}
	if !info.IsMultiSig || info.Threshold == 0 {
		return CosignResult{}, fmt.Errorf("%w: not a recognizable multisig transaction", ErrInvalidTx)
	}
	participants := make(map[string]bool, len(info.Participants))
	for _, p := range info.Participants {
		participants[strings.ToLower(p.KeyHash)] = true
	}

	a, err := apollo.New(s.chain).LoadTxCbor(strings.TrimSpace(txCbor))
	if err != nil {
		return CosignResult{}, fmt.Errorf("%w: %w", ErrInvalidTx, err)
	}
	tx := a.GetTx()
	if tx == nil {
		return CosignResult{}, fmt.Errorf("%w: no transaction body", ErrInvalidTx)
	}
	// Witnesses sign the exact body bytes carried by the imported transaction.
	// Re-encoding can drift while preserving semantics (mirrors Sign).
	bodyCbor := tx.Body.Cbor()
	if bodyCbor == nil {
		bodyCbor, err = cbor.Encode(&tx.Body)
		if err != nil {
			return CosignResult{}, fmt.Errorf("encode tx body: %w", err)
		}
	}
	bodyHash := lcommon.Blake2b256Hash(bodyCbor)

	mnemonicBytes, err := s.keys.Unlock(password)
	if err != nil {
		if errors.Is(err, keystore.ErrDecryptFailed) {
			return CosignResult{}, fmt.Errorf("%w: %w", ErrWrongPassword, err)
		}
		return CosignResult{}, fmt.Errorf("unlock keystore: %w", err)
	}
	var rootKey, acctKey, payKey bip32.XPrv
	defer func() {
		for _, k := range []bip32.XPrv{rootKey, acctKey, payKey} {
			zero(k)
		}
		zeroBytes(mnemonicBytes)
	}()

	rootKey, err = bursa.GetRootKeyFromMnemonic(string(mnemonicBytes), "")
	if err != nil {
		return CosignResult{}, fmt.Errorf("root key: %w", err)
	}
	acctKey, err = bursa.GetMultiSigAccountKey(rootKey, 0)
	if err != nil {
		return CosignResult{}, fmt.Errorf("multisig account key: %w", err)
	}
	payKey, err = bursa.GetMultiSigPaymentKey(acctKey, 0)
	if err != nil {
		return CosignResult{}, fmt.Errorf("multisig payment key: %w", err)
	}
	myKH := strings.ToLower(hex.EncodeToString(lcommon.Blake2b224Hash(payKey.Public().PublicKey()).Bytes()))
	if !participants[myKH] {
		return CosignResult{}, fmt.Errorf(
			"%w: this wallet is not a participant in the transaction's policy",
			ErrInvalidRequest,
		)
	}

	// Rebuild the witness set from only the existing witnesses whose signature
	// verifies over the body bytes, deduped by lower-case key-hash. Counting or
	// deduping by key-hash alone is unsafe: a pasted tx can carry an invalid
	// witness bearing this wallet's own key, which would make this cosign a
	// no-op (added=false) and leave the bogus witness in place for the node to
	// reject. Dropping non-verifying witnesses lets our valid one replace it.
	signed := make(map[string]bool, len(tx.WitnessSet.VkeyWitnesses.Items()))
	kept := make([]lcommon.VkeyWitness, 0, len(tx.WitnessSet.VkeyWitnesses.Items()))
	for _, w := range tx.WitnessSet.VkeyWitnesses.Items() {
		if !vkeyWitnessValid(w, bodyHash.Bytes()) {
			continue
		}
		kh := strings.ToLower(hex.EncodeToString(lcommon.Blake2b224Hash(w.Vkey).Bytes()))
		if signed[kh] {
			continue
		}
		signed[kh] = true
		kept = append(kept, w)
	}
	added := false
	if !signed[myKH] {
		w, err := apollo.NewVkeyWitnessFromSkey(bodyHash, []byte(payKey))
		if err != nil {
			return CosignResult{}, fmt.Errorf("sign with multisig key: %w", err)
		}
		signed[myKH] = true
		kept = append(kept, w)
		added = true
	}
	tx.WitnessSet.VkeyWitnesses = cbor.NewSetType(kept, true)

	// Clear the tx-level and witness-set caches so GetTxCbor re-serializes the
	// merged witness set; the BODY cache stays intact so every witness (ours
	// and any prior co-signer's) still matches the re-emitted body bytes
	// (mirrors Submit).
	tx.SetCbor(nil)
	tx.WitnessSet.SetCbor(nil)
	mergedBytes, err := a.GetTxCbor()
	if err != nil {
		return CosignResult{}, fmt.Errorf("encode merged tx: %w", err)
	}

	signedCount := 0
	for kh := range signed {
		if participants[kh] {
			signedCount++
		}
	}
	return CosignResult{
		TxCBOR:      hex.EncodeToString(mergedBytes),
		Added:       added,
		SignedCount: signedCount,
		Threshold:   info.Threshold,
	}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// vkeyWitnessValid reports whether w is a genuine Ed25519 signature by w.Vkey
// over msg (the tx body hash bytes). Cardano's BIP32-Ed25519 witnesses verify
// under standard Ed25519 against the 32-byte public key, so a pasted tx
// carrying a malformed or foreign witness — even one bearing a participant's
// key — is rejected here rather than counted toward the threshold on key-hash
// alone.
func vkeyWitnessValid(w lcommon.VkeyWitness, msg []byte) bool {
	if len(w.Vkey) != ed25519.PublicKeySize || len(w.Signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(w.Vkey), msg, w.Signature)
}

// decodeScript reconstructs a native script from its hex CBOR.
func decodeScript(scriptCBORHex string) (*bursa.NativeScript, error) {
	b, err := hex.DecodeString(scriptCBORHex)
	if err != nil {
		return nil, fmt.Errorf("%w: script hex: %w", ErrInvalidRequest, err)
	}
	var ns bursa.NativeScript
	if _, err := cbor.Decode(b, &ns); err != nil {
		return nil, fmt.Errorf("%w: decode script: %w", ErrInvalidRequest, err)
	}
	return &ns, nil
}

// mergeParticipantLabels copies each saved participant's Label onto the
// matching (case-insensitive key-hash) participant recovered from the
// script, leaving fromScript's ordering and threshold untouched. It is used
// so InspectTx can show friendly names for participants of a saved account
// even though the script itself only carries key-hashes.
func mergeParticipantLabels(fromScript, saved Policy) Policy {
	labels := make(map[string]string, len(saved.Participants))
	for _, sp := range saved.Participants {
		if sp.Label == "" {
			continue
		}
		labels[strings.ToLower(sp.KeyHashHex)] = sp.Label
	}
	out := fromScript
	out.Participants = make([]Participant, len(fromScript.Participants))
	for i, p := range fromScript.Participants {
		if label, ok := labels[strings.ToLower(p.KeyHashHex)]; ok {
			p.Label = label
		}
		out.Participants[i] = p
	}
	return out
}

// scriptKeyHashes returns the participant key-hashes (as raw 28-byte slices) of a
// policy, in policy order.
func scriptKeyHashes(p Policy) ([][]byte, error) {
	out := make([][]byte, 0, len(p.Participants))
	for _, part := range p.Participants {
		kh, err := hex.DecodeString(strings.TrimSpace(part.KeyHashHex))
		if err != nil {
			return nil, fmt.Errorf("%w: key hash %q: %w", ErrInvalidRequest, part.KeyHashHex, err)
		}
		out = append(out, kh)
	}
	return out, nil
}

// parseAmount parses a decimal uint64 lovelace string, rejecting values past the
// int64 range Apollo accepts.
func parseAmount(s string) (uint64, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
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
	default:
		return false
	}
}

func zero(k bip32.XPrv) {
	for i := range k {
		k[i] = 0
	}
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// randID generates a 16-byte random hex string for account ids.
func randID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
