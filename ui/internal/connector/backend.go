// Package connector implements the CIP-30 / CIP-95 wallet connector service.
// This file implements the Backend adapter (WalletBackend) over the existing
// wallet/chain services, encoding all wire values as CIP-30 expects
// (hex-encoded CBOR or raw address bytes).
package connector

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"sync"

	"github.com/blinklabs-io/bursa/ui/internal/chain"
	"github.com/blinklabs-io/bursa/ui/internal/spend"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
	gocbor "github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/ledger/babbage"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/conway"
	"github.com/blinklabs-io/gouroboros/ledger/mary"
	"github.com/blinklabs-io/gouroboros/ledger/shelley"
)

// defaultCollateralLovelace is the fallback collateral minimum (~5 ADA) when
// no amount is specified.
const defaultCollateralLovelace = 5_000_000

// chainFetcher is the minimal chain-client surface the WalletBackend needs.
// Satisfied by *chain.Client (and by test fakes).
type chainFetcher interface {
	AccountAddresses(ctx context.Context, stakeAddr string) ([]string, error)
	AddressUTxOs(ctx context.Context, addr string) ([]chain.UTxO, error)
}

// txUnspentOutput is a CBOR-serialisable representation of a CIP-30
// TransactionUnspentOutput: a 2-element array [TransactionInput, TransactionOutput].
// The cbor.StructAsArray tag causes cbor.Encode to emit this as a CBOR array.
type txUnspentOutput struct {
	gocbor.StructAsArray
	Input  shelley.ShelleyTransactionInput
	Output *babbage.BabbageTransactionOutput
}

// WalletBackend implements the connector.Backend interface over the wallet and
// chain services. It holds no private keys; signing methods are stubs.
type WalletBackend struct {
	wl      *wallet.Service
	sp      *spend.Service // reserved for Tasks 12-13
	chain   chainFetcher
	network string

	// mu guards walletID/acct, which are rebound whenever the active wallet
	// changes (unlock/activate/add). dApp request handlers read them
	// concurrently with the API server's lifecycle handlers, so all access goes
	// through account()/binding()/SetAccount.
	mu       sync.RWMutex
	walletID string
	acct     *wallet.Account
}

// NewWalletBackend constructs a WalletBackend.
// wl provides address views; sp is reserved for Tasks 12-13 (may be nil for read-only use).
// acct is the active derived account; network is "mainnet", "preview", or "preprod".
// cf is the chain querier (typically *chain.Client).
func NewWalletBackend(
	wl *wallet.Service,
	sp *spend.Service,
	acct *wallet.Account,
	network string,
	cf chainFetcher,
) *WalletBackend {
	return &WalletBackend{
		wl:      wl,
		sp:      sp,
		acct:    acct,
		chain:   cf,
		network: network,
	}
}

// SetAccount rebinds the backend to the active wallet's account. It is called
// whenever the active wallet changes (unlock/activate/add) so dApp calls always
// resolve against the current wallet, and never against a nil or stale account
// after a switch. A nil account clears the binding.
func (b *WalletBackend) SetAccount(walletID string, acct *wallet.Account) {
	b.mu.Lock()
	b.walletID = walletID
	b.acct = acct
	b.mu.Unlock()
}

// account returns the current active account under the read lock.
func (b *WalletBackend) account() *wallet.Account {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.acct
}

// binding returns a stable (walletID, account) snapshot under the read lock.
// SignTx uses this (rather than two separate account() reads) so the walletID
// it passes to spend.Service.WitnessTx always corresponds to the same account
// used to resolve input addresses and required signers.
func (b *WalletBackend) binding() (string, *wallet.Account) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.walletID, b.acct
}

// ---------------------------------------------------------------------------
// Backend interface — read methods
// ---------------------------------------------------------------------------

// NetworkID returns 1 for mainnet, 0 for all testnets (CIP-30 getNetworkId).
func (b *WalletBackend) NetworkID() int {
	if b.network == "mainnet" {
		return 1
	}
	return 0
}

// UsedAddresses returns hex-encoded raw address bytes for each chain-seen address.
func (b *WalletBackend) UsedAddresses(ctx context.Context, paginate *Paginate) ([]string, error) {
	av, err := b.wl.Addresses(ctx)
	if err != nil {
		return nil, err
	}
	return addrStringsToHex(paginateSlice(av.Used, paginate))
}

// UnusedAddresses returns hex-encoded raw bytes for derived addresses not yet on chain.
func (b *WalletBackend) UnusedAddresses(ctx context.Context) ([]string, error) {
	av, err := b.wl.Addresses(ctx)
	if err != nil {
		return nil, err
	}
	// An address is "unused" if it is in the derived receive window but not in the
	// chain-seen used set.
	usedSet := make(map[string]bool, len(av.Used))
	for _, a := range av.Used {
		usedSet[a] = true
	}
	var unused []string
	for _, a := range av.Receive {
		if !usedSet[a] {
			unused = append(unused, a)
		}
	}
	return addrStringsToHex(unused)
}

// ChangeAddress returns the hex-encoded raw bytes of the first unused receive
// address (or receive[0] when all are used).
func (b *WalletBackend) ChangeAddress(ctx context.Context) (string, error) {
	av, err := b.wl.Addresses(ctx)
	if err != nil {
		return "", err
	}
	change := av.NextUnused
	if change == "" && len(av.Receive) > 0 {
		change = av.Receive[0]
	}
	if change == "" {
		return "", errors.New("wallet has no receive addresses")
	}
	h, err := addrStringToHex(change)
	if err != nil {
		return "", err
	}
	return h, nil
}

// RewardAddresses returns the hex-encoded raw bytes of the wallet's stake/reward address.
func (b *WalletBackend) RewardAddresses(_ context.Context) ([]string, error) {
	acct := b.account()
	if acct == nil || acct.StakeAddress == "" {
		return nil, nil
	}
	h, err := addrStringToHex(acct.StakeAddress)
	if err != nil {
		return nil, err
	}
	return []string{h}, nil
}

// Balance returns the hex CBOR of a MaryTransactionOutputValue aggregated from
// all wallet UTxOs. Pure-ADA wallets encode as a bare CBOR integer; multi-asset
// wallets encode as a 2-element CBOR array [lovelace, multiasset_map].
func (b *WalletBackend) Balance(ctx context.Context) (string, error) {
	utxos, err := b.allUTxOs(ctx)
	if err != nil {
		return "", err
	}
	bal, err := wallet.AggregateBalance(utxos)
	if err != nil {
		return "", fmt.Errorf("aggregate balance: %w", err)
	}
	mv, err := balanceToMaryValue(bal)
	if err != nil {
		return "", err
	}
	cborBytes, err := gocbor.Encode(mv)
	if err != nil {
		return "", fmt.Errorf("encode balance CBOR: %w", err)
	}
	return hex.EncodeToString(cborBytes), nil
}

// Utxos returns hex CBOR of each TransactionUnspentOutput ([input, output]).
// When amount is non-empty it is a hex-CBOR CIP-30 Value; the returned UTxOs
// cover that requested value, or nil when the wallet cannot cover it. Pagination
// applies after amount selection.
func (b *WalletBackend) Utxos(ctx context.Context, amount string, paginate *Paginate) ([]string, error) {
	utxos, err := b.allUTxOs(ctx)
	if err != nil {
		return nil, err
	}

	if amount != "" {
		target, err := decodeRequestedValue(amount)
		if err != nil {
			return nil, err
		}
		selected, ok, err := selectUTxOsForValue(utxos, target)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, nil
		}
		utxos = selected
	}

	utxos = paginateSlice(utxos, paginate)
	if utxos == nil {
		return nil, nil
	}

	return encodeUTxOs(utxos)
}

// Collateral returns hex CBOR of pure-ADA UTxOs whose lovelace is at least the
// requested amount. The amount param is hex-CBOR of a Coin (uint) per CIP-30;
// defaults to 5 ADA when empty.
func (b *WalletBackend) Collateral(ctx context.Context, amount string) ([]string, error) {
	minLovelace := uint64(defaultCollateralLovelace)
	if amount != "" {
		amtBytes, err := hex.DecodeString(amount)
		if err != nil {
			return nil, fmt.Errorf("collateral amount %q is not valid hex: %w", amount, err)
		}
		var coin uint64
		if _, err := gocbor.Decode(amtBytes, &coin); err != nil {
			return nil, fmt.Errorf("collateral amount %q is not valid CBOR Coin: %w", amount, err)
		}
		minLovelace = coin
	}

	utxos, err := b.allUTxOs(ctx)
	if err != nil {
		return nil, err
	}

	// Gather all pure-ADA candidates (collateral may not carry native assets).
	var candidates []chain.UTxO
	for _, u := range utxos {
		if isPureADA(u) {
			candidates = append(candidates, u)
		}
	}
	// Largest-first so the requested amount is covered with the fewest inputs.
	sort.Slice(candidates, func(i, j int) bool {
		return utxoLovelace(candidates[i]) > utxoLovelace(candidates[j])
	})

	// Accumulate pure-ADA UTxOs until their combined lovelace covers the
	// requested amount. A single UTxO need not meet the full amount on its own —
	// CIP-30 collateral can be a set of several smaller UTxOs.
	var (
		collateral []chain.UTxO
		total      uint64
	)
	for _, u := range candidates {
		collateral = append(collateral, u)
		total += utxoLovelace(u)
		if total >= minLovelace {
			break
		}
	}
	// If the wallet's pure-ADA UTxOs cannot cover the requested amount, return
	// none (per CIP-30, an unsatisfiable collateral request yields null/empty).
	if total < minLovelace {
		return encodeUTxOs(nil)
	}
	return encodeUTxOs(collateral)
}

// ---------------------------------------------------------------------------
// Signing and submission methods — Task 12
// ---------------------------------------------------------------------------

// SignTx implements CIP-30 signTx. It decodes the externally-constructed tx CBOR,
// identifies which of the wallet's keys are needed (matching required-signers and
// input addresses owned by this wallet), produces vkey witnesses for those keys,
// and returns ONLY the witness set as hex CBOR — not the full transaction.
//
// If partialSign is false and the wallet owns no key required by the transaction,
// an error is returned.
func (b *WalletBackend) SignTx(ctx context.Context, txHex string, partialSign bool, password string) (string, error) {
	if b.sp == nil {
		return "", errors.New("signing service not configured")
	}
	// Capture a single (walletID, account) snapshot for this call. walletID is
	// threaded through to spend.Service.WitnessTx below so it can fail closed
	// (ErrWalletChanged) if the active wallet changes between now and when
	// WitnessTx actually derives keys, instead of silently deriving witnesses
	// from whatever wallet happens to be active at that later point.
	walletID, acct := b.binding()
	if acct == nil {
		return "", errors.New("no wallet account configured")
	}

	// Decode the full transaction CBOR.
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		return "", fmt.Errorf("decode tx hex: %w", err)
	}
	var tx conway.ConwayTransaction
	if _, err := gocbor.Decode(txBytes, &tx); err != nil {
		return "", fmt.Errorf("decode tx CBOR: %w", err)
	}

	// Extract the body CBOR by slicing the OUTER transaction CBOR array, taking
	// element [0] (the body) byte-for-byte. The transaction id (and therefore the
	// signing target) is blake2b-256 of these exact body bytes; re-encoding the
	// decoded struct can produce a different (canonicalised) byte sequence, which
	// would make every witness sign the wrong hash and the node reject the tx.
	bodyCbor, err := extractTxBodyCbor(txBytes)
	if err != nil {
		return "", err
	}

	// Collect required signers from the body.
	requiredSigners := tx.Body.RequiredSigners()

	// Resolve which of our derived addresses appear as input addresses.
	// Strategy: resolve our address UTxO sets and cross-reference with tx inputs.
	// Resolution failures are non-fatal — chain lookups are best-effort and we may
	// still be able to sign via required signers — so per-address errors are skipped.
	inputAddrs := b.resolveInputAddresses(ctx, tx.Body.TxInputs.Items())

	// Delegate to the spend service to derive keys and build the witness set.
	wsCbor, err := b.sp.WitnessTx(walletID, bodyCbor, requiredSigners, inputAddrs, password, partialSign)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(wsCbor), nil
}

// extractTxBodyCbor returns the raw CBOR bytes of the transaction body (element
// [0] of the outer transaction array), preserving them exactly as supplied so the
// signing hash (blake2b-256 of the body) matches what the node computes. It does
// NOT re-encode the decoded struct.
func extractTxBodyCbor(txBytes []byte) ([]byte, error) {
	var outer []gocbor.RawMessage
	if _, err := gocbor.Decode(txBytes, &outer); err != nil {
		return nil, fmt.Errorf("decode tx as CBOR array: %w", err)
	}
	if len(outer) < 1 {
		return nil, errors.New("transaction CBOR array is empty (no body element)")
	}
	body := []byte(outer[0])
	if len(body) == 0 {
		return nil, errors.New("transaction body element is empty")
	}
	return body, nil
}

// resolveInputAddresses looks up which of this wallet's derived receive addresses
// have UTxOs that match the transaction inputs. This is used by SignTx to
// identify which payment keys are needed for signing. Per-address chain lookup
// failures are best-effort and skipped, so this never returns an error.
func (b *WalletBackend) resolveInputAddresses(ctx context.Context, inputs []shelley.ShelleyTransactionInput) []string {
	acct := b.account()
	if acct == nil || len(inputs) == 0 {
		return nil
	}

	// Build a set of input references: "txhash#index".
	inputSet := make(map[string]bool, len(inputs))
	for _, inp := range inputs {
		ref := hex.EncodeToString(inp.TxId.Bytes()) + "#" + strconv.Itoa(int(inp.OutputIndex))
		inputSet[ref] = true
	}

	// Query UTxOs at each derived receive address; check if any UTxO is in inputSet.
	var owned []string
	for _, addrStr := range acct.ReceiveAddresses {
		utxos, err := b.chain.AddressUTxOs(ctx, addrStr)
		if err != nil || len(utxos) == 0 {
			continue
		}
		for _, u := range utxos {
			ref := u.TxHash + "#" + strconv.Itoa(u.OutputIndex)
			if inputSet[ref] {
				owned = append(owned, addrStr)
				break
			}
		}
	}
	return owned
}

// SignData implements CIP-30 signData. addrHex is the hex-encoded raw address
// bytes (as returned by CIP-30's getUsedAddresses / getChangeAddress); payloadHex
// is the hex-encoded message. Returns (signatureHex, keyHex) where both values
// are hex-encoded CBOR per the CIP-8 / CIP-30 signData spec.
func (b *WalletBackend) SignData(addrHex, payloadHex, password string) (sig, key string, err error) {
	if b.sp == nil {
		return "", "", errors.New("signing service not configured")
	}

	// Decode address hex → bech32 string (the form spend.SignData expects).
	addrBytes, err := hex.DecodeString(addrHex)
	if err != nil {
		return "", "", fmt.Errorf("decode address hex: %w", err)
	}
	addr, err := lcommon.NewAddressFromBytes(addrBytes)
	if err != nil {
		return "", "", fmt.Errorf("parse address bytes: %w", err)
	}
	addrStr := addr.String()

	// Decode payload hex.
	payload, err := hex.DecodeString(payloadHex)
	if err != nil {
		return "", "", fmt.Errorf("decode payload hex: %w", err)
	}

	return b.sp.SignData(addrStr, payload, password)
}

// SubmitTx submits a fully signed transaction to the chain and returns the
// transaction hash as a hex string.  txHex is the hex-encoded CBOR of the
// complete (body + witnesses) Conway transaction.
func (b *WalletBackend) SubmitTx(ctx context.Context, txHex string) (string, error) {
	if b.sp == nil {
		return "", errors.New("signing service not configured")
	}
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		return "", fmt.Errorf("decode tx hex: %w", err)
	}
	return b.sp.Submit(ctx, txBytes)
}

// PubDRepKey implements CIP-95 getPubDRepKey. It unlocks the keystore with the
// supplied password, derives the DRep key (CIP-0105, role 3: m/1852'/1815'/0'/3/0),
// and returns the raw 32-byte Ed25519 public key as a hex string.
func (b *WalletBackend) PubDRepKey(password string) (string, error) {
	if b.sp == nil {
		return "", errors.New("signing service not configured")
	}
	pub, err := b.sp.PubDRepKey(password)
	if err != nil {
		return "", fmt.Errorf("drep public key: %w", err)
	}
	return hex.EncodeToString(pub), nil
}

// RegisteredPubStakeKeys implements CIP-95 getRegisteredPubStakeKeys.
// It derives the account's stake public key (role 2) and returns its hex in
// this slice when the stake key is registered (active) on chain, or an empty
// slice when it is not. The unregistered bucket receives the complement.
func (b *WalletBackend) RegisteredPubStakeKeys(password string) ([]string, error) {
	registered, _, err := b.pubStakeKeyBuckets(password)
	return registered, err
}

// UnregisteredPubStakeKeys implements CIP-95 getUnregisteredPubStakeKeys.
// It derives the account's stake public key (role 2) and returns its hex in
// this slice when the stake key is NOT registered (active) on chain, or an
// empty slice when it is registered.
func (b *WalletBackend) UnregisteredPubStakeKeys(password string) ([]string, error) {
	_, unregistered, err := b.pubStakeKeyBuckets(password)
	return unregistered, err
}

// pubStakeKeyBuckets derives the stake public key hex and places it in the
// registered or unregistered bucket based on the on-chain delegation state.
// Registration is determined by wallet.Service.Delegation (info.Active); when
// the chain query fails (e.g. no node configured) the key is placed in the
// unregistered bucket and the error is silently suppressed.
func (b *WalletBackend) pubStakeKeyBuckets(password string) (registered, unregistered []string, err error) {
	if b.sp == nil {
		return nil, nil, errors.New("signing service not configured")
	}
	pub, err := b.sp.PubStakeKey(password)
	if err != nil {
		return nil, nil, fmt.Errorf("stake public key: %w", err)
	}
	stakeKeyHex := hex.EncodeToString(pub)

	// Determine on-chain registration. A stake key is "registered" when the
	// delegation state shows Active=true (staking certificate submitted and seen
	// by the node). On any error (node not reachable, wallet not set, etc.) we
	// default to unregistered so the caller still gets a usable key.
	active := false
	if b.wl != nil {
		if dv, dvErr := b.wl.Delegation(context.Background()); dvErr == nil {
			active = dv.Active
		}
	}

	if active {
		return []string{stakeKeyHex}, []string{}, nil
	}
	return []string{}, []string{stakeKeyHex}, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// allUTxOs gathers UTxOs from all scan addresses (chain-discovered union derived
// receive window), mirroring wallet.Service.Balance's address-scanning strategy.
func (b *WalletBackend) allUTxOs(ctx context.Context) ([]chain.UTxO, error) {
	acct := b.account()
	if acct == nil {
		return nil, errors.New("no wallet account configured")
	}
	// Discover chain-seen addresses via the account's stake credential.
	discovered, err := b.chain.AccountAddresses(ctx, acct.StakeAddress)
	if err != nil && !errors.Is(err, chain.ErrNotFound) {
		return nil, fmt.Errorf("account addresses: %w", err)
	}

	// Union chain-seen + derived receive addresses (dedup, preserve order).
	seen := make(map[string]bool, len(discovered)+len(acct.ReceiveAddresses))
	var addrs []string
	for _, a := range append(discovered, acct.ReceiveAddresses...) {
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		addrs = append(addrs, a)
	}

	var all []chain.UTxO
	for _, a := range addrs {
		us, err := b.chain.AddressUTxOs(ctx, a)
		if errors.Is(err, chain.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("utxos for %s: %w", a, err)
		}
		all = append(all, us...)
	}
	return all, nil
}

// encodeUTxOs encodes a slice of chain.UTxO to hex CBOR TransactionUnspentOutputs.
func encodeUTxOs(utxos []chain.UTxO) ([]string, error) {
	result := make([]string, 0, len(utxos))
	for _, u := range utxos {
		s, err := encodeUTxO(u)
		if err != nil {
			return nil, fmt.Errorf("encode utxo %s#%d: %w", u.TxHash, u.OutputIndex, err)
		}
		result = append(result, s)
	}
	return result, nil
}

// encodeUTxO encodes a single chain.UTxO as hex CBOR [TransactionInput, TransactionOutput].
// The address string from the UTxO is decoded to lcommon.Address for the output.
func encodeUTxO(u chain.UTxO) (string, error) {
	// Build the transaction input.
	input, err := buildInput(u)
	if err != nil {
		return "", err
	}

	// Build the transaction output.
	output, err := buildOutput(u)
	if err != nil {
		return "", err
	}

	// Encode as [input, output] CBOR array (CIP-30 TransactionUnspentOutput).
	tuo := txUnspentOutput{Input: input, Output: output}
	cborBytes, err := gocbor.Encode(tuo)
	if err != nil {
		return "", fmt.Errorf("cbor encode: %w", err)
	}
	return hex.EncodeToString(cborBytes), nil
}

// buildInput constructs a ShelleyTransactionInput from a chain.UTxO.
func buildInput(u chain.UTxO) (shelley.ShelleyTransactionInput, error) {
	hashBytes, err := hex.DecodeString(u.TxHash)
	if err != nil {
		return shelley.ShelleyTransactionInput{}, fmt.Errorf("decode tx hash %q: %w", u.TxHash, err)
	}
	if len(hashBytes) != lcommon.Blake2b256Size {
		return shelley.ShelleyTransactionInput{}, fmt.Errorf(
			"tx hash %q has wrong length: want %d bytes, got %d",
			u.TxHash, lcommon.Blake2b256Size, len(hashBytes),
		)
	}
	var txID lcommon.Blake2b256
	copy(txID[:], hashBytes)
	if u.OutputIndex < 0 {
		return shelley.ShelleyTransactionInput{}, fmt.Errorf("negative output index %d", u.OutputIndex)
	}
	return shelley.ShelleyTransactionInput{
		TxId:        txID,
		OutputIndex: uint32(u.OutputIndex), //nolint:gosec // validated non-negative above
	}, nil
}

// buildOutput constructs a BabbageTransactionOutput from a chain.UTxO.
func buildOutput(u chain.UTxO) (*babbage.BabbageTransactionOutput, error) {
	addr, err := lcommon.NewAddress(u.Address)
	if err != nil {
		return nil, fmt.Errorf("parse address %q: %w", u.Address, err)
	}

	// Parse amounts.
	var lovelace uint64
	assetData := make(map[lcommon.Blake2b224]map[gocbor.ByteString]*big.Int)
	for _, amt := range u.Amount {
		if amt.Unit == "lovelace" {
			v, ok := new(big.Int).SetString(amt.Quantity, 10)
			if !ok || v.Sign() < 0 {
				return nil, fmt.Errorf("invalid lovelace quantity %q", amt.Quantity)
			}
			lovelace = v.Uint64()
		} else if len(amt.Unit) >= 56 {
			qty, ok := new(big.Int).SetString(amt.Quantity, 10)
			if !ok || qty.Sign() < 0 {
				return nil, fmt.Errorf("invalid asset quantity %q for unit %s", amt.Quantity, amt.Unit)
			}
			policyHex := amt.Unit[:56]
			nameHex := amt.Unit[56:]
			policyBytes, err := hex.DecodeString(policyHex)
			if err != nil {
				return nil, fmt.Errorf("decode policy id %q: %w", policyHex, err)
			}
			nameBytes, err := hex.DecodeString(nameHex)
			if err != nil {
				return nil, fmt.Errorf("decode asset name %q: %w", nameHex, err)
			}
			var policyID lcommon.Blake2b224
			copy(policyID[:], policyBytes)
			if assetData[policyID] == nil {
				assetData[policyID] = make(map[gocbor.ByteString]*big.Int)
			}
			assetData[policyID][gocbor.NewByteString(nameBytes)] = qty
		}
	}

	var assets *lcommon.MultiAsset[lcommon.MultiAssetTypeOutput]
	if len(assetData) > 0 {
		ma := lcommon.NewMultiAsset[lcommon.MultiAssetTypeOutput](assetData)
		assets = &ma
	}

	return &babbage.BabbageTransactionOutput{
		OutputAddress: addr,
		OutputAmount: mary.MaryTransactionOutputValue{
			Amount: lovelace,
			Assets: assets,
		},
	}, nil
}

// balanceToMaryValue converts a wallet.Balance to a mary.MaryTransactionOutputValue
// for CBOR serialisation.
func balanceToMaryValue(bal wallet.Balance) (*mary.MaryTransactionOutputValue, error) {
	lovelace, ok := new(big.Int).SetString(bal.Lovelace, 10)
	if !ok {
		return nil, fmt.Errorf("invalid lovelace string %q", bal.Lovelace)
	}
	var assets *lcommon.MultiAsset[lcommon.MultiAssetTypeOutput]
	if len(bal.Assets) > 0 {
		assetData := make(map[lcommon.Blake2b224]map[gocbor.ByteString]*big.Int)
		for _, a := range bal.Assets {
			if len(a.Unit) < 56 {
				continue // skip malformed units (policy ID must be 28 bytes = 56 hex chars)
			}
			qty, ok := new(big.Int).SetString(a.Quantity, 10)
			if !ok {
				return nil, fmt.Errorf("invalid asset quantity %q for unit %s", a.Quantity, a.Unit)
			}
			policyHex := a.Unit[:56]
			nameHex := a.Unit[56:]
			policyBytes, err := hex.DecodeString(policyHex)
			if err != nil {
				return nil, fmt.Errorf("decode policy id: %w", err)
			}
			nameBytes, err := hex.DecodeString(nameHex)
			if err != nil {
				return nil, fmt.Errorf("decode asset name: %w", err)
			}
			var policyID lcommon.Blake2b224
			copy(policyID[:], policyBytes)
			if assetData[policyID] == nil {
				assetData[policyID] = make(map[gocbor.ByteString]*big.Int)
			}
			assetData[policyID][gocbor.NewByteString(nameBytes)] = qty
		}
		ma := lcommon.NewMultiAsset[lcommon.MultiAssetTypeOutput](assetData)
		assets = &ma
	}
	return &mary.MaryTransactionOutputValue{
		Amount: lovelace.Uint64(),
		Assets: assets,
	}, nil
}

// addrStringsToHex converts a slice of bech32 address strings to their hex raw bytes.
func addrStringsToHex(addrs []string) ([]string, error) {
	result := make([]string, 0, len(addrs))
	for _, a := range addrs {
		h, err := addrStringToHex(a)
		if err != nil {
			return nil, err
		}
		result = append(result, h)
	}
	return result, nil
}

// addrStringToHex converts a single bech32 address to its hex raw bytes.
func addrStringToHex(addrStr string) (string, error) {
	addr, err := lcommon.NewAddress(addrStr)
	if err != nil {
		return "", fmt.Errorf("parse address %q: %w", addrStr, err)
	}
	b, err := addr.Bytes()
	if err != nil {
		return "", fmt.Errorf("address bytes %q: %w", addrStr, err)
	}
	return hex.EncodeToString(b), nil
}

// isPureADA returns true if the UTxO has only lovelace (no native assets).
func isPureADA(u chain.UTxO) bool {
	for _, a := range u.Amount {
		if a.Unit != "lovelace" {
			return false
		}
	}
	return true
}

// utxoLovelace returns the lovelace amount from a chain.UTxO (0 on parse error).
func utxoLovelace(u chain.UTxO) uint64 {
	for _, a := range u.Amount {
		if a.Unit == "lovelace" {
			v, ok := new(big.Int).SetString(a.Quantity, 10)
			if !ok || v.Sign() < 0 {
				return 0
			}
			return v.Uint64()
		}
	}
	return 0
}

func paginateSlice[T any](items []T, paginate *Paginate) []T {
	if paginate == nil || paginate.Limit <= 0 {
		return items
	}
	if len(items) == 0 {
		return nil
	}
	page := paginate.Page
	if page < 0 {
		page = 0
	}
	limit := paginate.Limit
	// CIP-30 pages are 0-indexed. Check the page against len/limit before
	// multiplying so oversized connector inputs cannot overflow into slice
	// bounds.
	if page > (len(items)-1)/limit {
		return nil
	}
	start := page * limit
	end := len(items)
	if limit < len(items)-start {
		end = start + limit
	}
	return items[start:end]
}

type cip30Value struct {
	lovelace *big.Int
	assets   map[string]*big.Int
}

func newCIP30Value() cip30Value {
	return cip30Value{lovelace: new(big.Int), assets: map[string]*big.Int{}}
}

func decodeRequestedValue(amount string) (cip30Value, error) {
	raw, err := hex.DecodeString(amount)
	if err != nil {
		return cip30Value{}, fmt.Errorf("utxo amount %q is not valid hex: %w", amount, err)
	}
	var mv mary.MaryTransactionOutputValue
	if _, err := gocbor.Decode(raw, &mv); err != nil {
		return cip30Value{}, fmt.Errorf("utxo amount %q is not valid CBOR Value: %w", amount, err)
	}
	v := newCIP30Value()
	v.lovelace.SetUint64(mv.Amount)
	if mv.Assets != nil {
		for _, policy := range mv.Assets.Policies() {
			for _, name := range mv.Assets.Assets(policy) {
				qty := mv.Assets.Asset(policy, name)
				if qty == nil {
					continue
				}
				if qty.Sign() < 0 {
					return cip30Value{}, fmt.Errorf("utxo amount has negative asset quantity for %s", assetUnit(policy, name))
				}
				if qty.Sign() == 0 {
					continue
				}
				v.assets[assetUnit(policy, name)] = new(big.Int).Set(qty)
			}
		}
	}
	return v, nil
}

func utxoToValue(u chain.UTxO) (cip30Value, error) {
	v := newCIP30Value()
	for _, amt := range u.Amount {
		qty, ok := new(big.Int).SetString(amt.Quantity, 10)
		if !ok || qty.Sign() < 0 {
			return cip30Value{}, fmt.Errorf("invalid quantity %q for unit %s", amt.Quantity, amt.Unit)
		}
		if amt.Unit == "lovelace" {
			v.lovelace.Add(v.lovelace, qty)
			continue
		}
		if v.assets[amt.Unit] == nil {
			v.assets[amt.Unit] = new(big.Int)
		}
		v.assets[amt.Unit].Add(v.assets[amt.Unit], qty)
	}
	return v, nil
}

func assetUnit(policy lcommon.Blake2b224, name []byte) string {
	return hex.EncodeToString(policy.Bytes()) + hex.EncodeToString(name)
}

func (v cip30Value) add(other cip30Value) {
	v.lovelace.Add(v.lovelace, other.lovelace)
	for unit, qty := range other.assets {
		if v.assets[unit] == nil {
			v.assets[unit] = new(big.Int)
		}
		v.assets[unit].Add(v.assets[unit], qty)
	}
}

func (v cip30Value) covers(target cip30Value) bool {
	if v.lovelace.Cmp(target.lovelace) < 0 {
		return false
	}
	for unit, want := range target.assets {
		got := v.assets[unit]
		if got == nil || got.Cmp(want) < 0 {
			return false
		}
	}
	return true
}

func (v cip30Value) isZero() bool {
	if v.lovelace.Sign() != 0 {
		return false
	}
	for _, qty := range v.assets {
		if qty.Sign() != 0 {
			return false
		}
	}
	return true
}

func contributionScore(v, target cip30Value) *big.Int {
	score := new(big.Int)
	if target.lovelace.Sign() > 0 {
		addMin(score, v.lovelace, target.lovelace)
	}
	for unit, want := range target.assets {
		if got := v.assets[unit]; got != nil {
			addMin(score, got, want)
		}
	}
	return score
}

func excessScore(v, target cip30Value) *big.Int {
	score := new(big.Int)
	if diff := new(big.Int).Sub(v.lovelace, target.lovelace); diff.Sign() > 0 {
		score.Add(score, diff)
	}
	for unit, want := range target.assets {
		got := v.assets[unit]
		if got == nil {
			continue
		}
		if diff := new(big.Int).Sub(got, want); diff.Sign() > 0 {
			score.Add(score, diff)
		}
	}
	return score
}

func addMin(dst, a, b *big.Int) {
	if a.Cmp(b) < 0 {
		dst.Add(dst, a)
		return
	}
	dst.Add(dst, b)
}

func selectUTxOsForValue(utxos []chain.UTxO, target cip30Value) ([]chain.UTxO, bool, error) {
	if target.isZero() {
		return []chain.UTxO{}, true, nil
	}
	type candidate struct {
		utxo   chain.UTxO
		value  cip30Value
		score  *big.Int
		excess *big.Int
	}
	candidates := make([]candidate, 0, len(utxos))
	total := newCIP30Value()
	var bestSingle *candidate
	for _, u := range utxos {
		v, err := utxoToValue(u)
		if err != nil {
			return nil, false, err
		}
		total.add(v)
		score := contributionScore(v, target)
		if score.Sign() == 0 {
			continue
		}
		c := candidate{
			utxo:   u,
			value:  v,
			score:  score,
			excess: excessScore(v, target),
		}
		if v.covers(target) && (bestSingle == nil || c.excess.Cmp(bestSingle.excess) < 0) {
			tmp := c
			bestSingle = &tmp
		}
		candidates = append(candidates, c)
	}
	if !total.covers(target) {
		return nil, false, nil
	}
	if bestSingle != nil {
		return []chain.UTxO{bestSingle.utxo}, true, nil
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if cmp := candidates[i].score.Cmp(candidates[j].score); cmp != 0 {
			return cmp > 0
		}
		return utxoLovelace(candidates[i].utxo) > utxoLovelace(candidates[j].utxo)
	})
	selected := make([]chain.UTxO, 0, len(candidates))
	sum := newCIP30Value()
	for _, c := range candidates {
		selected = append(selected, c.utxo)
		sum.add(c.value)
		if sum.covers(target) {
			return selected, true, nil
		}
	}
	return nil, false, nil
}
