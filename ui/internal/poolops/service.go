// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package poolops

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	apollo "github.com/blinklabs-io/apollo/v2"
	"github.com/blinklabs-io/apollo/v2/backend"
	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/bip32"
	"github.com/blinklabs-io/bursa/ui/internal/keystore"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// Keystore is the minimal interface satisfied by *keystore.Keystore; it is
// accepted as an interface so the service can run with a nil keystore (offline
// builders only) and be faked in tests.
type Keystore interface {
	Exists() bool
	Unlock(password string) (mnemonic []byte, err error)
}

type walletSeedStore interface {
	UnlockFor(walletID, password string) (mnemonic []byte, err error)
}

// GenesisQuerier provides the genesis parameters the KES-period math needs. The
// API layer adapts the loopback Blockfrost client's chain.Genesis to the local
// poolops.Genesis so this package does not import internal/chain.
type GenesisQuerier interface {
	Genesis(ctx context.Context) (genesis Genesis, err error)
}

// Tipper reports the node's current tip slot. TipSlot returns an error when
// the node has not yet caught up to the chain tip, because a stale slot would
// produce an incorrect KES period that is silently accepted but wrong.
type Tipper interface {
	TipSlot() (uint64, error)
}

// defaultColdIndex / defaultVRFIndex / defaultKESIndex are the conventional
// derivation indices for a single pool operated from one wallet.
const (
	defaultColdIndex = 0
	defaultVRFIndex  = 0
	defaultKESIndex  = 0

	retirementFeePaddingLovelace = 1000
)

type paymentKeyRole uint32

const (
	paymentKeyRoleReceive paymentKeyRole = 0
	paymentKeyRoleChange  paymentKeyRole = 1
)

type ownedPaymentAddress struct {
	address string
	role    paymentKeyRole
	index   uint32
}

// Service is the SPO toolkit bound to the active wallet. Credential derivation,
// opcert issuance/rotation, and certificate/tx construction all operate on the
// wallet recorded via SetAccount and unlock the keystore on demand.
type Service struct {
	chain   backend.ChainContext // build/sign/submit (nil for offline-only use)
	keys    Keystore             // nil for offline-only use
	genesis GenesisQuerier
	tipper  Tipper

	mu       sync.Mutex
	walletID string
	account  *wallet.Account
}

// NewService constructs a Service. cc/ks may be nil when only the offline
// builders (credentials require ks; cert/metadata builders do not) are needed.
func NewService(cc backend.ChainContext, ks Keystore, gq GenesisQuerier, tp Tipper) *Service {
	return &Service{chain: cc, keys: ks, genesis: gq, tipper: tp}
}

// SetAccount records the active wallet ID and account so pool operations always
// derive credentials from the wallet whose account data is current. Pass an
// empty id and nil acct to clear the binding (e.g. on vault lock).
func (s *Service) SetAccount(id string, acct *wallet.Account) {
	s.mu.Lock()
	s.walletID = id
	s.account = acct
	s.mu.Unlock()
}

func (s *Service) currentAccount() *wallet.Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.account
}

func (s *Service) currentBinding() (string, *wallet.Account) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.walletID, s.account
}

// unlockRoot decrypts the keystore with password and returns the wallet root
// key plus a zeroizer the caller must defer. Maps a decrypt failure to
// ErrWrongPassword.
func (s *Service) unlockRoot(walletID, password string) (bip32.XPrv, func(), error) {
	if s.keys == nil {
		return nil, func() {}, errors.New("no keystore configured")
	}
	var (
		mnemonic []byte
		err      error
	)
	if walletID != "" {
		ks, ok := s.keys.(walletSeedStore)
		if !ok {
			return nil, func() {}, fmt.Errorf("wallet-bound seed unlock requires UnlockFor support for wallet %q", walletID)
		}
		mnemonic, err = ks.UnlockFor(walletID, password)
	} else {
		mnemonic, err = s.keys.Unlock(password)
	}
	if err != nil {
		if errors.Is(err, keystore.ErrDecryptFailed) {
			return nil, func() {}, fmt.Errorf("%w: %w", ErrWrongPassword, err)
		}
		return nil, func() {}, fmt.Errorf("unlock keystore: %w", err)
	}
	root, err := wallet.RootKeyFromMnemonicBytes(mnemonic)
	if err != nil {
		keystore.Zero(mnemonic)
		return nil, func() {}, fmt.Errorf("root key: %w", err)
	}
	zero := func() {
		keystore.Zero(mnemonic)
		for i := range root {
			root[i] = 0
		}
	}
	return root, zero, nil
}

// ---------------------------------------------------------------------------
// 1. Generate pool credentials
// ---------------------------------------------------------------------------

// Credentials derives the active wallet's pool cold/VRF/KES credentials and
// reports their verification keys, hashes, and the pool ID. It requires the
// spending password to unlock the wallet seed; no node is needed.
func (s *Service) Credentials(password string) (Credentials, error) {
	walletID, acct := s.currentBinding()
	if acct == nil {
		return Credentials{}, ErrNoWallet
	}
	root, zero, err := s.unlockRoot(walletID, password)
	if err != nil {
		return Credentials{}, err
	}
	defer zero()
	return deriveCredentials(root, acct.Network, defaultColdIndex, defaultVRFIndex, defaultKESIndex)
}

// ---------------------------------------------------------------------------
// 2. Operational certificate (issue + KES rotation) + KES-period math
// ---------------------------------------------------------------------------

// OpCert is an operational certificate ready for the node's KES config. The
// fields mirror gouroboros' OpCert; KesVKeyHex/ColdSignatureHex are hex for the
// JSON surface, and KesPeriod/IssueNumber drive node forging.
type OpCert struct {
	KesVKeyHex       string `json:"kes_vkey_hex"`
	IssueNumber      uint64 `json:"issue_number"`
	KesPeriod        uint64 `json:"kes_period"`
	ColdSignatureHex string `json:"cold_signature_hex"`
	// KESIndex is the derivation index of the KES key used (rotation bumps it).
	KESIndex uint32 `json:"kes_index"`
}

// KESPeriod returns the current KES period derived from the node tip slot and
// genesis slots-per-KES-period, with the genesis inputs for display. No
// external call: tip comes from the supervisor and genesis from the node.
func (s *Service) KESPeriod(ctx context.Context) (KESPeriodInfo, error) {
	if s.genesis == nil || s.tipper == nil {
		return KESPeriodInfo{}, errors.New("node data source not configured")
	}
	g, err := s.genesis.Genesis(ctx)
	if err != nil {
		return KESPeriodInfo{}, fmt.Errorf("genesis: %w", err)
	}
	tip, err := s.tipper.TipSlot()
	if err != nil {
		return KESPeriodInfo{}, fmt.Errorf("tip slot: %w", err)
	}
	if g.SlotsPerKESPeriod < 0 {
		return KESPeriodInfo{}, fmt.Errorf("genesis slots_per_kes_period is negative: %d", g.SlotsPerKESPeriod)
	}
	if g.MaxKESEvolutions < 0 {
		return KESPeriodInfo{}, fmt.Errorf("genesis max_kes_evolutions is negative: %d", g.MaxKESEvolutions)
	}
	spkp := uint64(g.SlotsPerKESPeriod) //nolint:gosec // genesis value is non-negative
	period, err := kesPeriod(tip, spkp)
	if err != nil {
		return KESPeriodInfo{}, err
	}
	return KESPeriodInfo{
		CurrentPeriod:     period,
		TipSlot:           tip,
		SlotsPerKESPeriod: spkp,
		MaxKESEvolutions:  uint64(g.MaxKESEvolutions), //nolint:gosec // genesis value is non-negative
	}, nil
}

// IssueOpCert issues an operational certificate from the active wallet's
// seed-derived cold + KES keys. kesIndex selects the KES key (rotation passes a
// new index); issueNumber is the certificate counter (incremented on rotation);
// kesPeriod is the period at which the cert becomes valid (default: the current
// period). The cold key signs the (KES vkey, issue, period) tuple in-app.
func (s *Service) IssueOpCert(password string, kesIndex uint32, issueNumber, kesPeriod uint64) (OpCert, error) {
	walletID, acct := s.currentBinding()
	if acct == nil {
		return OpCert{}, ErrNoWallet
	}
	root, zero, err := s.unlockRoot(walletID, password)
	if err != nil {
		return OpCert{}, err
	}
	defer zero()

	cold, err := deriveCold(root, defaultColdIndex)
	if err != nil {
		return OpCert{}, err
	}
	defer cold.zero()

	kesSeed, err := bursa.GetKESSeed(root, kesIndex)
	if err != nil {
		return OpCert{}, fmt.Errorf("derive KES seed: %w", err)
	}
	defer zeroBytes(kesSeed)
	kesSKey, kesPub, err := bursa.GetKESKeyPair(kesSeed)
	zeroBytes(kesSeed)
	if kesSKey != nil {
		defer zeroBytes(kesSKey.Data)
	}
	if err != nil {
		return OpCert{}, fmt.Errorf("derive KES key pair: %w", err)
	}

	opcert, err := bursa.CreateOperationalCertificate(kesPub, issueNumber, kesPeriod, cold.seed)
	if err != nil {
		return OpCert{}, fmt.Errorf("create operational certificate: %w", err)
	}
	return OpCert{
		KesVKeyHex:       hex.EncodeToString(opcert.KesVkey),
		IssueNumber:      opcert.IssueNumber,
		KesPeriod:        opcert.KesPeriod,
		ColdSignatureHex: hex.EncodeToString(opcert.ColdSignature),
		KESIndex:         kesIndex,
	}, nil
}

// RotateKES performs a KES rotation: it derives the next KES key (kesIndex+1 by
// convention, supplied by the caller) and issues a fresh opcert with the issue
// counter incremented. The current issue number is supplied by the caller (read
// from the previous opcert / counter file); the new cert uses prevIssue+1.
func (s *Service) RotateKES(password string, newKESIndex uint32, prevIssueNumber, kesPeriod uint64) (OpCert, error) {
	return s.IssueOpCert(password, newKESIndex, prevIssueNumber+1, kesPeriod)
}

// ---------------------------------------------------------------------------
// Air-gap: operational certificate offline
// ---------------------------------------------------------------------------

// OpCertPayload is the to-be-signed payload for an air-gapped opcert: the cold
// key (held on an offline machine) signs PayloadHex with a standard Ed25519
// key, and the resulting signature is fed back to AssembleOpCert. PayloadHex is
// the OCertSignable representation (kes_vkey || issue_number || kes_period, the
// counters big-endian uint64) — exactly what gouroboros' CreateOpCert signs —
// so an external signer reproduces the same bytes.
type OpCertPayload struct {
	PayloadHex  string `json:"payload_hex"`
	KesVKeyHex  string `json:"kes_vkey_hex"`
	IssueNumber uint64 `json:"issue_number"`
	KesPeriod   uint64 `json:"kes_period"`
}

// OpCertPayloadForVKey builds the to-be-signed opcert payload for an externally
// supplied KES verification key. No wallet/keystore is needed — this is the
// air-gap path where the cold key never touches this machine.
func (s *Service) OpCertPayload(kesVKeyHex string, issueNumber, kesPeriod uint64) (OpCertPayload, error) {
	kesVkey, err := hex.DecodeString(strings.TrimSpace(kesVKeyHex))
	if err != nil {
		return OpCertPayload{}, fmt.Errorf("%w: KES vkey is not valid hex: %w", ErrInvalidRequest, err)
	}
	if len(kesVkey) != coldVKeyLen {
		return OpCertPayload{}, fmt.Errorf("%w: KES vkey must be %d bytes, got %d", ErrInvalidRequest, coldVKeyLen, len(kesVkey))
	}
	// The cold key signs the OCertSignable representation — the raw
	// concatenation kes_vkey || issue_number || kes_period (both counters
	// big-endian uint64), NOT a CBOR array. This mirrors ledger.CreateOpCert
	// (gouroboros >= v0.187) and cardano-node/cardano-ledger; signing any other
	// encoding yields a certificate that real blocks reject.
	payload := lcommon.OpCertSignableBytes(kesVkey, issueNumber, kesPeriod)
	return OpCertPayload{
		PayloadHex:  hex.EncodeToString(payload),
		KesVKeyHex:  hex.EncodeToString(kesVkey),
		IssueNumber: issueNumber,
		KesPeriod:   kesPeriod,
	}, nil
}

// AssembleOpCert assembles an operational certificate from an externally
// produced cold-key signature (the air-gap path). It validates that the
// signature verifies against the supplied cold verification key over the
// canonical opcert payload before returning — so a wrong key or corrupted
// signature is rejected rather than producing an invalid certificate.
func (s *Service) AssembleOpCert(coldVKeyHex, kesVKeyHex, signatureHex string, issueNumber, kesPeriod uint64) (OpCert, error) {
	coldVkey, err := decodeColdVKey(coldVKeyHex)
	if err != nil {
		return OpCert{}, err
	}
	payload, err := s.OpCertPayload(kesVKeyHex, issueNumber, kesPeriod)
	if err != nil {
		return OpCert{}, err
	}
	payloadBytes, err := hex.DecodeString(payload.PayloadHex)
	if err != nil {
		return OpCert{}, fmt.Errorf("decode payload: %w", err)
	}
	sig, err := hex.DecodeString(strings.TrimSpace(signatureHex))
	if err != nil {
		return OpCert{}, fmt.Errorf("%w: signature is not valid hex: %w", ErrInvalidRequest, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return OpCert{}, fmt.Errorf("%w: signature must be %d bytes, got %d", ErrInvalidRequest, ed25519.SignatureSize, len(sig))
	}
	if !ed25519.Verify(coldVkey, payloadBytes, sig) {
		return OpCert{}, fmt.Errorf("%w: signature does not verify against the supplied cold vkey", ErrInvalidRequest)
	}
	return OpCert{
		KesVKeyHex:       payload.KesVKeyHex,
		IssueNumber:      issueNumber,
		KesPeriod:        kesPeriod,
		ColdSignatureHex: hex.EncodeToString(sig),
	}, nil
}

// ---------------------------------------------------------------------------
// 6. Metadata builder
// ---------------------------------------------------------------------------

// BuildMetadata canonicalizes operator-supplied pool metadata to RFC 8785 JSON
// and returns it with its Blake2b-256 hash. The operator hosts the JSON and
// references the URL + hash in the registration certificate. No node needed.
func (s *Service) BuildMetadata(in MetadataInput) (MetadataResult, error) {
	return buildMetadata(in)
}

// ---------------------------------------------------------------------------
// PoolID (air-gap import of an external cold vkey)
// ---------------------------------------------------------------------------

// PoolIDFromColdVKey computes the pool ID from an externally-supplied cold
// verification key (raw 32-byte Ed25519, hex). Used by the air-gap flow where
// the wallet never holds the cold signing key.
func (s *Service) PoolIDFromColdVKey(coldVKeyHex string) (string, string, error) {
	id, err := poolIDFromColdVKeyHex(coldVKeyHex)
	if err != nil {
		return "", "", err
	}
	return id.Bech32("pool"), hex.EncodeToString(id.Bytes()), nil
}

// ---------------------------------------------------------------------------
// 3/4/5. Registration / update / retirement certificate + tx
// ---------------------------------------------------------------------------

// RegistrationParams is the operator-supplied input for a pool registration or
// update certificate. RewardAddress defaults to the active wallet's stake
// address when empty. ColdVKeyHex, when set, supplies an external cold vkey for
// the air-gap path (build the cert body without the signing key); when empty the
// cold vkey is derived from the active wallet seed (and SignAndSubmit may sign
// it in-app).
type RegistrationParams struct {
	Pledge        uint64   `json:"pledge"`
	Cost          uint64   `json:"cost"`
	MarginNum     int64    `json:"margin_num"`
	MarginDenom   int64    `json:"margin_denom"`
	RewardAddress string   `json:"reward_address,omitempty"`
	Owners        []string `json:"owners,omitempty"` // stake-key-hash hex or stake-address bech32
	Relays        []Relay  `json:"relays,omitempty"`
	MetadataURL   string   `json:"metadata_url,omitempty"`
	MetadataHash  string   `json:"metadata_hash,omitempty"` // blake2b-256 hex
	ColdVKeyHex   string   `json:"cold_vkey_hex,omitempty"` // air-gap: external cold vkey
}

// CertResult is a built certificate ready to display, host in an unsigned tx, or
// hand to an offline signer.
type CertResult struct {
	PoolID  string `json:"pool_id"`
	CBORHex string `json:"cbor_hex"`
}

// resolveRewardAccount returns the 29-byte reward-account bytes for the params,
// defaulting to the active wallet's stake address.
func (s *Service) resolveRewardAccount(p RegistrationParams, acct *wallet.Account) ([]byte, error) {
	addrStr := strings.TrimSpace(p.RewardAddress)
	if addrStr == "" {
		if acct == nil {
			return nil, fmt.Errorf("%w: no reward address and no active wallet", ErrInvalidRequest)
		}
		addrStr = acct.StakeAddress
	}
	addr, err := lcommon.NewAddress(addrStr)
	if err != nil {
		return nil, fmt.Errorf("%w: reward address %q: %w", ErrInvalidRequest, addrStr, err)
	}
	if addr.Type() != lcommon.AddressTypeNoneKey && addr.Type() != lcommon.AddressTypeNoneScript {
		return nil, fmt.Errorf("%w: reward address must be a stake/reward address", ErrInvalidRequest)
	}
	b, err := addr.Bytes()
	if err != nil {
		return nil, fmt.Errorf("%w: reward address bytes: %w", ErrInvalidRequest, err)
	}
	if len(b) != 1+lcommon.AddressHashSize {
		return nil, fmt.Errorf("%w: reward address must be %d bytes, got %d", ErrInvalidRequest, 1+lcommon.AddressHashSize, len(b))
	}
	return b, nil
}

// resolveOwners returns the pool-owner stake key hashes. Each owner may be a
// 28-byte stake key hash (hex) or a bech32 stake address. Defaults to the active
// wallet's own stake key hash when none are supplied.
func (s *Service) resolveOwners(owners []string, acct *wallet.Account) ([]lcommon.AddrKeyHash, error) {
	if len(owners) == 0 {
		if acct == nil {
			return nil, fmt.Errorf("%w: no owners and no active wallet", ErrInvalidRequest)
		}
		addr, err := lcommon.NewAddress(acct.StakeAddress)
		if err != nil {
			return nil, fmt.Errorf("wallet stake address: %w", err)
		}
		return []lcommon.AddrKeyHash{addr.StakeKeyHash()}, nil
	}
	out := make([]lcommon.AddrKeyHash, 0, len(owners))
	for _, o := range owners {
		o = strings.TrimSpace(o)
		if strings.HasPrefix(o, "stake") {
			addr, err := lcommon.NewAddress(o)
			if err != nil {
				return nil, fmt.Errorf("%w: owner address %q: %w", ErrInvalidRequest, o, err)
			}
			out = append(out, addr.StakeKeyHash())
			continue
		}
		hb, err := hex.DecodeString(o)
		if err != nil {
			return nil, fmt.Errorf("%w: owner %q is not a stake address or hex key hash: %w", ErrInvalidRequest, o, err)
		}
		if len(hb) != lcommon.Blake2b224Size {
			return nil, fmt.Errorf("%w: owner key hash %q must be %d bytes, got %d", ErrInvalidRequest, o, lcommon.Blake2b224Size, len(hb))
		}
		out = append(out, lcommon.NewBlake2b224(hb))
	}
	return out, nil
}

// buildRegistration assembles the registration certificate from cold vkey, VRF
// hash, reward account, owners, relays, and optional metadata, returning the
// CBOR and pool ID. It is shared by the seed and air-gap paths.
func (s *Service) buildRegistration(coldVKey, vrfHash []byte, p RegistrationParams, acct *wallet.Account) (CertResult, error) {
	if p.MarginDenom == 0 {
		return CertResult{}, fmt.Errorf("%w: margin denominator must not be zero", ErrInvalidRequest)
	}
	if p.MarginNum < 0 || p.MarginDenom < 0 || p.MarginNum > p.MarginDenom {
		return CertResult{}, fmt.Errorf("%w: margin must be between 0 and 1", ErrInvalidRequest)
	}
	reward, err := s.resolveRewardAccount(p, acct)
	if err != nil {
		return CertResult{}, err
	}
	owners, err := s.resolveOwners(p.Owners, acct)
	if err != nil {
		return CertResult{}, err
	}
	relays, err := relaysToPoolRelays(p.Relays)
	if err != nil {
		return CertResult{}, err
	}

	operator := poolIDFromVKey(coldVKey)
	cert := &bursa.PoolRegistrationCertificate{
		Operator:      operator,
		VrfKeyHash:    lcommon.NewBlake2b256(vrfHash),
		Pledge:        p.Pledge,
		Cost:          p.Cost,
		MarginNum:     p.MarginNum,
		MarginDenom:   p.MarginDenom,
		RewardAccount: reward,
		PoolOwners:    owners,
		Relays:        relays,
	}
	metadataURL := strings.TrimSpace(p.MetadataURL)
	metadataHash := strings.TrimSpace(p.MetadataHash)
	if metadataHash != "" && metadataURL == "" {
		return CertResult{}, fmt.Errorf("%w: metadata hash requires metadata URL", ErrInvalidRequest)
	}
	if metadataURL != "" {
		hb, err := hex.DecodeString(metadataHash)
		if err != nil {
			return CertResult{}, fmt.Errorf("%w: metadata hash is not valid hex: %w", ErrInvalidRequest, err)
		}
		if len(hb) != lcommon.Blake2b256Size {
			return CertResult{}, fmt.Errorf("%w: metadata hash must be %d bytes, got %d", ErrInvalidRequest, lcommon.Blake2b256Size, len(hb))
		}
		cert.MetadataURL = metadataURL
		cert.MetadataHash = lcommon.NewBlake2b256(hb)
	}

	cborBytes, err := bursa.CreatePoolRegistrationCertificate(cert)
	if err != nil {
		return CertResult{}, fmt.Errorf("create pool registration certificate: %w", err)
	}
	return CertResult{
		PoolID:  operator.Bech32("pool"),
		CBORHex: hex.EncodeToString(cborBytes),
	}, nil
}

// BuildRegistrationFromSeed builds the registration/update certificate using the
// active wallet's seed-derived cold + VRF keys. It requires the spending
// password. The returned cert is the canonical CBOR (correct 29-byte reward
// account) — submission is handled separately (see SubmitRetirement and the
// package-level TODO about registration tx submission).
func (s *Service) BuildRegistrationFromSeed(password string, p RegistrationParams) (CertResult, error) {
	walletID, acct := s.currentBinding()
	if acct == nil {
		return CertResult{}, ErrNoWallet
	}
	root, zero, err := s.unlockRoot(walletID, password)
	if err != nil {
		return CertResult{}, err
	}
	defer zero()
	cold, err := deriveCold(root, defaultColdIndex)
	if err != nil {
		return CertResult{}, err
	}
	defer cold.zero()
	cold.zero()
	vrfSeed, err := bursa.GetVRFSeed(root, defaultVRFIndex)
	if err != nil {
		return CertResult{}, fmt.Errorf("derive VRF seed: %w", err)
	}
	defer zeroBytes(vrfSeed)
	vrfPub, _, err := bursa.GetVRFKeyPair(vrfSeed)
	zeroBytes(vrfSeed)
	if err != nil {
		return CertResult{}, fmt.Errorf("derive VRF key pair: %w", err)
	}
	vrfHash := lcommon.Blake2b256Hash(vrfPub)
	return s.buildRegistration(cold.vkey, vrfHash.Bytes(), p, acct)
}

// AirGapRegistrationParams is the air-gap registration input: an external cold
// vkey and VRF key hash, with the standard registration params.
type AirGapRegistrationParams struct {
	RegistrationParams
	VRFKeyHashHex string `json:"vrf_key_hash_hex"`
}

// BuildRegistrationAirGap builds the registration/update certificate from an
// imported external cold vkey + VRF hash, without any signing key — the air-gap
// path. The resulting cert body is handed to an offline cold-key signer; the
// pool-registration tx is then assembled and submitted (see the offline tx-witness
// TODO). No keystore needed.
func (s *Service) BuildRegistrationAirGap(p AirGapRegistrationParams) (CertResult, error) {
	coldVkey, err := decodeColdVKey(p.ColdVKeyHex)
	if err != nil {
		return CertResult{}, err
	}
	vrfHash, err := hex.DecodeString(strings.TrimSpace(p.VRFKeyHashHex))
	if err != nil {
		return CertResult{}, fmt.Errorf("%w: VRF key hash is not valid hex: %w", ErrInvalidRequest, err)
	}
	if len(vrfHash) != lcommon.Blake2b256Size {
		return CertResult{}, fmt.Errorf("%w: VRF key hash must be %d bytes, got %d", ErrInvalidRequest, lcommon.Blake2b256Size, len(vrfHash))
	}
	return s.buildRegistration(coldVkey, vrfHash, p.RegistrationParams, s.currentAccount())
}

// BuildRetirementCert builds a pool retirement certificate for the given epoch.
// coldVKeyHex, when set, uses an external cold vkey (air-gap); otherwise the
// cold vkey is derived from the active wallet seed (requires the password).
func (s *Service) BuildRetirementCert(password, coldVKeyHex string, epoch uint64) (CertResult, error) {
	var coldVKey []byte
	if strings.TrimSpace(coldVKeyHex) != "" {
		b, err := decodeColdVKey(coldVKeyHex)
		if err != nil {
			return CertResult{}, err
		}
		coldVKey = b
	} else {
		walletID, acct := s.currentBinding()
		if acct == nil {
			return CertResult{}, ErrNoWallet
		}
		root, zero, err := s.unlockRoot(walletID, password)
		if err != nil {
			return CertResult{}, err
		}
		defer zero()
		cold, err := deriveCold(root, defaultColdIndex)
		if err != nil {
			return CertResult{}, err
		}
		defer cold.zero()
		coldVKey = append([]byte(nil), cold.vkey...)
	}
	operator := poolIDFromVKey(coldVKey)
	cborBytes, err := bursa.CreatePoolRetirementCertificate(&bursa.PoolRetirementCertificateParams{
		PoolKeyHash: operator,
		Epoch:       epoch,
	})
	if err != nil {
		return CertResult{}, fmt.Errorf("create pool retirement certificate: %w", err)
	}
	return CertResult{PoolID: operator.Bech32("pool"), CBORHex: hex.EncodeToString(cborBytes)}, nil
}

// TxResult is returned after a successful pool-operation submission.
type TxResult struct {
	TxHash string `json:"tx_hash"`
}

// SubmitRetirement builds, signs (with the wallet's first receive-address key
// for fees + the cold key as the pool witness), and submits a pool retirement
// transaction to the embedded node. It requires the spending password and a
// synced node. Retirement is the one pool operation whose certificate encodes
// identically through apollo's typed path (verified), so it is submitted in-app.
func (s *Service) SubmitRetirement(ctx context.Context, password string, epoch uint64) (TxResult, error) {
	walletID, acct := s.currentBinding()
	if acct == nil {
		return TxResult{}, ErrNoWallet
	}
	if s.chain == nil {
		return TxResult{}, errors.New("no chain context configured")
	}
	if len(acct.ReceiveAddresses) == 0 {
		return TxResult{}, errors.New("account has no receive addresses")
	}
	root, zero, err := s.unlockRoot(walletID, password)
	if err != nil {
		return TxResult{}, err
	}
	defer zero()
	cold, err := deriveCold(root, defaultColdIndex)
	if err != nil {
		return TxResult{}, err
	}
	defer cold.zero()
	operator := poolIDFromVKey(cold.vkey)

	acctKey, err := bursa.GetAccountKey(root, 0)
	if err != nil {
		return TxResult{}, fmt.Errorf("account key: %w", err)
	}
	defer zeroBytes(acctKey)

	changeAddr, err := lcommon.NewAddress(acct.ReceiveAddresses[0])
	if err != nil {
		return TxResult{}, fmt.Errorf("change address: %w", err)
	}
	a := apollo.New(s.chain).
		SetWallet(apollo.NewExternalWallet(changeAddr)).
		SetChangeAddress(changeAddr).
		SetFeePadding(retirementFeePaddingLovelace)

	fundingAddrs, err := retirementFundingAddresses(acct, acctKey)
	if err != nil {
		return TxResult{}, err
	}
	utxoAddr := make(map[string]ownedPaymentAddress)
	for _, owner := range fundingAddrs {
		addrStr := owner.address
		addr, err := lcommon.NewAddress(addrStr)
		if err != nil {
			return TxResult{}, fmt.Errorf("address %q: %w", addrStr, err)
		}
		utxos, err := s.chain.Utxos(ctx, addr)
		if err != nil {
			return TxResult{}, fmt.Errorf("utxos for %s: %w", addrStr, err)
		}
		if len(utxos) > 0 {
			a = a.AddLoadedUTxOs(utxos...)
			for _, u := range utxos {
				ref := hex.EncodeToString(u.Id.Id().Bytes()) + "#" + strconv.FormatUint(uint64(u.Id.Index()), 10)
				utxoAddr[ref] = owner
			}
		}
	}

	// Retirement certificate; the cold key must witness the tx.
	a = a.DeregisterPool(operator, epoch).
		AddRequiredSigner(operator)

	a, err = a.CompleteContext(ctx)
	if err != nil {
		return TxResult{}, fmt.Errorf("complete transaction: %w", err)
	}

	// Sign for fee inputs with the wallet payment keys, then add the cold-key
	// witness. Apollo's Sign() APPENDs a witness per SetWallet+Sign call.
	tx := a.GetTx()
	if tx == nil {
		return TxResult{}, errors.New("transaction not built")
	}
	seen := map[string]bool{}
	for _, inp := range tx.Body.TxInputs.Items() {
		ref := hex.EncodeToString(inp.TxId.Bytes()) + "#" + strconv.FormatUint(uint64(inp.OutputIndex), 10)
		owner, ok := utxoAddr[ref]
		if !ok || seen[owner.address] {
			continue
		}
		seen[owner.address] = true
		payKey, err := deriveOwnedPaymentKey(acctKey, owner)
		if err != nil {
			return TxResult{}, fmt.Errorf("%s payment key idx %d: %w", owner.role, owner.index, err)
		}
		if err := func() error {
			defer zeroBytes(payKey)
			addr, err := lcommon.NewAddress(owner.address)
			if err != nil {
				return fmt.Errorf("parse address %s: %w", owner.address, err)
			}
			kw, err := apollo.NewKeyPairWallet(addr, payKey)
			if err != nil {
				return fmt.Errorf("key pair wallet %s idx %d: %w", owner.role, owner.index, err)
			}
			a = a.SetWallet(kw)
			a, err = a.Sign()
			if err != nil {
				return fmt.Errorf("sign %s idx %d: %w", owner.role, owner.index, err)
			}
			return nil
		}(); err != nil {
			return TxResult{}, err
		}
	}
	// Cold-key witness: SignWithSkey accepts the 32-byte Ed25519 seed and adds a
	// vkey witness whose key is the standard Ed25519 cold vkey — matching the
	// operator hash in the retirement certificate.
	a, err = a.SignWithSkey(cold.seed)
	cold.zero()
	if err != nil {
		return TxResult{}, fmt.Errorf("cold-key witness: %w", err)
	}

	txHash, err := a.SubmitContext(context.WithoutCancel(ctx))
	if err != nil {
		return TxResult{}, fmt.Errorf("%w: %w", ErrSubmitRejected, err)
	}
	return TxResult{TxHash: hex.EncodeToString(txHash.Bytes())}, nil
}

func (r paymentKeyRole) String() string {
	switch r {
	case paymentKeyRoleReceive:
		return "receive"
	case paymentKeyRoleChange:
		return "change"
	default:
		return fmt.Sprintf("role-%d", r)
	}
}

func retirementFundingAddresses(acct *wallet.Account, acctKey bip32.XPrv) ([]ownedPaymentAddress, error) {
	seen := make(map[string]bool, len(acct.ReceiveAddresses)+len(acct.ChangeAddresses))
	out := make([]ownedPaymentAddress, 0, len(acct.ReceiveAddresses)+len(acct.ChangeAddresses))
	add := func(addr string, role paymentKeyRole, index uint32) {
		if addr == "" || seen[addr] {
			return
		}
		seen[addr] = true
		out = append(out, ownedPaymentAddress{address: addr, role: role, index: index})
	}

	for i, addr := range acct.ReceiveAddresses {
		add(addr, paymentKeyRoleReceive, uint32(i)) //nolint:gosec // bounded by the derived address window
	}

	changeAddresses := append([]string(nil), acct.ChangeAddresses...)
	if len(changeAddresses) < len(acct.ReceiveAddresses) {
		derived, err := deriveChangeAddresses(acct.ReceiveAddresses[0], acctKey, len(acct.ReceiveAddresses))
		if err != nil {
			return nil, err
		}
		changeAddresses = append(changeAddresses, derived[len(changeAddresses):]...)
	}
	for i, addr := range changeAddresses {
		add(addr, paymentKeyRoleChange, uint32(i)) //nolint:gosec // bounded by the derived address window
	}
	return out, nil
}

func deriveChangeAddresses(referenceAddr string, acctKey bip32.XPrv, count int) ([]string, error) {
	ref, err := lcommon.NewAddress(referenceAddr)
	if err != nil {
		return nil, fmt.Errorf("reference receive address: %w", err)
	}
	var networkID uint8
	switch ref.NetworkId() {
	case uint(lcommon.AddressNetworkTestnet):
		networkID = lcommon.AddressNetworkTestnet
	case uint(lcommon.AddressNetworkMainnet):
		networkID = lcommon.AddressNetworkMainnet
	default:
		return nil, fmt.Errorf("reference receive address network id %d is invalid", ref.NetworkId())
	}
	stakeHash := ref.StakeKeyHash()
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		idx := uint32(i) //nolint:gosec // bounded by the derived address window
		changeKey, err := deriveOwnedPaymentKey(acctKey, ownedPaymentAddress{
			role:  paymentKeyRoleChange,
			index: idx,
		})
		if err != nil {
			return nil, fmt.Errorf("change payment key idx %d: %w", idx, err)
		}
		payHash := changeKey.Public().PublicKey().Hash()
		zeroBytes(changeKey)
		addr, err := lcommon.NewAddressFromParts(
			lcommon.AddressTypeKeyKey,
			networkID,
			payHash,
			stakeHash.Bytes(),
		)
		if err != nil {
			return nil, fmt.Errorf("change address idx %d: %w", idx, err)
		}
		out = append(out, addr.String())
	}
	return out, nil
}

func deriveOwnedPaymentKey(acctKey bip32.XPrv, owner ownedPaymentAddress) (bip32.XPrv, error) {
	switch owner.role {
	case paymentKeyRoleReceive:
		return bursa.GetPaymentKey(acctKey, owner.index)
	case paymentKeyRoleChange:
		if owner.index >= 0x80000000 {
			return nil, bursa.ErrInvalidDerivationIndex
		}
		roleKey := acctKey.Derive(uint32(paymentKeyRoleChange))
		defer zeroBytes(roleKey)
		return roleKey.Derive(owner.index), nil
	default:
		return nil, fmt.Errorf("unknown payment key role %d", owner.role)
	}
}

// compile-time guard: *keystore.Keystore satisfies Keystore.
var _ Keystore = (*keystore.Keystore)(nil)
