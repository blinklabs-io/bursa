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

// Package poolops is the Stake Pool Operations (SPO) toolkit for the Bursa
// full-node wallet. It wraps bursa's existing key-derivation and certificate
// primitives to:
//
//   - derive a pool's cold / VRF / KES credentials from the active wallet seed
//     (CIP-1853) and report the verification keys, key hashes, and pool ID;
//   - issue and rotate operational certificates;
//   - build pool registration / update / retirement certificates and submit
//     them as transactions witnessed by the cold key (reusing the spend
//     build/sign/submit path);
//   - build canonical (RFC 8785 / JCS) pool metadata JSON and its Blake2b-256
//     hash for the operator to host; and
//   - support an air-gapped cold key: import an external cold verification key
//     to compute the pool ID and build the registration cert body without the
//     signing key, and assemble an operational certificate from an externally
//     produced cold-key signature.
//
// All chain data (node tip, genesis parameters, current epoch) comes from the
// embedded node's loopback Blockfrost endpoint; this package never contacts an
// external service and never fetches metadata.
package poolops

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/bip32"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/gowebpki/jcs"
	"golang.org/x/crypto/blake2b"
)

// Sentinel errors. The API layer maps these to HTTP status codes; callers match
// them with errors.Is. Service methods wrap them with context.
var (
	// ErrNoWallet: no active wallet/keystore configured (→ 409).
	ErrNoWallet = errors.New("no wallet set")
	// ErrInvalidRequest: a malformed parameter (→ 400).
	ErrInvalidRequest = errors.New("invalid pool operation request")
	// ErrWrongPassword: keystore authentication failed (→ 401).
	ErrWrongPassword = errors.New("incorrect spending password")
	// ErrSubmitRejected: the node rejected the signed transaction (→ 422).
	ErrSubmitRejected = errors.New("transaction rejected by node")
)

// coldVKeyLen is the length of a raw Ed25519 verification key (cold/VRF/KES are
// all 32-byte keys at the verification level).
const coldVKeyLen = 32

// poolColdUseCase is the CIP-1853 usecase index (currently fixed to 0).
const poolColdUseCase = 0

// KeyInfo is a verification key plus its derived hashes, ready for display.
type KeyInfo struct {
	// VKeyHex is the raw 32-byte verification key, hex-encoded.
	VKeyHex string `json:"vkey_hex"`
	// VKeyBech32 is the cardano-cli-compatible bech32 of the vkey, when one
	// applies (cold keys → addr_vk; VRF/KES have no standard bech32 vkey form
	// here, so this is left empty for them).
	VKeyBech32 string `json:"vkey_bech32,omitempty"`
	// HashHex is the key's blake2b hash, hex-encoded (224-bit for the cold key,
	// 256-bit for VRF/KES).
	HashHex string `json:"hash_hex"`
}

// Credentials is the full set of derived pool credentials plus the pool ID.
type Credentials struct {
	// Network the credentials were derived for (matches the active wallet).
	Network string `json:"network"`
	// PoolID is the bech32 (pool1…) stake-pool identifier: blake2b-224 of the
	// cold verification key.
	PoolID string `json:"pool_id"`
	// PoolIDHex is the same identifier, hex-encoded (the 28-byte operator hash).
	PoolIDHex string `json:"pool_id_hex"`

	Cold KeyInfo `json:"cold"`
	VRF  KeyInfo `json:"vrf"`
	KES  KeyInfo `json:"kes"`

	// ColdIndex / VRFIndex / KESIndex are the derivation indices used.
	ColdIndex uint32 `json:"cold_index"`
	VRFIndex  uint32 `json:"vrf_index"`
	KESIndex  uint32 `json:"kes_index"`
}

// coldKeyMaterial is the internally-consistent cold-key representation the
// wallet uses for the pool ID, operator hash, operational-certificate signing,
// and the transaction cold-key witness.
//
// The pool cold key is a CIP-1853 BIP32-Ed25519 extended key, but gouroboros'
// CreateOpCert signs the operational certificate with a *standard* Ed25519 key
// seeded from the extended key's first 32 bytes (k_L). For the opcert signature
// to verify against the cold verification key — and for the registration cert's
// operator hash and the tx vkey witness to all agree with it — the cold vkey
// MUST be that same standard-Ed25519 public key (NOT the extended/bip32 public
// key). seed/vkey here are derived accordingly; the rest of the package uses
// only this representation so every artifact references one consistent cold key.
type coldKeyMaterial struct {
	seed []byte // 32-byte Ed25519 seed (k_L); secret — zero after use
	vkey []byte // 32-byte standard Ed25519 public key
}

// deriveCold returns the consistent cold-key material for the active wallet's
// root key at the given index.
func deriveCold(root bip32.XPrv, index uint32) (coldKeyMaterial, error) {
	cold, err := bursa.GetPoolColdKey(root, poolColdUseCase, index)
	if err != nil {
		return coldKeyMaterial{}, fmt.Errorf("derive pool cold key: %w", err)
	}
	seed := append([]byte(nil), cold.PrivateKey()[:32]...)
	vkey := append([]byte(nil), ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)...)
	return coldKeyMaterial{seed: seed, vkey: vkey}, nil
}

// zero overwrites the secret seed.
func (c *coldKeyMaterial) zero() {
	for i := range c.seed {
		c.seed[i] = 0
	}
}

// poolID returns the operator key hash (blake2b-224 of the cold vkey).
func poolIDFromVKey(coldVKey []byte) lcommon.PoolKeyHash {
	return lcommon.Blake2b224Hash(coldVKey)
}

// deriveCredentials derives the full credential set from a root key.
func deriveCredentials(root bip32.XPrv, network string, coldIdx, vrfIdx, kesIdx uint32) (Credentials, error) {
	cold, err := deriveCold(root, coldIdx)
	if err != nil {
		return Credentials{}, err
	}
	defer cold.zero()

	vrfSeed, err := bursa.GetVRFSeed(root, vrfIdx)
	if err != nil {
		return Credentials{}, fmt.Errorf("derive VRF seed: %w", err)
	}
	vrfPub, _, err := bursa.GetVRFKeyPair(vrfSeed)
	if err != nil {
		return Credentials{}, fmt.Errorf("derive VRF key pair: %w", err)
	}

	kesSeed, err := bursa.GetKESSeed(root, kesIdx)
	if err != nil {
		return Credentials{}, fmt.Errorf("derive KES seed: %w", err)
	}
	_, kesPub, err := bursa.GetKESKeyPair(kesSeed)
	if err != nil {
		return Credentials{}, fmt.Errorf("derive KES key pair: %w", err)
	}

	operator := poolIDFromVKey(cold.vkey)
	vrfHash := lcommon.Blake2b256Hash(vrfPub)
	kesHash := lcommon.Blake2b256Hash(kesPub)

	return Credentials{
		Network:   network,
		PoolID:    operator.Bech32("pool"),
		PoolIDHex: hex.EncodeToString(operator.Bytes()),
		Cold: KeyInfo{
			VKeyHex:    hex.EncodeToString(cold.vkey),
			VKeyBech32: bip32.PublicKey(cold.vkey).String(),
			HashHex:    hex.EncodeToString(operator.Bytes()),
		},
		VRF: KeyInfo{
			VKeyHex: hex.EncodeToString(vrfPub),
			HashHex: hex.EncodeToString(vrfHash.Bytes()),
		},
		KES: KeyInfo{
			VKeyHex: hex.EncodeToString(kesPub),
			HashHex: hex.EncodeToString(kesHash.Bytes()),
		},
		ColdIndex: coldIdx,
		VRFIndex:  vrfIdx,
		KESIndex:  kesIdx,
	}, nil
}

// poolIDFromColdVKeyHex computes the pool ID from an externally-supplied cold
// verification key (hex-encoded raw 32-byte Ed25519 key). Used by the air-gap
// import flow where the wallet never holds the cold signing key.
func poolIDFromColdVKeyHex(coldVKeyHex string) (lcommon.PoolKeyHash, error) {
	vkey, err := decodeColdVKey(coldVKeyHex)
	if err != nil {
		return lcommon.PoolKeyHash{}, err
	}
	return poolIDFromVKey(vkey), nil
}

// decodeColdVKey decodes and validates a hex-encoded raw 32-byte cold vkey.
func decodeColdVKey(coldVKeyHex string) ([]byte, error) {
	vkey, err := hex.DecodeString(strings.TrimSpace(coldVKeyHex))
	if err != nil {
		return nil, fmt.Errorf("%w: cold vkey is not valid hex: %w", ErrInvalidRequest, err)
	}
	if len(vkey) != coldVKeyLen {
		return nil, fmt.Errorf("%w: cold vkey must be %d bytes, got %d", ErrInvalidRequest, coldVKeyLen, len(vkey))
	}
	return vkey, nil
}

// ---------------------------------------------------------------------------
// KES-period math
// ---------------------------------------------------------------------------

// Genesis is the subset of network genesis parameters the SPO toolkit needs for
// KES-period math. It is supplied by a GenesisQuerier (the loopback Blockfrost
// client, adapted by the API layer) so this package does not import
// internal/chain.
type Genesis struct {
	SlotsPerKESPeriod int
	MaxKESEvolutions  int
	EpochLength       int
}

// KESPeriodInfo reports the current KES period and the genesis parameters it is
// derived from. CurrentPeriod = tipSlot / slotsPerKESPeriod.
type KESPeriodInfo struct {
	CurrentPeriod     uint64 `json:"current_period"`
	TipSlot           uint64 `json:"tip_slot"`
	SlotsPerKESPeriod uint64 `json:"slots_per_kes_period"`
	MaxKESEvolutions  uint64 `json:"max_kes_evolutions"`
}

// kesPeriod computes the current KES period from the node tip slot and the
// genesis slots-per-KES-period. It is the integer division tipSlot ÷ spkp.
func kesPeriod(tipSlot, slotsPerKESPeriod uint64) (uint64, error) {
	if slotsPerKESPeriod == 0 {
		return 0, errors.New("slots_per_kes_period is zero (genesis not available)")
	}
	return tipSlot / slotsPerKESPeriod, nil
}

// ---------------------------------------------------------------------------
// Pool metadata builder
// ---------------------------------------------------------------------------

// MetadataInput is the operator-supplied pool metadata. The fields mirror the
// CIP-6 / SMASH pool-metadata schema the registration certificate references.
type MetadataInput struct {
	Name        string `json:"name"`
	Ticker      string `json:"ticker"`
	Homepage    string `json:"homepage"`
	Description string `json:"description"`
}

// MetadataResult is the canonical JSON the operator hosts plus its hash. The
// registration certificate references the URL where this JSON is served and the
// hash so that downstream consumers can verify the hosted content is unchanged.
type MetadataResult struct {
	// JSON is the RFC 8785 (JCS) canonicalized metadata document.
	JSON string `json:"json"`
	// HashHex is the Blake2b-256 hash of the canonical JSON, hex-encoded — the
	// value that goes in the registration cert's metadata field.
	HashHex string `json:"hash_hex"`
}

// buildMetadata canonicalizes the metadata to RFC 8785 (JCS) JSON and hashes it
// with Blake2b-256, mirroring the parent bursa CLI's RunHashMetadata. Marshaling
// the struct directly keeps the field set well-formed; JCS then fixes ordering
// and formatting so the hash is reproducible.
func buildMetadata(in MetadataInput) (MetadataResult, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Ticker = strings.TrimSpace(in.Ticker)
	in.Homepage = strings.TrimSpace(in.Homepage)
	in.Description = strings.TrimSpace(in.Description)
	if in.Name == "" || in.Ticker == "" {
		return MetadataResult{}, fmt.Errorf("%w: metadata name and ticker are required", ErrInvalidRequest)
	}

	raw, err := json.Marshal(in)
	if err != nil {
		return MetadataResult{}, fmt.Errorf("marshal metadata: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return MetadataResult{}, fmt.Errorf("canonicalize metadata (RFC 8785): %w", err)
	}
	sum := blake2b.Sum256(canonical)
	return MetadataResult{
		JSON:    string(canonical),
		HashHex: hex.EncodeToString(sum[:]),
	}, nil
}

// ---------------------------------------------------------------------------
// Relays
// ---------------------------------------------------------------------------

// Relay is the wallet's relay input. Type selects the encoding:
//
//	"single_host_address" → ipv4/ipv6 + optional port
//	"single_host_name"    → hostname (DNS A/AAAA) + optional port
//	"multi_host_name"     → hostname (DNS SRV), no port
type Relay struct {
	Type     string  `json:"type"`
	IPv4     string  `json:"ipv4,omitempty"`
	IPv6     string  `json:"ipv6,omitempty"`
	Hostname string  `json:"hostname,omitempty"`
	Port     *uint32 `json:"port,omitempty"`
}

// toPoolRelay converts a wallet Relay into a gouroboros PoolRelay.
func (r Relay) toPoolRelay() (lcommon.PoolRelay, error) {
	switch r.Type {
	case "single_host_address":
		pr := lcommon.PoolRelay{Type: lcommon.PoolRelayTypeSingleHostAddress, Port: r.Port}
		if r.IPv4 == "" && r.IPv6 == "" {
			return lcommon.PoolRelay{}, fmt.Errorf("%w: single_host_address relay needs ipv4 or ipv6", ErrInvalidRequest)
		}
		if r.IPv4 != "" {
			ip := net.ParseIP(strings.TrimSpace(r.IPv4))
			if ip == nil || ip.To4() == nil {
				return lcommon.PoolRelay{}, fmt.Errorf("%w: invalid ipv4 %q", ErrInvalidRequest, r.IPv4)
			}
			v4 := ip.To4()
			pr.Ipv4 = &v4
		}
		if r.IPv6 != "" {
			ip := net.ParseIP(strings.TrimSpace(r.IPv6))
			if ip == nil || ip.To16() == nil {
				return lcommon.PoolRelay{}, fmt.Errorf("%w: invalid ipv6 %q", ErrInvalidRequest, r.IPv6)
			}
			v6 := ip.To16()
			pr.Ipv6 = &v6
		}
		return pr, nil
	case "single_host_name":
		host := strings.TrimSpace(r.Hostname)
		if host == "" {
			return lcommon.PoolRelay{}, fmt.Errorf("%w: single_host_name relay needs a hostname", ErrInvalidRequest)
		}
		return lcommon.PoolRelay{Type: lcommon.PoolRelayTypeSingleHostName, Hostname: &host, Port: r.Port}, nil
	case "multi_host_name":
		host := strings.TrimSpace(r.Hostname)
		if host == "" {
			return lcommon.PoolRelay{}, fmt.Errorf("%w: multi_host_name relay needs a hostname", ErrInvalidRequest)
		}
		return lcommon.PoolRelay{Type: lcommon.PoolRelayTypeMultiHostName, Hostname: &host}, nil
	default:
		return lcommon.PoolRelay{}, fmt.Errorf("%w: unknown relay type %q", ErrInvalidRequest, r.Type)
	}
}

func relaysToPoolRelays(relays []Relay) ([]lcommon.PoolRelay, error) {
	out := make([]lcommon.PoolRelay, 0, len(relays))
	for i, r := range relays {
		pr, err := r.toPoolRelay()
		if err != nil {
			return nil, fmt.Errorf("relay %d: %w", i, err)
		}
		out = append(out, pr)
	}
	return out, nil
}
