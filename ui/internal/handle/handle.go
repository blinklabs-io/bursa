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

// Package handle resolves an ADA Handle ($name) — an on-chain NFT — to the
// address currently holding it. Resolve always uses the embedded node; the
// separate APIResolver is invoked only by an explicitly consented fallback.
package handle

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/blinklabs-io/bursa/ui/internal/cardanonet"
	"github.com/blinklabs-io/bursa/ui/internal/chain"
)

// PolicyID is the ADA Handle root policy used on mainnet and supported testnets.
const PolicyID = "f0ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9a"

// MainnetPolicyID is kept as a compatibility alias for PolicyID.
const MainnetPolicyID = PolicyID

// ErrInvalidName is returned when a handle input has no name left after
// stripping its optional leading '$' and surrounding whitespace.
var ErrInvalidName = errors.New("handle: empty name")

// ErrAmbiguousHolder is returned when a resolver cannot prove one current
// recipient. Callers must never select an address from an ambiguous result.
var ErrAmbiguousHolder = errors.New("handle: holder is ambiguous")

// Normalize strips an optional leading '$' (and surrounding whitespace) from
// a handle input and case-folds it to lowercase — "$Chris", "CHRIS", and
// "chris" all normalize to "chris" — and rejects an empty result. Case
// folding matters because the Handle minting policy restricts base-handle
// names to lowercase a-z, digits, and "._-", so resolution must be
// case-insensitive to match how every mainstream wallet treats handle input.
func Normalize(input string) (string, error) {
	name := strings.TrimPrefix(strings.TrimSpace(input), "$")
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return "", ErrInvalidName
	}
	return name, nil
}

// AssetNameHex returns the base-handle on-chain asset name: the hex encoding
// of the handle's UTF-8 bytes (assetName = hex(utf8(name))). It does not
// handle CIP-113 virtual sub-handles ("$a@b"), only the base handle.
func AssetNameHex(name string) string {
	return hex.EncodeToString([]byte(name))
}

// PolicyForNetwork returns the ADA Handle policy ID for a supported Cardano
// network and whether handle resolution is available there.
func PolicyForNetwork(network string) (policyID string, ok bool) {
	if cardanonet.ValidNetwork(network) {
		return PolicyID, true
	}
	return "", false
}

// AssetUnit returns the Blockfrost-style asset unit (policy ID concatenated
// with the hex-encoded asset name) identifying handle name on network, or
// ok=false when network is unsupported.
func AssetUnit(network, name string) (unit string, ok bool) {
	policy, ok := PolicyForNetwork(network)
	if !ok {
		return "", false
	}
	return policy + AssetNameHex(name), true
}

// AssetLookup is the node-backed surface Resolve needs: the current holder
// addresses for an on-chain asset unit. *chain.Client satisfies it via
// AssetAddresses (GET /api/v0/assets/{asset}/addresses on the embedded node).
type AssetLookup interface {
	AssetAddresses(ctx context.Context, asset string) ([]chain.AssetAddress, error)
}

// Resolve resolves an ADA Handle (input may or may not carry a leading '$',
// and is matched case-insensitively — see Normalize) to its current holding
// address by querying lookup for the handle NFT's holder on network. It
// returns the normalized (lowercased, '$'-stripped) name alongside the
// address, so callers don't need to normalize the input a second time. It
// returns chain.ErrNotFound — never a hard error — for every "not found"
// case: an empty/invalid name, an unsupported network, the node not having
// seen the asset, or the asset having no current holder. Any other lookup
// error is returned as-is.
func Resolve(ctx context.Context, lookup AssetLookup, network, input string) (name, address string, err error) {
	name, err = Normalize(input)
	if err != nil {
		return "", "", chain.ErrNotFound
	}
	unit, ok := AssetUnit(network, name)
	if !ok {
		return name, "", chain.ErrNotFound
	}
	if lookup == nil {
		return name, "", chain.ErrNotFound
	}
	addrs, err := lookup.AssetAddresses(ctx, unit)
	if err != nil {
		return name, "", err
	}
	if len(addrs) == 0 {
		return name, "", chain.ErrNotFound
	}
	if len(addrs) != 1 || addrs[0].Address == "" || addrs[0].Quantity != "1" {
		return name, "", ErrAmbiguousHolder
	}
	return name, addrs[0].Address, nil
}
