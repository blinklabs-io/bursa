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
package boundary

import (
	"os/exec"
	"strings"
	"testing"
)

// denylist is import-path substrings for external services the wallet must
// never reach. Sanctioned outbound links: the embedded node's P2P, and a
// one-time Mithril snapshot download at bootstrap (first-party Cardano infra,
// certificate-verified, leaks no wallet data — see internal/supervisor/bootstrap.go).
//
// On the embedded IPFS client (boxo / go-libp2p / go-libp2p-kad-dht, used by
// internal/nft): these are deliberately NOT denylisted. They are peer-to-peer
// protocol libraries — the user's OWN IPFS retrieval client, in the same spirit
// as the embedded Cardano node — not a hosted-service or gateway SDK. Crucially:
//   - The client is OFF by default and is only started after a one-time,
//     deliberate opt-in (the "Enable NFT media" setting). While disabled, no
//     libp2p host is created and nothing touches the network.
//   - Retrieval is direct p2p (DHT provider routing + bitswap). There is NO
//     third-party HTTP gateway and NO delegated-routing HTTP service: no hosted
//     IPFS SaaS SDK (e.g. pinata, web3.storage, nft.storage, infura ipfs) is
//     imported. If one ever is, add its import substring here to fail the build.
var denylist = []string{
	// Hosted IPFS / gateway SaaS SDKs — the embedded boxo client must never be
	// swapped for one of these. (None are imported today.)
	"web3-storage",
	"nftstorage",
	"pinata",
	"coingecko",
	"coinmarketcap",
	"binance", // matches go-binance, binance-connector-go, api.binance, etc.
	"kraken",
	"coinbase",
	"bybit",
	"blockfrost/blockfrost-go", // hosted Blockfrost SaaS SDK (we use the LOCAL dingo/blockfrost endpoint, not this)
	"maestro",                  // hosted indexer
}

func TestHostedIPFSDenylistMatchesRealModulePaths(t *testing.T) {
	for _, module := range []string{
		"github.com/web3-storage/go-w3s-client",
		"github.com/nftstorage/go-client",
	} {
		matched := false
		for _, bad := range denylist {
			matched = matched || strings.Contains(module, bad)
		}
		if !matched {
			t.Errorf("known hosted IPFS module %q is not denied", module)
		}
	}
}

// TestNoExternalServiceImports walks the bursa-wallet module's full transitive
// import set and fails if any denylisted package is present.
//
// The scan is scoped to the module's real Go package roots (cmd + internal)
// rather than "../../..." on purpose: the SPA under ../../web ships an npm
// dependency tree, and at least one package (flatted) vendors a stray *.go
// file under node_modules. Go's "..." wildcard does NOT skip node_modules, so a
// repo-wide list would pull that package into the module graph and, on a clean
// CI checkout, fail module resolution ("updates to go.mod needed"). The wallet's
// outbound surface lives entirely under cmd/ and internal/, so those roots are
// the correct and complete scope for this boundary check.
func TestNoExternalServiceImports(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "../../cmd/...", "../../internal/...").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	deps := strings.Split(strings.TrimSpace(string(out)), "\n")
	// Sanity-check the scan actually ran: the module pulls in dingo and its
	// large transitive closure, so a tiny count means go list returned nothing
	// useful and the denylist below would vacuously pass.
	if len(deps) < 50 {
		t.Fatalf("dependency scan returned only %d entries; go list likely failed", len(deps))
	}
	for _, imp := range deps {
		for _, bad := range denylist {
			if strings.Contains(imp, bad) {
				t.Errorf("forbidden external-service import in closure: %q (matched %q)", imp, bad)
			}
		}
	}
}
