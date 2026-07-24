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
//
//go:build integration && nftmedia

package nft

import (
	"context"
	"testing"
	"time"
)

// TestRealIPFSFetch exercises the real embedded IPFS client (libp2p host + DHT +
// bitswap) against the public swarm, fetching a well-known CID over direct p2p
// with NO gateway. It is network-dependent and SLOW, so it sits behind the
// project's `integration` build tag (matching spend/supervisor integration
// tests) and is excluded from the default `go test ./...` run. It also requires
// the `nftmedia` tag, since the real boxo client only exists in that build (the
// default build's stub never touches the network). Run it with
// `go test -tags 'integration nftmedia' -run TestRealIPFSFetch ./internal/nft`.
func TestRealIPFSFetch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	c, err := newIPFSClient(ctx)
	if err != nil {
		t.Fatalf("newIPFSClient: %v", err)
	}
	defer func() { _ = c.Close() }()
	client, ok := c.(*ipfsClient)
	if !ok {
		t.Fatalf("newIPFSClient returned %T, want *ipfsClient", c)
	}
	if client.bswap.Server != nil {
		t.Fatal("embedded retrieval client has a Bitswap server")
	}

	// Wait only as long as needed for bootstrap to add a routing peer. A fixed
	// sleep is both wasteful on fast networks and unreliable on slow ones.
	for client.dht.RoutingTable().Size() == 0 {
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for DHT routing peer: %v", ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}

	// A widely-pinned single small FILE (the "about" page of the canonical IPFS
	// welcome directory) — NFT images are files, so this matches the real case.
	const cid = "QmZTR5bcpQD7cFgTorqxZDYaew1Wqgfbd2ud9QqGPAkK2V"
	data, err := c.fetch(ctx, cid)
	if err != nil {
		t.Fatalf("fetch %s over p2p: %v", cid, err)
	}
	if len(data) == 0 {
		t.Fatalf("fetched 0 bytes for %s", cid)
	}
	t.Logf("fetched %d bytes for %s via direct p2p (no gateway)", len(data), cid)
}
