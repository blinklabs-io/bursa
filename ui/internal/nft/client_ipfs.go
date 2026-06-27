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

//go:build nftmedia

// This file holds the real embedded IPFS retrieval client (boxo: libp2p + DHT +
// bitswap). It is the ONLY file that imports the heavy peer-to-peer stack, and
// it is compiled ONLY into the `-tags nftmedia` build. The default build uses
// the no-op stub in client_stub.go instead, so boxo/libp2p never enter the
// dependency closure (keeping the binary near baseline). This mirrors the
// `webview` build-tag split in cmd/bursa-wallet.
package nft

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/ipfs/boxo/bitswap"
	bsnet "github.com/ipfs/boxo/bitswap/network/bsnet"
	"github.com/ipfs/boxo/blockservice"
	blockstore "github.com/ipfs/boxo/blockstore"
	unixfile "github.com/ipfs/boxo/ipld/unixfs/file"
	"github.com/ipfs/boxo/ipld/merkledag"
	gocid "github.com/ipfs/go-cid"
	"github.com/ipfs/go-datastore"
	dssync "github.com/ipfs/go-datastore/sync"
	ipld "github.com/ipfs/go-ipld-format"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// bootstrapPeers are public libp2p bootstrap nodes used to join the IPFS DHT so
// the client can discover which peers provide a given CID. These are the IPFS
// project's well-known bootstrappers — peer-discovery infrastructure, not a
// data service: no NFT/wallet data is sent to them, only DHT routing queries.
var bootstrapPeers = []string{
	"/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
	"/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
	"/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
	"/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
}

// fetchTimeout bounds a single CID fetch (DHT lookup + bitswap transfer).
const fetchTimeout = 60 * time.Second

// ipfsClient is the embedded IPFS retrieval client: a libp2p host, a Kademlia
// DHT (client mode) for provider routing, and a bitswap exchange. It is the
// user's OWN node-like infrastructure — it speaks the IPFS peer protocol
// directly and contacts no hosted gateway or delegated-routing HTTP service.
//
// The client is started ONLY when NFT media is enabled (see Service.start). A
// zero ipfsClient is never used; nil-checks live in the Service.
type ipfsClient struct {
	host    host.Host
	dht     *dht.IpfsDHT
	bswap   *bitswap.Bitswap
	dag     ipld.DAGService
	closeMu sync.Mutex
	closed  bool
}

// newIPFSClient brings up the libp2p host, DHT and bitswap exchange and kicks
// off (non-blocking) bootstrap. ctx governs the lifetime of background swarm
// activity; cancelling it (or calling Close) tears the client down.
func newIPFSClient(ctx context.Context) (fetcher, error) {
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"))
	if err != nil {
		return nil, fmt.Errorf("nft: libp2p host: %w", err)
	}
	kad, err := dht.New(ctx, h, dht.Mode(dht.ModeClient))
	if err != nil {
		_ = h.Close()
		return nil, fmt.Errorf("nft: dht: %w", err)
	}

	ds := dssync.MutexWrap(datastore.NewMapDatastore())
	bs := blockstore.NewBlockstore(ds)
	net := bsnet.NewFromIpfsHost(h)
	bswap := bitswap.New(ctx, net, kad, bs)
	net.Start(bswap)
	dag := merkledag.NewDAGService(blockservice.New(bs, bswap))

	c := &ipfsClient{host: h, dht: kad, bswap: bswap, dag: dag}
	c.bootstrap(ctx)
	go func() {
		// Best-effort: build the DHT routing table in the background. Fetches
		// initiated before this completes simply take longer.
		_ = kad.Bootstrap(ctx)
	}()
	return c, nil
}

// bootstrap dials the public bootstrap peers (best-effort, in the background).
func (c *ipfsClient) bootstrap(ctx context.Context) {
	for _, addr := range bootstrapPeers {
		ma, err := multiaddr.NewMultiaddr(addr)
		if err != nil {
			continue
		}
		ai, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			continue
		}
		go func(ai peer.AddrInfo) {
			dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			_ = c.host.Connect(dialCtx, ai)
		}(*ai)
	}
}

// fetch retrieves the bytes of a UnixFS file at cidStr over the IPFS p2p
// network. It is read-only and bounded by fetchTimeout (and the caller's ctx).
func (c *ipfsClient) fetch(ctx context.Context, cidStr string) ([]byte, error) {
	id, err := gocid.Decode(cidStr)
	if err != nil {
		return nil, fmt.Errorf("nft: invalid cid %q: %w", cidStr, err)
	}
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	nd, err := c.dag.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("nft: fetch %s: %w", cidStr, err)
	}
	f, err := unixfile.NewUnixfsFile(ctx, c.dag, nd)
	if err != nil {
		return nil, fmt.Errorf("nft: unixfs %s: %w", cidStr, err)
	}
	r, ok := f.(io.Reader)
	if !ok {
		return nil, fmt.Errorf("nft: cid %s is not a file", cidStr)
	}
	// Cap the read so a hostile provider can't stream an unbounded "image".
	data, err := io.ReadAll(io.LimitReader(r, maxImageBytes+1))
	if err != nil {
		return nil, fmt.Errorf("nft: read %s: %w", cidStr, err)
	}
	if len(data) > maxImageBytes {
		return nil, fmt.Errorf("nft: image %s exceeds %d bytes", cidStr, maxImageBytes)
	}
	return data, nil
}

// Close tears down the bitswap exchange, DHT and libp2p host. Safe to call
// more than once.
func (c *ipfsClient) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.bswap != nil {
		_ = c.bswap.Close()
	}
	if c.dht != nil {
		_ = c.dht.Close()
	}
	if c.host != nil {
		return c.host.Close()
	}
	return nil
}
