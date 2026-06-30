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

//go:build !nftmedia

// This file is the no-op IPFS client used by the DEFAULT build. It implements
// the same newIPFSClient constructor as the real boxo client (client_ipfs.go)
// but imports NO peer-to-peer dependencies — boxo and libp2p stay out of the
// default dependency closure entirely, keeping the binary near baseline. Build
// with `-tags nftmedia` to pull in the real client.
//
// Because no client can ever start, enabling NFT media in this build fails
// fast with ErrMediaUnavailable; the service and API surface that gracefully
// (the toggle reports media as unavailable rather than starting anything).
package nft

import (
	"context"
	"errors"
)

// ErrMediaUnavailable is returned when NFT media is requested in a build that
// does not include the embedded IPFS client (i.e. built without `-tags
// nftmedia`). It is distinct from ErrMediaDisabled, which means media is
// compiled in but switched off by the user.
var ErrMediaUnavailable = errors.New("nft: media not available in this build")

// newIPFSClient is the stub constructor. It never starts a libp2p host and
// imports no boxo/libp2p code; it simply reports that media is unavailable so
// callers can degrade gracefully. The signature matches the real constructor
// in client_ipfs.go exactly.
func newIPFSClient(_ context.Context) (fetcher, error) {
	return nil, ErrMediaUnavailable
}
