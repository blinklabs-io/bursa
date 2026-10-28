// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"bytes"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/stretchr/testify/require"
)

var (
	votePoolHash = bytes.Repeat([]byte{0x11}, 28)
	voteTxID     = strings.Repeat("ab", 32)
	voteAnchor   = strings.Repeat("cd", 32)
)

func votePoolBech32(t *testing.T) string {
	t.Helper()
	conv, err := bech32.ConvertBits(votePoolHash, 8, 5, true)
	require.NoError(t, err)
	s, err := bech32.Encode("pool", conv)
	require.NoError(t, err)
	return s
}

func TestPoolVoteFlagsNone(t *testing.T) {
	pv, err := PoolVoteFlags{}.poolVote()
	require.NoError(t, err)
	require.Nil(t, pv)
}

func TestPoolVoteFlags(t *testing.T) {
	for _, tc := range []struct {
		pool  string
		vote  string
		index string
		want  uint8
		idx   uint32
	}{
		{votePoolBech32(t), "yes", "3", lcommon.GovVoteYes, 3},
		{hex.EncodeToString(votePoolHash), "No", "0", lcommon.GovVoteNo, 0},
		{votePoolBech32(t), "abstain", "65535", lcommon.GovVoteAbstain, 65535},
	} {
		pv, err := PoolVoteFlags{
			PoolID:    tc.pool,
			GovAction: voteTxID + "#" + tc.index,
			Vote:      tc.vote,
		}.poolVote()
		require.NoError(t, err, tc.vote)
		require.Equal(t, votePoolHash, pv.PoolKeyHash[:])
		require.Equal(t, voteTxID, hex.EncodeToString(pv.ActionTxId[:]))
		require.Equal(t, tc.idx, pv.ActionIndex)
		require.Equal(t, tc.want, pv.Vote)
		require.Nil(t, pv.Anchor)
	}
}

func TestPoolVoteFlagsAnchor(t *testing.T) {
	url := "https://" + strings.Repeat("a", 120) // 128 bytes
	pv, err := PoolVoteFlags{
		PoolID:     votePoolBech32(t),
		GovAction:  voteTxID + "#1",
		Vote:       "yes",
		AnchorURL:  url,
		AnchorHash: voteAnchor,
	}.poolVote()
	require.NoError(t, err)
	require.NotNil(t, pv.Anchor)
	require.Equal(t, url, pv.Anchor.Url)
	require.Equal(t, voteAnchor, hex.EncodeToString(pv.Anchor.DataHash[:]))
}

func TestPoolVoteFlagsInvalid(t *testing.T) {
	good := PoolVoteFlags{
		PoolID:    votePoolBech32(t),
		GovAction: voteTxID + "#1",
		Vote:      "yes",
	}
	for name, mutate := range map[string]func(*PoolVoteFlags){
		"missing vote":     func(f *PoolVoteFlags) { f.Vote = "" },
		"vote word":        func(f *PoolVoteFlags) { f.Vote = "maybe" },
		"short pool id":    func(f *PoolVoteFlags) { f.PoolID = "abcd" },
		"no index":         func(f *PoolVoteFlags) { f.GovAction = voteTxID },
		"bad tx id":        func(f *PoolVoteFlags) { f.GovAction = "zz#1" },
		"index too large":  func(f *PoolVoteFlags) { f.GovAction = voteTxID + "#65536" },
		"url without hash": func(f *PoolVoteFlags) { f.AnchorURL = "https://x" },
		"hash without url": func(f *PoolVoteFlags) { f.AnchorHash = voteAnchor },
		"bad anchor hash":  func(f *PoolVoteFlags) { f.AnchorURL, f.AnchorHash = "https://x", "zz" },
		"anchor url too long": func(f *PoolVoteFlags) {
			f.AnchorURL, f.AnchorHash = "https://"+strings.Repeat("a", 121), voteAnchor
		},
	} {
		f := good
		mutate(&f)
		_, err := f.poolVote()
		require.Error(t, err, name)
	}
}

// An invalid vote is reported before the node is dialed: the socket path
// does not exist, so a dial would fail with a different error.
func TestRunTxBuildValidatesVoteBeforeDialing(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "missing.socket")
	err := RunTxBuild(socket, "preview", "addr_test1x", nil, 1, "", 3600, 5,
		PoolVoteFlags{
			PoolID:    votePoolBech32(t),
			GovAction: voteTxID + "#1",
			Vote:      "maybe",
		})
	require.ErrorContains(t, err, "--vote:")
}
