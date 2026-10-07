//go:build unix

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

package storage

import (
	"context"
	"os"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileStoreGetWalletRejectsGroupOrOtherAccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewFileStore(t.TempDir())
	w, err := store.CreateWallet("perm")
	require.NoError(t, err)
	w.PutItem("k", "v")
	require.NoError(t, w.Save(ctx))
	path := store.walletPath("perm")

	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o660, 0o666, 0o610, 0o601} {
		require.NoError(t, os.Chmod(path, mode))
		_, err := store.GetWallet(ctx, "perm")
		assert.ErrorIs(t, err, bursa.ErrInsecureFileMode, "mode %04o", mode)
	}
	for _, mode := range []os.FileMode{0o600, 0o400} {
		require.NoError(t, os.Chmod(path, mode))
		_, err := store.GetWallet(ctx, "perm")
		assert.NoError(t, err, "mode %04o", mode)
	}
}
