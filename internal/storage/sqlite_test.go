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

package storage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestSQLiteStore(t *testing.T) *SQLiteStore {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "bursa-sqlite-test")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	dbPath := filepath.Join(tempDir, "test.db")
	store, err := NewSQLiteStore(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	return store
}

func TestSQLiteStore(t *testing.T) {
	store := newTestSQLiteStore(t)

	t.Run("CreateWallet", func(t *testing.T) {
		wallet, err := store.CreateWallet("test-wallet")
		assert.NoError(t, err)
		assert.Equal(t, "test-wallet", wallet.Name())
		assert.Empty(t, wallet.Description())
	})

	t.Run("SaveAndLoadWallet", func(t *testing.T) {
		wallet, err := store.CreateWallet("save-test")
		assert.NoError(t, err)

		bursaWallet, err := bursa.NewWallet(
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		)
		require.NoError(t, err)

		err = wallet.PopulateFrom(bursaWallet)
		require.NoError(t, err)

		err = wallet.Save(context.Background())
		require.NoError(t, err)

		loadedWallet, err := store.GetWallet(
			context.Background(),
			"save-test",
		)
		require.NoError(t, err)

		assert.Equal(t, "save-test", loadedWallet.Name())
		assert.Equal(
			t,
			"Wallet created from bursa.Wallet",
			loadedWallet.Description(),
		)

		items := loadedWallet.ListItems()
		assert.Contains(t, items, "mnemonic")
		assert.Contains(t, items, "payment_address")
		assert.Contains(t, items, "stake_address")
	})

	t.Run("PopulateTo", func(t *testing.T) {
		wallet, err := store.CreateWallet("populate-to-test")
		assert.NoError(t, err)

		originalWallet, err := bursa.NewWallet(
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		)
		require.NoError(t, err)

		err = wallet.PopulateFrom(originalWallet)
		require.NoError(t, err)

		err = wallet.Save(context.Background())
		require.NoError(t, err)

		loadedWallet, err := store.GetWallet(
			context.Background(),
			"populate-to-test",
		)
		require.NoError(t, err)

		newWallet := &bursa.Wallet{}
		err = loadedWallet.PopulateTo(newWallet)
		require.NoError(t, err)

		assert.Equal(
			t,
			originalWallet.Mnemonic,
			newWallet.Mnemonic,
		)
		assert.Equal(
			t,
			originalWallet.PaymentAddress,
			newWallet.PaymentAddress,
		)
		assert.Equal(
			t,
			originalWallet.StakeAddress,
			newWallet.StakeAddress,
		)
	})

	t.Run("ListWallets", func(t *testing.T) {
		wallet1, err := store.CreateWallet("list-test-1")
		assert.NoError(t, err)
		wallet2, err := store.CreateWallet("list-test-2")
		assert.NoError(t, err)

		err = wallet1.Save(context.Background())
		require.NoError(t, err)
		err = wallet2.Save(context.Background())
		require.NoError(t, err)

		wallets, err := store.ListWallets(
			context.Background(),
		)
		require.NoError(t, err)

		names := make([]string, len(wallets))
		for i, w := range wallets {
			names[i] = w.Name()
		}

		assert.Contains(t, names, "list-test-1")
		assert.Contains(t, names, "list-test-2")
	})

	t.Run("DeleteWallet", func(t *testing.T) {
		wallet, err := store.CreateWallet("delete-test")
		assert.NoError(t, err)
		err = wallet.Save(context.Background())
		require.NoError(t, err)

		_, err = store.GetWallet(
			context.Background(),
			"delete-test",
		)
		require.NoError(t, err)

		err = store.DeleteWallet(
			context.Background(),
			"delete-test",
		)
		require.NoError(t, err)

		_, err = store.GetWallet(
			context.Background(),
			"delete-test",
		)
		assert.Error(t, err)
	})

	t.Run("WalletNotFound", func(t *testing.T) {
		_, err := store.GetWallet(
			context.Background(),
			"nonexistent",
		)
		assert.Error(t, err)
	})
}

func TestSQLiteStoreWalletOperations(t *testing.T) {
	store := newTestSQLiteStore(t)
	wallet, err := store.CreateWallet("ops-test")
	assert.NoError(t, err)

	t.Run("ItemOperations", func(t *testing.T) {
		wallet.PutItem("test-key", "test-value")
		value, err := wallet.GetItem("test-key")
		require.NoError(t, err)
		assert.Equal(t, "test-value", value)

		items := wallet.ListItems()
		assert.Contains(t, items, "test-key")

		wallet.DeleteItem("test-key")
		_, err = wallet.GetItem("test-key")
		assert.Error(t, err)
	})

	t.Run("GetNonexistentItem", func(t *testing.T) {
		_, err := wallet.GetItem("nonexistent")
		assert.Error(t, err)
	})
}

func TestSQLiteStoreUpdateWallet(t *testing.T) {
	store := newTestSQLiteStore(t)

	wallet, err := store.CreateWallet("update-test")
	require.NoError(t, err)

	wallet.SetDescription("original description")
	wallet.PutItem("key1", "value1")
	err = wallet.Save(context.Background())
	require.NoError(t, err)

	// Load and update
	loaded, err := store.GetWallet(
		context.Background(),
		"update-test",
	)
	require.NoError(t, err)
	assert.Equal(t, "original description", loaded.Description())

	loaded.SetDescription("updated description")
	loaded.PutItem("key2", "value2")
	err = loaded.Save(context.Background())
	require.NoError(t, err)

	// Verify update
	reloaded, err := store.GetWallet(
		context.Background(),
		"update-test",
	)
	require.NoError(t, err)
	assert.Equal(
		t,
		"updated description",
		reloaded.Description(),
	)

	items := reloaded.Items()
	assert.Equal(t, "value1", items["key1"])
	assert.Equal(t, "value2", items["key2"])
}

func TestSQLiteStoreDeleteNonexistent(t *testing.T) {
	store := newTestSQLiteStore(t)

	err := store.DeleteWallet(
		context.Background(),
		"nonexistent",
	)
	assert.Error(t, err)
}

func TestSQLiteStoreWalletDelete(t *testing.T) {
	store := newTestSQLiteStore(t)

	wallet, err := store.CreateWallet("wallet-delete-test")
	require.NoError(t, err)
	wallet.PutItem("key", "value")
	err = wallet.Save(context.Background())
	require.NoError(t, err)

	// Delete via wallet method
	err = wallet.Delete(context.Background())
	require.NoError(t, err)

	_, err = store.GetWallet(
		context.Background(),
		"wallet-delete-test",
	)
	assert.Error(t, err)
}

func TestSQLiteStoreInvalidWalletNames(t *testing.T) {
	store := newTestSQLiteStore(t)

	invalidNames := []string{
		"",
		"../../../etc/passwd",
		"wallet/../secret",
		"wallet/with/slashes",
		"wallet\\with\\backslashes",
		"wallet with spaces",
		"wallet@special",
		strings.Repeat("a", 256),
	}

	t.Run(
		"CreateWalletRejectsInvalidNames",
		func(t *testing.T) {
			for _, name := range invalidNames {
				_, err := store.CreateWallet(name)
				assert.Error(
					t,
					err,
					"CreateWallet should reject invalid name: %s",
					name,
				)
			}
		},
	)

	t.Run(
		"GetWalletRejectsInvalidNames",
		func(t *testing.T) {
			for _, name := range invalidNames {
				_, err := store.GetWallet(
					context.Background(),
					name,
				)
				assert.Error(
					t,
					err,
					"GetWallet should reject invalid name: %s",
					name,
				)
			}
		},
	)

	t.Run(
		"DeleteWalletRejectsInvalidNames",
		func(t *testing.T) {
			for _, name := range invalidNames {
				err := store.DeleteWallet(
					context.Background(),
					name,
				)
				assert.Error(
					t,
					err,
					"DeleteWallet should reject invalid name: %s",
					name,
				)
			}
		},
	)

	validNames := []string{
		"simple",
		"with-numbers-123",
		"with_underscores",
		"mixed-123_abc",
		"a",
		"long-but-valid-name-1234567890",
	}

	t.Run("ValidNamesWork", func(t *testing.T) {
		for _, name := range validNames {
			wallet, err := store.CreateWallet(name)
			assert.NoError(t, err)
			assert.Equal(t, name, wallet.Name())

			err = wallet.Save(context.Background())
			assert.NoError(
				t,
				err,
				"Save should work for valid name: %s",
				name,
			)

			loaded, err := store.GetWallet(
				context.Background(),
				name,
			)
			assert.NoError(
				t,
				err,
				"GetWallet should work for valid name: %s",
				name,
			)
			assert.Equal(t, name, loaded.Name())
		}
	})
}

func TestSQLiteStoreEmptyList(t *testing.T) {
	store := newTestSQLiteStore(t)

	wallets, err := store.ListWallets(context.Background())
	require.NoError(t, err)
	assert.Empty(t, wallets)
	assert.NotNil(t, wallets)
}

func TestSQLiteStorePopulateToNilWallet(t *testing.T) {
	store := newTestSQLiteStore(t)

	wallet, err := store.CreateWallet("nil-test")
	require.NoError(t, err)

	err = wallet.PopulateTo(nil)
	assert.Error(t, err)
}

func TestSQLiteStoreItemsCopy(t *testing.T) {
	store := newTestSQLiteStore(t)

	wallet, err := store.CreateWallet("copy-test")
	require.NoError(t, err)

	wallet.PutItem("key1", "value1")

	// Get items copy and modify it
	items := wallet.Items()
	items["key2"] = "value2"

	// Original should not be modified
	_, err = wallet.GetItem("key2")
	assert.Error(t, err)
}
