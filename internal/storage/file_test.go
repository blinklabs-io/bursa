// Copyright 2025 Blink Labs Software
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

func TestFileStore(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "bursa-storage-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	store := NewFileStore(tempDir)

	t.Run("CreateWallet", func(t *testing.T) {
		wallet, err := store.CreateWallet("test-wallet")
		assert.NoError(t, err)
		assert.Equal(t, "test-wallet", wallet.Name())
		assert.Empty(t, wallet.Description())
	})

	t.Run("SaveAndLoadWallet", func(t *testing.T) {
		wallet, err := store.CreateWallet("save-test")
		assert.NoError(t, err)

		// Create a bursa wallet to populate from
		bursaWallet, err := bursa.NewWallet(
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			"mainnet",
			"",
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
		)
		require.NoError(t, err)

		err = wallet.PopulateFrom(bursaWallet)
		require.NoError(t, err)

		// Save the wallet
		err = wallet.Save(context.Background())
		require.NoError(t, err)

		// Load the wallet
		loadedWallet, err := store.GetWallet(context.Background(), "save-test")
		require.NoError(t, err)

		assert.Equal(t, "save-test", loadedWallet.Name())
		assert.Equal(
			t,
			"Wallet created from bursa.Wallet",
			loadedWallet.Description(),
		)

		// Check that items were saved
		items := loadedWallet.ListItems()
		assert.Contains(t, items, "mnemonic")
		assert.Contains(t, items, "payment_address")
		assert.Contains(t, items, "stake_address")
	})

	t.Run("PopulateTo", func(t *testing.T) {
		wallet, err := store.CreateWallet("populate-to-test")
		assert.NoError(t, err)

		// Create a bursa wallet to populate from
		originalWallet, err := bursa.NewWallet(
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			"mainnet",
			"",
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
		)
		require.NoError(t, err)

		err = wallet.PopulateFrom(originalWallet)
		require.NoError(t, err)

		// Save and reload the wallet
		err = wallet.Save(context.Background())
		require.NoError(t, err)

		loadedWallet, err := store.GetWallet(
			context.Background(),
			"populate-to-test",
		)
		require.NoError(t, err)

		// Create a new empty bursa wallet and populate it
		newWallet := &bursa.Wallet{}
		err = loadedWallet.PopulateTo(newWallet)
		require.NoError(t, err)

		// Verify the data was populated correctly
		assert.Equal(t, originalWallet.Mnemonic, newWallet.Mnemonic)
		assert.Equal(t, originalWallet.PaymentAddress, newWallet.PaymentAddress)
		assert.Equal(t, originalWallet.StakeAddress, newWallet.StakeAddress)
	})

	t.Run("ListWallets", func(t *testing.T) {
		// Create a few wallets
		wallet1, err := store.CreateWallet("list-test-1")
		assert.NoError(t, err)
		wallet2, err := store.CreateWallet("list-test-2")
		assert.NoError(t, err)

		err = wallet1.Save(context.Background())
		require.NoError(t, err)
		err = wallet2.Save(context.Background())
		require.NoError(t, err)

		wallets, err := store.ListWallets(context.Background())
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

		// Verify it exists
		_, err = store.GetWallet(context.Background(), "delete-test")
		require.NoError(t, err)

		// Delete it
		err = store.DeleteWallet(context.Background(), "delete-test")
		require.NoError(t, err)

		// Verify it's gone
		_, err = store.GetWallet(context.Background(), "delete-test")
		assert.Error(t, err)
	})

	t.Run("WalletNotFound", func(t *testing.T) {
		_, err := store.GetWallet(context.Background(), "nonexistent")
		assert.Error(t, err)
	})
}

func TestFileStoreWalletOperations(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "bursa-wallet-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	store := NewFileStore(tempDir)
	wallet, err := store.CreateWallet("ops-test")
	assert.NoError(t, err)

	t.Run("ItemOperations", func(t *testing.T) {
		// Test PutItem and GetItem
		wallet.PutItem("test-key", "test-value")
		value, err := wallet.GetItem("test-key")
		require.NoError(t, err)
		assert.Equal(t, "test-value", value)

		// Test ListItems
		items := wallet.ListItems()
		assert.Contains(t, items, "test-key")

		// Test DeleteItem
		wallet.DeleteItem("test-key")
		_, err = wallet.GetItem("test-key")
		assert.Error(t, err)
	})

	t.Run("GetNonexistentItem", func(t *testing.T) {
		_, err := wallet.GetItem("nonexistent")
		assert.Error(t, err)
	})
}

func TestFileStoreDirectoryStructure(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "bursa-dir-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	store := NewFileStore(tempDir)
	wallet, err := store.CreateWallet("dir-test")
	assert.NoError(t, err)
	wallet.PutItem("test", "data")

	err = wallet.Save(context.Background())
	require.NoError(t, err)

	// Check directory structure
	walletDir := filepath.Join(tempDir, "wallet-dir-test")
	assert.DirExists(t, walletDir)

	walletFile := filepath.Join(walletDir, "wallet.json")
	assert.FileExists(t, walletFile)
}

func TestFileStoreInvalidWalletNames(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "bursa-invalid-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	store := NewFileStore(tempDir)

	invalidNames := []string{
		"",                          // empty name
		"../../../etc/passwd",       // path traversal
		"wallet/../secret",          // path traversal with valid prefix
		"wallet/with/slashes",       // path separators
		"wallet\\with\\backslashes", // backslashes
		"wallet with spaces",        // spaces (not in allowed charset)
		"wallet@special",            // special characters
		strings.Repeat("a", 256),    // too long
	}

	t.Run("CreateWalletRejectsInvalidNames", func(t *testing.T) {
		for _, name := range invalidNames {
			_, err := store.CreateWallet(name)
			assert.Error(
				t,
				err,
				"CreateWallet should reject invalid name: %s",
				name,
			)
		}
	})

	t.Run("GetWalletRejectsInvalidNames", func(t *testing.T) {
		for _, name := range invalidNames {
			_, err := store.GetWallet(context.Background(), name)
			assert.Error(
				t,
				err,
				"GetWallet should reject invalid name: %s",
				name,
			)
		}
	})

	t.Run("DeleteWalletRejectsInvalidNames", func(t *testing.T) {
		for _, name := range invalidNames {
			err := store.DeleteWallet(context.Background(), name)
			assert.Error(
				t,
				err,
				"DeleteWallet should reject invalid name: %s",
				name,
			)
		}
	})

	// Test that valid names work
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
			assert.NoError(t, err, "Save should work for valid name: %s", name)

			loaded, err := store.GetWallet(context.Background(), name)
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
