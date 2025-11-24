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

	"github.com/blinklabs-io/bursa"
)

// Wallet represents a stored wallet with metadata and key-value storage.
// It provides a unified interface for wallet persistence across different storage backends.
type Wallet interface {
	// Name returns the wallet's unique identifier.
	Name() string

	// Description returns the wallet's description.
	Description() string

	// SetDescription sets the wallet's description.
	SetDescription(description string)

	// Items returns a copy of all key-value items in the wallet.
	Items() map[string]string

	// ListItems returns a list of all item keys in the wallet.
	ListItems() []string

	// GetItem retrieves the value for the given item key.
	// Returns an error if the key does not exist.
	GetItem(name string) (string, error)

	// PutItem stores a key-value pair in the wallet.
	PutItem(name, value string)

	// DeleteItem removes an item from the wallet by key.
	DeleteItem(name string)

	// PopulateFrom populates the wallet from a bursa.Wallet instance.
	PopulateFrom(wallet *bursa.Wallet) error

	// PopulateTo populates a bursa.Wallet instance from the stored wallet data.
	PopulateTo(wallet *bursa.Wallet) error

	// Load loads the wallet data from the storage backend.
	Load(ctx context.Context) error

	// Save persists the wallet data to the storage backend.
	Save(ctx context.Context) error

	// Delete removes the wallet from the storage backend.
	Delete(ctx context.Context) error
}

// Store represents a storage backend that can manage wallets.
// Different implementations provide storage in various systems like filesystems, databases, or cloud services.
type Store interface {
	// GetWallet retrieves a wallet by name from the storage backend.
	GetWallet(ctx context.Context, name string) (Wallet, error)

	// ListWallets returns all wallets in the storage backend.
	ListWallets(ctx context.Context) ([]Wallet, error)

	// CreateWallet creates a new wallet with the given name.
	CreateWallet(name string) Wallet

	// DeleteWallet removes a wallet from the storage backend.
	DeleteWallet(ctx context.Context, name string) error
}
