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
	"github.com/blinklabs-io/bursa/gcp"
	"github.com/blinklabs-io/bursa/internal/logging"
)

// GCPStore implements the Store interface using Google Cloud Secret Manager.
// It provides secure wallet storage using GCP's Secret Manager service.
type GCPStore struct{}

// NewGCPStore creates a new GCP storage backend.
// It initializes a store that uses Google Cloud Secret Manager for wallet persistence.
func NewGCPStore() *GCPStore {
	return &GCPStore{}
}

// GetWallet retrieves a wallet from GCP Secret Manager.
// The wallet name corresponds to a secret in GCP Secret Manager.
func (s *GCPStore) GetWallet(ctx context.Context, name string) (Wallet, error) {
	gcpWallet, err := gcp.GetGoogleWallet(ctx, name)
	if err != nil {
		return nil, err
	}
	return &gcpWalletAdapter{wallet: gcpWallet}, nil
}

// ListWallets lists all wallets stored in GCP Secret Manager.
// It returns wallets for all accessible secrets in the configured GCP project.
func (s *GCPStore) ListWallets(ctx context.Context) ([]Wallet, error) {
	walletNames, err := gcp.ListGoogleWallets(ctx, nil)
	if err != nil {
		return nil, err
	}

	wallets := make([]Wallet, 0, len(walletNames))
	for _, name := range walletNames {
		gcpWallet, err := gcp.GetGoogleWallet(ctx, name)
		if err != nil {
			logging.GetLogger().
				Debug("skipping inaccessible wallet during list", "wallet", name, "error", err)
			continue // Skip wallets that can't be loaded
		}
		wallets = append(wallets, &gcpWalletAdapter{wallet: gcpWallet})
	}
	return wallets, nil
}

// CreateWallet creates a new wallet instance for GCP storage.
// The wallet is not persisted until Save() is called.
func (s *GCPStore) CreateWallet(name string) (Wallet, error) {
	gcpWallet := gcp.NewGoogleWallet(name)
	return &gcpWalletAdapter{wallet: gcpWallet}, nil
}

// DeleteWallet removes a wallet from GCP Secret Manager.
// It deletes the corresponding secret and all its versions.
func (s *GCPStore) DeleteWallet(ctx context.Context, name string) error {
	// Create a minimal wallet instance for deletion - no need to load data
	gcpWallet := gcp.NewGoogleWallet(name)
	return gcpWallet.Delete(ctx)
}

// gcpWalletAdapter adapts gcp.GoogleWallet to the storage.Wallet interface.
// It provides a bridge between the legacy GCP implementation and the new storage interface.
type gcpWalletAdapter struct {
	wallet *gcp.GoogleWallet
}

// Name returns the wallet name
func (a *gcpWalletAdapter) Name() string {
	return a.wallet.Name()
}

// Description returns the wallet description
func (a *gcpWalletAdapter) Description() string {
	return a.wallet.Description()
}

// SetDescription sets the wallet description
func (a *gcpWalletAdapter) SetDescription(description string) {
	a.wallet.SetDescription(description)
}

// Items returns all wallet items
func (a *gcpWalletAdapter) Items() map[string]string {
	return a.wallet.Items()
}

// ListItems returns a list of all item names
func (a *gcpWalletAdapter) ListItems() []string {
	return a.wallet.ListItems()
}

// GetItem retrieves a specific item
func (a *gcpWalletAdapter) GetItem(name string) (string, error) {
	return a.wallet.GetItem(name)
}

// PutItem stores an item
func (a *gcpWalletAdapter) PutItem(name, value string) {
	a.wallet.PutItem(name, value)
}

// DeleteItem removes an item
func (a *gcpWalletAdapter) DeleteItem(name string) {
	a.wallet.DeleteItem(name)
}

// PopulateFrom populates the wallet from a bursa.Wallet
func (a *gcpWalletAdapter) PopulateFrom(wallet *bursa.Wallet) error {
	return a.wallet.PopulateFrom(wallet)
}

// PopulateTo populates a bursa.Wallet from the stored wallet
func (a *gcpWalletAdapter) PopulateTo(wallet *bursa.Wallet) error {
	return a.wallet.PopulateTo(wallet)
}

// Load loads the wallet from storage
func (a *gcpWalletAdapter) Load(ctx context.Context) error {
	return a.wallet.Load(ctx)
}

// Save saves the wallet to storage
func (a *gcpWalletAdapter) Save(ctx context.Context) error {
	return a.wallet.Save(ctx)
}

// Delete deletes the wallet from storage
func (a *gcpWalletAdapter) Delete(ctx context.Context) error {
	return a.wallet.Delete(ctx)
}
