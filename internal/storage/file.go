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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/logging"
)

// FileStore implements the Store interface using local file system.
// It stores wallets as JSON files in a directory structure on disk.
type FileStore struct {
	baseDir string
	mu      sync.RWMutex
}

// NewFileStore creates a new file-based storage backend.
// baseDir specifies the root directory where wallets will be stored.
func NewFileStore(baseDir string) *FileStore {
	return &FileStore{
		baseDir: baseDir,
	}
}

// validateWalletName validates that a wallet name is safe for file system operations.
// It prevents path traversal attacks by ensuring the name contains only safe characters
// and no path separators or traversal sequences.
func validateWalletName(name string) error {
	if name == "" {
		return errors.New("wallet name cannot be empty")
	}
	if len(name) > 255 {
		return errors.New("wallet name too long")
	}

	// Check for path traversal sequences
	if strings.Contains(name, "..") {
		return errors.New("wallet name cannot contain path traversal sequences")
	}

	// Check for path separators
	if strings.ContainsAny(name, "/\\") {
		return errors.New("wallet name cannot contain path separators")
	}

	// Allow only safe characters: alphanumeric, hyphens, underscores
	for _, r := range name {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			// Letters are allowed
		case r >= '0' && r <= '9':
			// Numbers are allowed
		case r == '-' || r == '_':
			// Hyphens and underscores are allowed
		default:
			return errors.New(
				"wallet name can only contain alphanumeric characters, hyphens, and underscores",
			)
		}
	}

	return nil
}

// GetWallet retrieves a wallet from the file system.
// The wallet is loaded from a JSON file in the base directory.
func (s *FileStore) GetWallet(
	ctx context.Context,
	name string,
) (Wallet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := validateWalletName(name); err != nil {
		return nil, fmt.Errorf("invalid wallet name: %w", err)
	}

	walletPath := s.walletPath(name)
	if _, err := os.Stat(walletPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("wallet %s not found", name)
	}

	file, err := os.Open(walletPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open wallet file: %w", err)
	}
	defer file.Close()

	var data fileWalletData
	if err := json.NewDecoder(file).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode wallet data: %w", err)
	}

	return &fileWallet{
		name:        name,
		description: data.Description,
		items:       data.Items,
		store:       s,
	}, nil
}

// ListWallets lists all wallets in the file system.
// It scans the base directory for wallet subdirectories.
func (s *FileStore) ListWallets(ctx context.Context) ([]Wallet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []Wallet{}, nil
		}
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var wallets []Wallet
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "wallet-") {
			name := strings.TrimPrefix(entry.Name(), "wallet-")
			wallet, err := s.GetWallet(ctx, name)
			if err != nil {
				logging.GetLogger().
					Debug("skipping corrupted wallet during list", "wallet", name, "error", err)
				continue // Skip corrupted wallets
			}
			wallets = append(wallets, wallet)
		}
	}

	return wallets, nil
}

// CreateWallet creates a new wallet instance for file storage.
// The wallet is not persisted until Save() is called.
func (s *FileStore) CreateWallet(name string) Wallet {
	if err := validateWalletName(name); err != nil {
		// This is a programming error - panic to catch it early
		panic(fmt.Sprintf("invalid wallet name in CreateWallet: %v", err))
	}

	return &fileWallet{
		name:  name,
		items: make(map[string]string),
		store: s,
	}
}

// DeleteWallet removes a wallet from the file system.
// It deletes the wallet directory and all its contents.
func (s *FileStore) DeleteWallet(ctx context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := validateWalletName(name); err != nil {
		return fmt.Errorf("invalid wallet name: %w", err)
	}

	walletDir := s.walletDir(name)
	return os.RemoveAll(walletDir)
}

// fileWallet implements the Wallet interface for file-based storage
type fileWallet struct {
	name        string
	description string
	items       map[string]string
	store       *FileStore
	mu          sync.RWMutex
}

// fileWalletData represents the JSON structure for file storage
type fileWalletData struct {
	Description string            `json:"description"`
	Items       map[string]string `json:"items"`
}

func (w *fileWallet) Name() string {
	return w.name
}

func (w *fileWallet) Description() string {
	return w.description
}

func (w *fileWallet) SetDescription(description string) {
	w.description = description
}

func (w *fileWallet) Items() map[string]string {
	w.mu.RLock()
	defer w.mu.RUnlock()

	// Return a copy to prevent external modification
	result := make(map[string]string)
	for k, v := range w.items {
		result[k] = v
	}
	return result
}

func (w *fileWallet) ListItems() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()

	items := make([]string, 0, len(w.items))
	for name := range w.items {
		items = append(items, name)
	}
	return items
}

func (w *fileWallet) GetItem(name string) (string, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	value, exists := w.items[name]
	if !exists {
		return "", fmt.Errorf("item %s not found", name)
	}
	return value, nil
}

func (w *fileWallet) PutItem(name, value string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.items == nil {
		w.items = make(map[string]string)
	}
	w.items[name] = value
}

func (w *fileWallet) DeleteItem(name string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	delete(w.items, name)
}

func (w *fileWallet) PopulateFrom(wallet *bursa.Wallet) error {
	w.SetDescription("Wallet created from bursa.Wallet")

	// Add mnemonic if available
	if wallet.Mnemonic != "" {
		w.PutItem("mnemonic", wallet.Mnemonic)
	}

	// Add addresses
	w.PutItem("payment_address", wallet.PaymentAddress)
	w.PutItem("stake_address", wallet.StakeAddress)

	// Add key files
	keyFiles, err := bursa.ExtractKeyFiles(wallet)
	if err != nil {
		return fmt.Errorf("failed to extract key files: %w", err)
	}

	for name, content := range keyFiles {
		w.PutItem(name, content)
	}

	return nil
}

func (w *fileWallet) PopulateTo(wallet *bursa.Wallet) error {
	if wallet == nil {
		return errors.New("nil bursa wallet")
	}

	w.mu.RLock()
	defer w.mu.RUnlock()

	// Populate mnemonic if stored
	if mnemonic, exists := w.items["mnemonic"]; exists {
		wallet.Mnemonic = mnemonic
	}

	// Populate addresses if stored
	if paymentAddr, exists := w.items["payment_address"]; exists {
		wallet.PaymentAddress = paymentAddr
	}
	if stakeAddr, exists := w.items["stake_address"]; exists {
		wallet.StakeAddress = stakeAddr
	}

	// Note: Key files could be populated here if needed, but for basic functionality
	// the mnemonic and addresses should be sufficient for most use cases

	return nil
}

func (w *fileWallet) Load(ctx context.Context) error {
	// File wallet is always "loaded" since data is in memory
	return nil
}

func (w *fileWallet) Save(ctx context.Context) error {
	w.store.mu.Lock()
	defer w.store.mu.Unlock()

	// Validate wallet name for defense in depth
	if err := validateWalletName(w.name); err != nil {
		return fmt.Errorf("invalid wallet name: %w", err)
	}

	// Ensure directory exists with secure permissions (0700)
	walletDir := w.store.walletDir(w.name)
	if err := os.MkdirAll(walletDir, 0o700); err != nil {
		return fmt.Errorf("failed to create wallet directory: %w", err)
	}

	// Write wallet data
	w.mu.RLock()
	data := fileWalletData{
		Description: w.description,
		Items:       w.items,
	}
	w.mu.RUnlock()

	// Write wallet data with secure file permissions (0600)
	// TODO: Encrypt wallet data at rest using SOPS or similar encryption
	// SECURITY: Currently storing sensitive data (mnemonics, private keys) in plain JSON
	file, err := os.OpenFile(
		w.store.walletPath(w.name),
		os.O_RDWR|os.O_CREATE|os.O_TRUNC,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("failed to create wallet file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode wallet data: %w", err)
	}

	return nil
}

func (w *fileWallet) Delete(ctx context.Context) error {
	return w.store.DeleteWallet(ctx, w.name)
}

// walletDir returns the directory path for a wallet
func (s *FileStore) walletDir(name string) string {
	if err := validateWalletName(name); err != nil {
		// This should never happen if validation is done at public API boundaries
		panic(fmt.Sprintf("invalid wallet name in walletDir: %v", err))
	}
	return filepath.Join(s.baseDir, "wallet-"+name)
}

// walletPath returns the file path for a wallet
func (s *FileStore) walletPath(name string) string {
	if err := validateWalletName(name); err != nil {
		// This should never happen if validation is done at public API boundaries
		panic(fmt.Sprintf("invalid wallet name in walletPath: %v", err))
	}
	return filepath.Join(s.walletDir(name), "wallet.json")
}
