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
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/blinklabs-io/bursa"
	_ "modernc.org/sqlite"
)

// SQLiteStore implements the Store interface using SQLite.
// It stores wallets in a local SQLite database file.
type SQLiteStore struct {
	db *sql.DB
	mu sync.RWMutex
}

// NewSQLiteStore creates a new SQLite-based storage backend.
// The dsn specifies the database file path or connection string.
// The schema is automatically created on first use.
func NewSQLiteStore(dsn string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to open sqlite database: %w",
			err,
		)
	}

	// Enable WAL mode for better concurrent read performance
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf(
			"failed to set WAL mode: %w",
			err,
		)
	}

	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf(
			"failed to enable foreign keys: %w",
			err,
		)
	}

	// SQLite only supports one writer at a time. Limiting to a single
	// connection ensures all PRAGMAs (like foreign_keys=ON) remain in
	// effect, since they are per-connection settings.
	db.SetMaxOpenConns(1)

	store := &SQLiteStore{db: db}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf(
			"failed to migrate database: %w",
			err,
		)
	}

	return store, nil
}

// migrate creates the database schema if it does not exist.
func (s *SQLiteStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS wallets (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			name        TEXT    NOT NULL UNIQUE,
			description TEXT    NOT NULL DEFAULT '',
			created_at  TEXT    NOT NULL,
			updated_at  TEXT    NOT NULL
		);
		CREATE TABLE IF NOT EXISTS wallet_items (
			id        INTEGER PRIMARY KEY AUTOINCREMENT,
			wallet_id INTEGER NOT NULL,
			key       TEXT    NOT NULL,
			value     TEXT    NOT NULL,
			FOREIGN KEY (wallet_id) REFERENCES wallets(id)
				ON DELETE CASCADE,
			UNIQUE(wallet_id, key)
		);
		CREATE INDEX IF NOT EXISTS idx_wallet_items_wallet_id
			ON wallet_items(wallet_id);
	`)
	if err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}
	return nil
}

// Close closes the underlying database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// GetWallet retrieves a wallet from the SQLite database.
func (s *SQLiteStore) GetWallet(
	ctx context.Context,
	name string,
) (Wallet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := validateWalletName(name); err != nil {
		return nil, fmt.Errorf("invalid wallet name: %w", err)
	}

	var walletID int64
	var description string
	err := s.db.QueryRowContext(
		ctx,
		"SELECT id, description FROM wallets WHERE name = ?",
		name,
	).Scan(&walletID, &description)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf(
				"wallet %s not found", name,
			)
		}
		return nil, fmt.Errorf(
			"failed to query wallet: %w", err,
		)
	}

	items, err := s.loadItems(ctx, walletID)
	if err != nil {
		return nil, err
	}

	return &sqliteWallet{
		id:          walletID,
		name:        name,
		description: description,
		items:       items,
		store:       s,
	}, nil
}

// ListWallets returns all wallets in the SQLite database.
func (s *SQLiteStore) ListWallets(
	ctx context.Context,
) ([]Wallet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(
		ctx,
		"SELECT id, name, description FROM wallets ORDER BY name",
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to list wallets: %w", err,
		)
	}
	defer rows.Close()

	type walletMeta struct {
		id          int64
		name        string
		description string
	}
	var metas []walletMeta
	for rows.Next() {
		var m walletMeta
		if err := rows.Scan(
			&m.id, &m.name, &m.description,
		); err != nil {
			return nil, fmt.Errorf(
				"failed to scan wallet row: %w", err,
			)
		}
		metas = append(metas, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"error iterating wallets: %w", err,
		)
	}
	rows.Close()

	wallets := make([]Wallet, 0, len(metas))
	for _, m := range metas {
		items, err := s.loadItems(ctx, m.id)
		if err != nil {
			return nil, err
		}

		wallets = append(wallets, &sqliteWallet{
			id:          m.id,
			name:        m.name,
			description: m.description,
			items:       items,
			store:       s,
		})
	}
	return wallets, nil
}

// CreateWallet creates a new wallet instance for SQLite storage.
// The wallet is not persisted until Save() is called.
func (s *SQLiteStore) CreateWallet(
	name string,
) (Wallet, error) {
	if err := validateWalletName(name); err != nil {
		return nil, fmt.Errorf(
			"invalid wallet name: %w", err,
		)
	}

	return &sqliteWallet{
		name:  name,
		items: make(map[string]string),
		store: s,
	}, nil
}

// DeleteWallet removes a wallet from the SQLite database.
func (s *SQLiteStore) DeleteWallet(
	ctx context.Context,
	name string,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := validateWalletName(name); err != nil {
		return fmt.Errorf("invalid wallet name: %w", err)
	}

	result, err := s.db.ExecContext(
		ctx,
		"DELETE FROM wallets WHERE name = ?",
		name,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to delete wallet: %w", err,
		)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf(
			"failed to check rows affected: %w", err,
		)
	}
	if rows == 0 {
		return fmt.Errorf("wallet %s not found", name)
	}

	return nil
}

// loadItems loads all key-value items for a wallet by its ID.
func (s *SQLiteStore) loadItems(
	ctx context.Context,
	walletID int64,
) (map[string]string, error) {
	rows, err := s.db.QueryContext(
		ctx,
		"SELECT key, value FROM wallet_items WHERE wallet_id = ?",
		walletID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to load wallet items: %w", err,
		)
	}
	defer rows.Close()

	items := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, fmt.Errorf(
				"failed to scan item row: %w", err,
			)
		}
		items[key] = value
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"error iterating items: %w", err,
		)
	}

	return items, nil
}

// sqliteWallet implements the Wallet interface for SQLite storage.
type sqliteWallet struct {
	id          int64
	items       map[string]string
	store       *SQLiteStore
	name        string
	description string
	mu          sync.RWMutex
}

func (w *sqliteWallet) Name() string {
	return w.name
}

func (w *sqliteWallet) Description() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.description
}

func (w *sqliteWallet) SetDescription(description string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.description = description
}

func (w *sqliteWallet) Items() map[string]string {
	w.mu.RLock()
	defer w.mu.RUnlock()

	result := make(map[string]string)
	maps.Copy(result, w.items)
	return result
}

func (w *sqliteWallet) ListItems() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()

	items := make([]string, 0, len(w.items))
	for name := range w.items {
		items = append(items, name)
	}
	return items
}

func (w *sqliteWallet) GetItem(
	name string,
) (string, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	value, exists := w.items[name]
	if !exists {
		return "", fmt.Errorf("item %s not found", name)
	}
	return value, nil
}

func (w *sqliteWallet) PutItem(name, value string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.items == nil {
		w.items = make(map[string]string)
	}
	w.items[name] = value
}

func (w *sqliteWallet) DeleteItem(name string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	delete(w.items, name)
}

func (w *sqliteWallet) PopulateFrom(
	wallet *bursa.Wallet,
) error {
	w.SetDescription("Wallet created from bursa.Wallet")

	if wallet.Mnemonic != "" {
		w.PutItem("mnemonic", wallet.Mnemonic)
	}

	w.PutItem("payment_address", wallet.PaymentAddress)
	w.PutItem("stake_address", wallet.StakeAddress)

	keyFiles, err := bursa.ExtractKeyFiles(wallet)
	if err != nil {
		return fmt.Errorf(
			"failed to extract key files: %w", err,
		)
	}

	for name, content := range keyFiles {
		w.PutItem(name, content)
	}

	return nil
}

func (w *sqliteWallet) PopulateTo(
	wallet *bursa.Wallet,
) error {
	if wallet == nil {
		return errors.New("nil bursa wallet")
	}

	w.mu.RLock()
	defer w.mu.RUnlock()

	if mnemonic, exists := w.items["mnemonic"]; exists {
		wallet.Mnemonic = mnemonic
	}

	if paymentAddr, exists := w.items["payment_address"]; exists {
		wallet.PaymentAddress = paymentAddr
	}
	if stakeAddr, exists := w.items["stake_address"]; exists {
		wallet.StakeAddress = stakeAddr
	}

	return nil
}

func (w *sqliteWallet) Load(ctx context.Context) error {
	// Data is already loaded in memory from GetWallet
	return nil
}

func (w *sqliteWallet) Save(ctx context.Context) error {
	w.store.mu.Lock()
	defer w.store.mu.Unlock()

	w.mu.RLock()
	defer w.mu.RUnlock()

	if err := validateWalletName(w.name); err != nil {
		return fmt.Errorf("invalid wallet name: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)

	tx, err := w.store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf(
			"failed to begin transaction: %w", err,
		)
	}
	defer tx.Rollback() //nolint:errcheck

	if w.id == 0 {
		// Insert new wallet
		result, err := tx.ExecContext(
			ctx,
			`INSERT INTO wallets (name, description, created_at, updated_at)
			 VALUES (?, ?, ?, ?)`,
			w.name, w.description, now, now,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to insert wallet: %w", err,
			)
		}
		w.id, err = result.LastInsertId()
		if err != nil {
			return fmt.Errorf(
				"failed to get wallet id: %w", err,
			)
		}
	} else {
		// Update existing wallet
		_, err := tx.ExecContext(
			ctx,
			`UPDATE wallets
			 SET description = ?, updated_at = ?
			 WHERE id = ?`,
			w.description, now, w.id,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to update wallet: %w", err,
			)
		}
	}

	// Delete existing items and re-insert
	_, err = tx.ExecContext(
		ctx,
		"DELETE FROM wallet_items WHERE wallet_id = ?",
		w.id,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to clear wallet items: %w", err,
		)
	}

	for key, value := range w.items {
		_, err := tx.ExecContext(
			ctx,
			`INSERT INTO wallet_items (wallet_id, key, value)
			 VALUES (?, ?, ?)`,
			w.id, key, value,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to insert wallet item: %w", err,
			)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf(
			"failed to commit transaction: %w", err,
		)
	}

	return nil
}

func (w *sqliteWallet) Delete(ctx context.Context) error {
	return w.store.DeleteWallet(ctx, w.name)
}
