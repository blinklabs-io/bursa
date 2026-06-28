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
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/blinklabs-io/bursa/ui/internal/keystore"
	"github.com/blinklabs-io/bursa/ui/internal/spend"
	"github.com/blinklabs-io/bursa/ui/internal/supervisor"
	"github.com/blinklabs-io/bursa/ui/internal/vault"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
)

// Statuser is the minimal view the API needs of the supervisor.
type Statuser interface {
	Status() supervisor.Status
}

// Wallet is the read-only wallet surface the API exposes: it serves views for
// the active wallet. SetAccount binds the active wallet's read-only account
// (pushed by the vault on unlock/activate/add).
type Wallet interface {
	// SetAccount(nil) clears the active account binding.
	SetAccount(acct *wallet.Account) error
	Balance(ctx context.Context) (wallet.Balance, error)
	Addresses(ctx context.Context) (wallet.AddressView, error)
	Transactions(ctx context.Context) ([]wallet.Tx, error)
	Delegation(ctx context.Context) (wallet.DelegationView, error)
}

// Spender is the spending surface the API exposes for the active wallet:
// building a send for preview, confirming it (decrypt seed → sign → submit), and
// CIP-8/CIP-30 message signing. SetAccount binds the active wallet (pushed by
// the vault); the seed is decrypted via the vault under the wallet's spending
// password at confirm/sign time.
type Spender interface {
	// SetAccount("", nil) clears the active wallet binding and pending sends.
	SetAccount(id string, acct *wallet.Account)
	Build(ctx context.Context, req spend.SendRequest) (spend.Preview, error)
	Confirm(ctx context.Context, pendingID, password string) (spend.TxResult, error)
	SignData(addr string, message []byte, password string) (signatureHex, keyHex string, err error)
}

// Vault is the encrypted multi-wallet store the API drives. It owns the wallet
// list and the active-wallet selection; the API pushes the active wallet's
// account onto the Wallet/Spender services whenever it changes.
type Vault interface {
	Exists() bool
	Locked() bool
	WalletCount() int
	Create(vaultPassword string) error
	Unlock(vaultPassword string) ([]vault.WalletMeta, error)
	Lock()
	Wallets() ([]vault.WalletMeta, error)
	AddWallet(name, mnemonic, network, vaultPassword, spendPassword string, windowN int) (vault.WalletMeta, error)
	ImportWallet(name, mnemonic, network, vaultPassword, spendPassword string, windowN int) (vault.WalletMeta, error)
	ImportWalletMnemonicBytes(name string, mnemonic []byte, network, vaultPassword, spendPassword string, windowN int) (vault.WalletMeta, error)
	RemoveWallet(id, vaultPassword string) error
	SetActive(id string) (vault.WalletMeta, error)
	Active() (vault.WalletMeta, error)
}

// LegacyKeystore is the old single-wallet encrypted mnemonic store. It is
// accepted only for explicit migration into the vault when vault.json is absent.
type LegacyKeystore interface {
	Exists() bool
	Unlock(password string) ([]byte, error)
}

// SettingsController is the user-facing app-settings surface. It exposes the
// persisted lean-node (history-expiry) profile and whether a node restart is
// still needed for the persisted value to take effect (history expiry is a
// node-construction option, applied only at node start). It is decoupled from
// the storage and supervisor packages so the API can be tested with a fake.
type SettingsController interface {
	HistoryExpiry() bool
	SetHistoryExpiry(enabled bool) error
	// HistoryExpiryRestartRequired reports whether the running node was built
	// with a different history-expiry value than what is now persisted (so the
	// change has not taken effect yet).
	HistoryExpiryRestartRequired() bool
}

type handlerOptions struct {
	legacy LegacyKeystore
}

type HandlerOption func(*handlerOptions)

func WithLegacyKeystore(ks LegacyKeystore) HandlerOption {
	return func(o *handlerOptions) {
		o.legacy = ks
	}
}

const defaultWindow = 20

// vaultStatus is the GET /vault/status response.
type vaultStatus struct {
	Exists         bool `json:"exists"`
	Locked         bool `json:"locked"`
	WalletCount    int  `json:"wallet_count"`
	LegacyKeystore bool `json:"legacy_keystore"`
}

// walletView is the API representation of a vault wallet: the read-only fields a
// client needs to list and bind wallets. The encrypted seed is never exposed.
type walletView struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Network      string   `json:"network"`
	StakeAddress string   `json:"stake_address"`
	Addresses    []string `json:"addresses"`
	Active       bool     `json:"active"`
}

func toWalletView(w vault.WalletMeta, activeID string) walletView {
	v := walletView{
		ID:      w.ID,
		Name:    w.Name,
		Network: w.Network,
		Active:  w.ID == activeID,
	}
	if w.Account != nil {
		v.StakeAddress = w.Account.StakeAddress
		v.Addresses = w.Account.ReceiveAddresses
	}
	return v
}

// NewHandler returns the loopback control-surface mux. network is the network
// the embedded node runs on; wallet requests must match it (or omit it). vlt is
// the encrypted multi-wallet store; the API pushes the active wallet onto wl/sp
// whenever the selection changes. settings exposes user-facing app settings (the
// lean-node profile). spa is the embedded SPA, registered as the catch-all so
// the specific API routes take precedence on the mux.
func NewHandler(st Statuser, vlt Vault, wl Wallet, sp Spender, settings SettingsController, network string, spa http.Handler, opts ...HandlerOption) http.Handler {
	cfg := handlerOptions{}
	for _, opt := range opts {
		opt(&cfg)
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, st.Status())
	})

	// bindActive pushes the active wallet's read-only account onto the read and
	// spend services so existing endpoints operate on it. Called after unlock,
	// activate, and add.
	bindActive := func(w vault.WalletMeta) {
		if w.Account == nil {
			return
		}
		_ = wl.SetAccount(w.Account)
		sp.SetAccount(w.ID, w.Account)
	}
	clearActive := func() {
		_ = wl.SetAccount(nil)
		sp.SetAccount("", nil)
	}
	legacyAvailable := func() bool {
		return !vlt.Exists() && cfg.legacy != nil && cfg.legacy.Exists()
	}

	// --- Vault lifecycle -----------------------------------------------------

	mux.HandleFunc("GET /vault/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, vaultStatus{
			Exists:         vlt.Exists(),
			Locked:         vlt.Locked(),
			WalletCount:    vlt.WalletCount(),
			LegacyKeystore: legacyAvailable(),
		})
	})

	mux.HandleFunc("POST /vault", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		if !requirePassword(w, req.Password) {
			return
		}
		if err := vlt.Create(req.Password); err != nil {
			serve(w, struct{}{}, err)
			return
		}
		clearActive()
		writeJSON(w, http.StatusOK, vaultStatus{Exists: true, Locked: false, WalletCount: 0})
	})

	mux.HandleFunc("POST /vault/unlock", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		wallets, err := vlt.Unlock(req.Password)
		if err != nil {
			serve(w, struct{}{}, err)
			return
		}
		// Unlock auto-activates a sole wallet; bind it so reads work immediately.
		if active, err := vlt.Active(); err == nil {
			bindActive(active)
		}
		writeJSON(w, http.StatusOK, walletList(wallets, vlt))
	})

	mux.HandleFunc("POST /vault/lock", func(w http.ResponseWriter, _ *http.Request) {
		vlt.Lock()
		clearActive()
		writeJSON(w, http.StatusOK, vaultStatus{
			Exists: vlt.Exists(), Locked: true, WalletCount: vlt.WalletCount(),
		})
	})

	mux.HandleFunc("POST /vault/migrate-legacy", func(w http.ResponseWriter, r *http.Request) {
		if vlt.Exists() {
			serve(w, struct{}{}, vault.ErrVaultExists)
			return
		}
		if cfg.legacy == nil || !cfg.legacy.Exists() {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "legacy keystore not found"})
			return
		}
		var req struct {
			Name          string `json:"name"`
			VaultPassword string `json:"vault_password"`
			SpendPassword string `json:"spend_password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		if !requirePassword(w, req.VaultPassword) {
			return
		}
		if req.SpendPassword == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "spend_password is required"})
			return
		}
		if !requirePassword(w, req.SpendPassword) {
			return
		}
		name := strings.TrimSpace(req.Name)
		if name == "" {
			name = "Wallet"
		}
		mnemonic, err := cfg.legacy.Unlock(req.SpendPassword)
		if err != nil {
			if errors.Is(err, keystore.ErrDecryptFailed) {
				serve(w, struct{}{}, fmt.Errorf("%w: %w", vault.ErrWrongPassword, err))
				return
			}
			serve(w, struct{}{}, err)
			return
		}
		defer keystore.Zero(mnemonic)
		meta, err := vlt.ImportWalletMnemonicBytes(name, mnemonic, network, req.VaultPassword, req.SpendPassword, defaultWindow)
		if err != nil {
			serve(w, struct{}{}, err)
			return
		}
		bindActive(meta)
		writeJSON(w, http.StatusOK, toWalletView(meta, meta.ID))
	})

	// --- Wallet management ---------------------------------------------------

	// POST /wallet adds a wallet to the vault: derive + encrypt seed under the
	// spending password, store read-only metadata under the vault password. The
	// new wallet becomes active. No synced node needed (derivation is offline).
	mux.HandleFunc("POST /wallet", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name          string `json:"name"`
			Mnemonic      string `json:"mnemonic"`
			Network       string `json:"network"`
			VaultPassword string `json:"vault_password"`
			SpendPassword string `json:"spend_password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		net, ok := resolveNetwork(w, req.Network, network)
		if !ok {
			return
		}
		// The spending password is required and floored at MinPasswordLen; the
		// vault password must be supplied to re-seal the index.
		if !requirePassword(w, req.SpendPassword) {
			return
		}
		if req.VaultPassword == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "vault_password is required"})
			return
		}
		meta, err := vlt.AddWallet(req.Name, req.Mnemonic, net, req.VaultPassword, req.SpendPassword, defaultWindow)
		if err != nil {
			serve(w, struct{}{}, err)
			return
		}
		bindActive(meta)
		writeJSON(w, http.StatusOK, toWalletView(meta, meta.ID))
	})

	mux.HandleFunc("POST /wallet/{id}/activate", func(w http.ResponseWriter, r *http.Request) {
		meta, err := vlt.SetActive(r.PathValue("id"))
		if err != nil {
			serve(w, struct{}{}, err)
			return
		}
		bindActive(meta)
		writeJSON(w, http.StatusOK, toWalletView(meta, meta.ID))
	})

	mux.HandleFunc("DELETE /wallet/{id}", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			VaultPassword string `json:"vault_password"`
		}
		// A DELETE may carry a body for the vault password; tolerate an empty body.
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&req)
		}
		if req.VaultPassword == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "vault_password is required"})
			return
		}
		if err := vlt.RemoveWallet(r.PathValue("id"), req.VaultPassword); err != nil {
			serve(w, struct{}{}, err)
			return
		}
		if active, err := vlt.Active(); err == nil {
			bindActive(active)
		} else {
			clearActive()
		}
		writeJSON(w, http.StatusOK, map[string]bool{"removed": true})
	})

	// --- Read-only views (active wallet) -------------------------------------

	mux.HandleFunc("GET /wallet/balance", gated(st, func(w http.ResponseWriter, r *http.Request) {
		v, err := wl.Balance(r.Context())
		serve(w, v, err)
	}))
	mux.HandleFunc("GET /wallet/addresses", gated(st, func(w http.ResponseWriter, r *http.Request) {
		v, err := wl.Addresses(r.Context())
		serve(w, v, err)
	}))
	mux.HandleFunc("GET /wallet/transactions", gated(st, func(w http.ResponseWriter, r *http.Request) {
		v, err := wl.Transactions(r.Context())
		serve(w, v, err)
	}))
	mux.HandleFunc("GET /wallet/delegation", gated(st, func(w http.ResponseWriter, r *http.Request) {
		v, err := wl.Delegation(r.Context())
		serve(w, v, err)
	}))

	// --- Spending (active wallet, spending password) -------------------------

	mux.HandleFunc("POST /wallet/send", readyGate(st, func(w http.ResponseWriter, r *http.Request) {
		var req spend.SendRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		pv, err := sp.Build(r.Context(), req)
		serve(w, pv, err)
	}))

	mux.HandleFunc("POST /wallet/send/{id}/confirm", readyGate(st, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		res, err := sp.Confirm(r.Context(), r.PathValue("id"), req.Password)
		serve(w, res, err)
	}))

	// CIP-8 / CIP-30 message signing. Ungated: signing is fully offline (no node
	// needed) — it requires only the active wallet's spending password to decrypt
	// its seed.
	mux.HandleFunc("POST /wallet/sign-data", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Address  string `json:"address"`
			Message  string `json:"message"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		sig, key, err := sp.SignData(req.Address, []byte(req.Message), req.Password)
		serve(w, map[string]string{"signature": sig, "key": key}, err)
	})

	// App settings: the lean-node (history-expiry) profile. Ungated — it is a
	// config setting, not a node query, so it is readable/settable regardless of
	// sync state. History expiry is a node-construction option, so a change only
	// takes effect on the next node restart; restart_required surfaces that.
	mux.HandleFunc("GET /wallet/settings/history-expiry", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{
			"enabled":          settings.HistoryExpiry(),
			"restart_required": settings.HistoryExpiryRestartRequired(),
		})
	})
	mux.HandleFunc("PUT /wallet/settings/history-expiry", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		if err := settings.SetHistoryExpiry(req.Enabled); err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody(err))
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{
			"enabled":          settings.HistoryExpiry(),
			"restart_required": settings.HistoryExpiryRestartRequired(),
		})
	})

	// SPA catch-all: the specific API routes above take precedence on the mux;
	// everything else is served by the embedded frontend.
	mux.Handle("/", spa)

	return mux
}

// walletList maps vault metadata to the client-facing wallet views, marking the
// active wallet.
func walletList(wallets []vault.WalletMeta, vlt Vault) []walletView {
	activeID := ""
	if active, err := vlt.Active(); err == nil {
		activeID = active.ID
	}
	out := make([]walletView, 0, len(wallets))
	for _, w := range wallets {
		out = append(out, toWalletView(w, activeID))
	}
	return out
}

// requirePassword enforces the shared MinPasswordLen floor (counting runes, to
// match the server-side scrypt input). It writes a 400 and returns false when
// the password is too short.
func requirePassword(w http.ResponseWriter, password string) bool {
	if utf8.RuneCountInString(password) < keystore.MinPasswordLen {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("password must be at least %d characters", keystore.MinPasswordLen),
		})
		return false
	}
	return true
}

// resolveNetwork returns the effective network for a wallet request, defaulting
// to the node's network and rejecting a mismatch (a wallet derived for a
// different network than the node always reads as empty). ok is false when it
// has already written an error response.
func resolveNetwork(w http.ResponseWriter, reqNet, nodeNet string) (string, bool) {
	if reqNet == "" {
		return nodeNet, true
	}
	if reqNet != nodeNet {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("network mismatch: node is running %s, request says %s", nodeNet, reqNet),
		})
		return "", false
	}
	return reqNet, true
}

// gated blocks wallet reads until the node can serve queries (ready or syncing).
func gated(st Statuser, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := st.Status().State
		if state != supervisor.StateReady && state != supervisor.StateSyncing {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"error": "node not ready", "state": state,
			})
			return
		}
		next(w, r)
	}
}

// readyGate blocks spending until the node is fully synced (StateReady). It is
// stricter than gated (reads): a spend built against a partial UTxO view could
// select already-spent inputs.
func readyGate(st Statuser, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if state := st.Status().State; state != supervisor.StateReady {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"error": "node not fully synced", "state": state,
			})
			return
		}
		next(w, r)
	}
}

// serve writes a query result, or maps a known error to its HTTP status code
// (falling back to 500). The spend and vault sentinels carry the precise
// client-facing code so the caller can distinguish e.g. wrong-password from
// insufficient-funds or a locked vault.
func serve[T any](w http.ResponseWriter, v T, err error) {
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, v)
	case errors.Is(err, vault.ErrNoVault):
		writeJSON(w, http.StatusNotFound, errBody(err)) // 404: no vault yet
	case errors.Is(err, vault.ErrVaultExists):
		writeJSON(w, http.StatusConflict, errBody(err)) // 409: vault already exists
	case errors.Is(err, vault.ErrUnknownWallet):
		writeJSON(w, http.StatusNotFound, errBody(err)) // 404
	case errors.Is(err, vault.ErrDuplicateWallet):
		writeJSON(w, http.StatusConflict, errBody(err)) // 409
	case errors.Is(err, vault.ErrLocked), errors.Is(err, vault.ErrNoActiveWallet),
		errors.Is(err, wallet.ErrNoWallet), errors.Is(err, spend.ErrNoWallet):
		writeJSON(w, http.StatusConflict, errBody(err)) // 409: locked / no active wallet
	case errors.Is(err, spend.ErrWalletChanged):
		writeJSON(w, http.StatusConflict, errBody(err)) // 409: active wallet switched during build
	case errors.Is(err, vault.ErrWrongPassword), errors.Is(err, spend.ErrWrongPassword):
		writeJSON(w, http.StatusUnauthorized, errBody(err)) // 401
	case errors.Is(err, spend.ErrInvalidRequest):
		writeJSON(w, http.StatusBadRequest, errBody(err)) // 400
	case errors.Is(err, spend.ErrUnknownPending):
		writeJSON(w, http.StatusNotFound, errBody(err)) // 404
	case errors.Is(err, spend.ErrExpiredPending):
		writeJSON(w, http.StatusGone, errBody(err)) // 410
	case errors.Is(err, spend.ErrInsufficientFunds), errors.Is(err, spend.ErrSubmitRejected):
		// 422: the request was understood but cannot be fulfilled; the node's
		// structured rejection reason (for submit) rides along in the message.
		writeJSON(w, http.StatusUnprocessableEntity, errBody(err))
	default:
		writeJSON(w, http.StatusInternalServerError, errBody(err))
	}
}

func errBody(err error) map[string]string {
	return map[string]string{"error": err.Error()}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "internal error encoding response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(b)
}
