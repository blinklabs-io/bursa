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
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/blinklabs-io/bursa/ui/internal/chain"
	"github.com/blinklabs-io/bursa/ui/internal/handle"
	"github.com/blinklabs-io/bursa/ui/internal/keystore"
	"github.com/blinklabs-io/bursa/ui/internal/poolops"
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
	// TransactionDetail returns the drill-down view (inputs/outputs, every
	// asset delta) of one transaction in the history; chain.ErrNotFound when
	// the node has no record of hash.
	TransactionDetail(ctx context.Context, hash string) (wallet.TxDetail, error)
	Delegation(ctx context.Context) (wallet.DelegationView, error)
}

// Spender is the spending surface the API exposes for the active wallet:
// building a send for preview, confirming it (decrypt seed → sign → submit),
// CIP-8/CIP-30 message signing, and building staking/governance delegation
// transactions (which Confirm signs + submits through the same path as a send).
// SetAccount binds the active wallet (pushed by the vault); the seed is
// decrypted via the vault under the wallet's spending password at confirm/sign
// time.
type Spender interface {
	// SetAccount("", nil) clears the active wallet binding and pending sends.
	SetAccount(id string, acct *wallet.Account)
	Build(ctx context.Context, req spend.SendRequest) (spend.Preview, error)
	Confirm(ctx context.Context, pendingID, password string) (spend.TxResult, error)
	SignData(addr string, message []byte, password string) (signatureHex, keyHex string, err error)
	VerifyData(signatureHex, keyHex string, message []byte, hashed bool, expectedAddress string) (valid bool, address string, err error)
	ExportUnsigned(pendingID string) (spend.UnsignedTx, error)
	SignTx(unsignedTxCBOR, password string, requiredSigners []string) (spend.Witness, error)
	SubmitSigned(ctx context.Context, unsignedTxCBOR, witnessCBOR string) (spend.TxResult, error)
	BuildDelegation(ctx context.Context, req spend.DelegationRequest) (spend.DelegationPreview, error)
}

// NodeLookup is the node-backed verification surface the staking and send
// screens use: confirming a pasted pool or DRep ID exists, and resolving an
// ADA Handle ($name) to its current holding address (consent law: the
// embedded node is the only thing that touches the network). *chain.Client
// satisfies it.
type NodeLookup interface {
	Pool(ctx context.Context, poolID string) (chain.PoolInfo, error)
	DRep(ctx context.Context, drepID string) (chain.DRepInfo, error)
	AssetAddresses(ctx context.Context, asset string) ([]chain.AssetAddress, error)
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
	// TPM feature: machine-binding of the at-rest vault.
	TPMStatus() vault.TPMStatusInfo
	EnableTPM(vaultPassword string, pcrBound bool) error
	DisableTPM(vaultPassword string) error
}

// tpmStatusResponse is the GET /vault/tpm/status response.
type tpmStatusResponse struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	Enabled   bool   `json:"enabled"`
	PCRBound  bool   `json:"pcrBound"`
}

func toTPMStatusResponse(info vault.TPMStatusInfo) tpmStatusResponse {
	return tpmStatusResponse{
		Available: info.Available,
		Reason:    info.Reason,
		Enabled:   info.Enabled,
		PCRBound:  info.PCRBound,
	}
}

// LegacyKeystore is the old single-wallet encrypted mnemonic store. It is
// accepted only for explicit migration into the vault when vault.json is absent.
type LegacyKeystore interface {
	Exists() bool
	Unlock(password string) ([]byte, error)
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

// PoolOps is the Stake Pool Operations surface the API exposes. Credential
// generation and seed-derived certificate/opcert building need the active
// wallet + spending password; the air-gap builders (pool ID, opcert payload /
// assembly, metadata, air-gap registration cert) need neither. Submission
// (retirement) needs a synced node. It operates on the active wallet.
type PoolOps interface {
	// SetAccount binds the active wallet (both its ID and its read-only account)
	// so pool operations always derive credentials from the same wallet whose
	// account is in use. Passing an empty id and nil acct clears the binding.
	SetAccount(id string, acct *wallet.Account)
	Credentials(password string) (poolops.Credentials, error)
	KESPeriod(ctx context.Context) (poolops.KESPeriodInfo, error)
	IssueOpCert(password string, kesIndex uint32, issueNumber, kesPeriod uint64) (poolops.OpCert, error)
	RotateKES(password string, newKESIndex uint32, prevIssueNumber, kesPeriod uint64) (poolops.OpCert, error)
	OpCertPayload(kesVKeyHex string, issueNumber, kesPeriod uint64) (poolops.OpCertPayload, error)
	AssembleOpCert(coldVKeyHex, kesVKeyHex, signatureHex string, issueNumber, kesPeriod uint64) (poolops.OpCert, error)
	BuildMetadata(in poolops.MetadataInput) (poolops.MetadataResult, error)
	PoolIDFromColdVKey(coldVKeyHex string) (poolID, poolIDHex string, err error)
	BuildRegistrationFromSeed(password string, p poolops.RegistrationParams) (poolops.CertResult, error)
	BuildRegistrationAirGap(p poolops.AirGapRegistrationParams) (poolops.CertResult, error)
	BuildRetirementCert(password, coldVKeyHex string, epoch uint64) (poolops.CertResult, error)
	SubmitRetirement(ctx context.Context, password string, epoch uint64) (poolops.TxResult, error)
}

type decimalUint64 uint64

func (n *decimalUint64) UnmarshalJSON(data []byte) error {
	raw := strings.TrimSpace(string(data))
	if raw == "" || raw == "null" {
		return errors.New("expected unsigned integer")
	}
	if raw[0] == '"' {
		unquoted, err := strconv.Unquote(raw)
		if err != nil {
			return fmt.Errorf("invalid quoted unsigned integer: %w", err)
		}
		raw = strings.TrimSpace(unquoted)
	}
	if raw == "" {
		return errors.New("expected unsigned integer")
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return errors.New("expected unsigned integer")
		}
	}
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return fmt.Errorf("unsigned integer out of range: %w", err)
	}
	*n = decimalUint64(v)
	return nil
}

type poolRegistrationRequest struct {
	Pledge        decimalUint64   `json:"pledge"`
	Cost          decimalUint64   `json:"cost"`
	MarginNum     int64           `json:"margin_num"`
	MarginDenom   int64           `json:"margin_denom"`
	RewardAddress string          `json:"reward_address,omitempty"`
	Owners        []string        `json:"owners,omitempty"`
	Relays        []poolops.Relay `json:"relays,omitempty"`
	MetadataURL   string          `json:"metadata_url,omitempty"`
	MetadataHash  string          `json:"metadata_hash,omitempty"`
	ColdVKeyHex   string          `json:"cold_vkey_hex,omitempty"`
}

func (r poolRegistrationRequest) params() poolops.RegistrationParams {
	return poolops.RegistrationParams{
		Pledge:        uint64(r.Pledge),
		Cost:          uint64(r.Cost),
		MarginNum:     r.MarginNum,
		MarginDenom:   r.MarginDenom,
		RewardAddress: r.RewardAddress,
		Owners:        r.Owners,
		Relays:        r.Relays,
		MetadataURL:   r.MetadataURL,
		MetadataHash:  r.MetadataHash,
		ColdVKeyHex:   r.ColdVKeyHex,
	}
}

type poolRegistrationSeedRequest struct {
	Password string `json:"password"`
	poolRegistrationRequest
}

type poolRegistrationAirGapRequest struct {
	poolRegistrationRequest
	VRFKeyHashHex string `json:"vrf_key_hash_hex"`
}

// handleInfo mirrors GET /wallet/handle/{name}: a node-verified ADA Handle
// resolution. Handle is the bare name (no leading '$'); Address is the
// bech32 payment address currently holding the handle NFT.
type handleInfo struct {
	Handle  string `json:"handle"`
	Address string `json:"address"`
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
// whenever the selection changes. settings exposes user-facing app settings
// (the lean-node profile). lookup verifies pasted pool/DRep IDs and resolves
// ADA Handles through the node (may be nil, in which case those endpoints
// report unavailable). po is the Stake Pool Operations surface. spa is the
// embedded SPA, registered as the catch-all so the specific API routes take
// precedence on the mux.
func NewHandler(st Statuser, vlt Vault, wl Wallet, sp Spender, settings SettingsController, lookup NodeLookup, po PoolOps, network string, spa http.Handler, opts ...HandlerOption) http.Handler {
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
		// Pool operations run on the same active wallet; attach both the wallet
		// ID and its account so the SPO toolkit always derives credentials from
		// the wallet whose account data is current.
		if po != nil {
			po.SetAccount(w.ID, w.Account)
		}
	}
	clearActive := func() {
		_ = wl.SetAccount(nil)
		sp.SetAccount("", nil)
		if po != nil {
			po.SetAccount("", nil)
		}
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

	// --- TPM vault binding ---------------------------------------------------

	// GET /vault/tpm/status returns a probe of TPM availability on this machine
	// and whether the vault is currently TPM-enrolled. No vault unlock needed.
	mux.HandleFunc("GET /vault/tpm/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, toTPMStatusResponse(vlt.TPMStatus()))
	})

	// POST /vault/tpm/enable adds a TPM protector to the vault. The vault
	// password is required to authenticate and recover the VEK. pcrBound is
	// optional (defaults to false); when true the seal additionally binds to PCR
	// 7 (firmware state). The password protector is always kept as recovery.
	mux.HandleFunc("POST /vault/tpm/enable", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
			PCRBound bool   `json:"pcrBound"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		if !requirePassword(w, req.Password) {
			return
		}
		if err := vlt.EnableTPM(req.Password, req.PCRBound); err != nil {
			serve(w, struct{}{}, err)
			return
		}
		writeJSON(w, http.StatusOK, toTPMStatusResponse(vlt.TPMStatus()))
	})

	// POST /vault/tpm/disable removes the TPM protector and re-persists with
	// the password protector only. A no-op vault (no TPM enrolled) succeeds
	// silently.
	mux.HandleFunc("POST /vault/tpm/disable", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		if !requirePassword(w, req.Password) {
			return
		}
		if err := vlt.DisableTPM(req.Password); err != nil {
			serve(w, struct{}{}, err)
			return
		}
		writeJSON(w, http.StatusOK, toTPMStatusResponse(vlt.TPMStatus()))
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
	// Drill-down for one transaction in the history: full input/output
	// breakdown. Gated like the list above — it only needs the node serving
	// queries, not a full sync.
	mux.HandleFunc("GET /wallet/transactions/{hash}", gated(st, func(w http.ResponseWriter, r *http.Request) {
		v, err := wl.TransactionDetail(r.Context(), r.PathValue("hash"))
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
			Enabled *bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		if req.Enabled == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "enabled is required"})
			return
		}
		if err := settings.SetHistoryExpiry(*req.Enabled); err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody(err))
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{
			"enabled":          settings.HistoryExpiry(),
			"restart_required": settings.HistoryExpiryRestartRequired(),
		})
	})

	// CIP-8 / CIP-30 message verification — the inverse of sign-data. Pure
	// crypto: ungated, no node, no keystore (a read-only wallet can verify too).
	mux.HandleFunc("POST /wallet/verify-data", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Signature       string `json:"signature"`
			Key             string `json:"key"`
			Message         string `json:"message"`
			Hashed          bool   `json:"hashed"`
			ExpectedAddress string `json:"expected_address"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		valid, addr, err := sp.VerifyData(req.Signature, req.Key, []byte(req.Message), req.Hashed, req.ExpectedAddress)
		serve(w, map[string]any{"valid": valid, "address": addr}, err)
	})

	// Air-gap step 1 (online instance): export the completed-but-unsigned tx for
	// a pending send + the key-hashes that must sign it. Built against a synced
	// node's UTxO view, so it shares the send flow's readyGate.
	mux.HandleFunc("POST /wallet/send/{id}/export-unsigned", readyGate(st, func(w http.ResponseWriter, r *http.Request) {
		v, err := sp.ExportUnsigned(r.PathValue("id"))
		serve(w, v, err)
	}))

	// Air-gap step 2 (offline instance): sign an unsigned tx with the active
	// wallet's key. Ungated like sign-data — pure crypto over the keystore, no
	// node needed; this is what the air-gapped machine runs.
	mux.HandleFunc("POST /wallet/sign-tx", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			UnsignedTxCBOR  string   `json:"unsigned_tx_cbor"`
			Password        string   `json:"password"`
			RequiredSigners []string `json:"required_signers"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		v, err := sp.SignTx(req.UnsignedTxCBOR, req.Password, req.RequiredSigners)
		serve(w, v, err)
	})

	// Air-gap step 3 (online instance): attach the offline witness to the
	// unsigned tx and broadcast. Needs a synced node (readyGate).
	mux.HandleFunc("POST /wallet/submit-signed", readyGate(st, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			UnsignedTxCBOR string `json:"unsigned_tx_cbor"`
			WitnessCBOR    string `json:"witness_cbor"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		v, err := sp.SubmitSigned(r.Context(), req.UnsignedTxCBOR, req.WitnessCBOR)
		serve(w, v, err)
	}))

	// Staking & governance. Pool/DRep lookups verify a pasted ID through the node
	// (gated like reads — they only need the node serving queries). Building a
	// delegation tx and confirming it are gated like sends (a fully synced node),
	// since they select UTxOs and submit.
	mux.HandleFunc("GET /wallet/pool/{id}", gated(st, func(w http.ResponseWriter, r *http.Request) {
		if lookup == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "pool lookup unavailable"})
			return
		}
		info, err := lookup.Pool(r.Context(), r.PathValue("id"))
		serveLookup(w, info, err)
	}))
	mux.HandleFunc("GET /wallet/drep/{id}", gated(st, func(w http.ResponseWriter, r *http.Request) {
		if lookup == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "drep lookup unavailable"})
			return
		}
		info, err := lookup.DRep(r.Context(), r.PathValue("id"))
		serveLookup(w, info, err)
	}))

	// ADA Handle ($name) resolution for the Send screen: resolve the on-chain
	// NFT to its current holding address through the node (never an external
	// service). A leading '$' is optional; handle.Resolve normalizes it. A
	// name on an unsupported network or with no on-chain holder reports as a
	// clean not-found (404), never a hard error.
	mux.HandleFunc("GET /wallet/handle/{name}", gated(st, func(w http.ResponseWriter, r *http.Request) {
		if lookup == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "handle lookup unavailable"})
			return
		}
		bare, addr, err := handle.Resolve(r.Context(), lookup, network, r.PathValue("name"))
		serveLookup(w, handleInfo{Handle: bare, Address: addr}, err)
	}))

	mux.HandleFunc("POST /wallet/delegation", readyGate(st, func(w http.ResponseWriter, r *http.Request) {
		var req spend.DelegationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		pv, err := sp.BuildDelegation(r.Context(), req)
		serve(w, pv, err)
	}))

	mux.HandleFunc("POST /wallet/delegation/{id}/confirm", readyGate(st, func(w http.ResponseWriter, r *http.Request) {
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

	if po != nil {
		registerPoolRoutes(mux, st, po)
	}

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

// serveLookup writes a pool/DRep lookup result, mapping the node's not-found to
// 404 (so the screen can show "not found by your node" inline) and other errors
// to 502 (the node query failed).
func serveLookup[T any](w http.ResponseWriter, v T, err error) {
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, v)
	case errors.Is(err, chain.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found by your node"})
	default:
		writeJSON(w, http.StatusBadGateway, errBody(err))
	}
}

// registerPoolRoutes wires the Stake Pool Operations (SPO) endpoints under
// /wallet/pool/. Air-gap builders (pool ID, opcert payload/assembly, metadata,
// air-gap registration cert) are ungated and need no node — they are pure
// transforms over operator-supplied data. Seed-derived credential/cert/opcert
// building needs the active wallet + spending password but no node (offline).
// KES-period and retirement submission need a node (gated / readyGate).
func registerPoolRoutes(mux *http.ServeMux, st Statuser, po PoolOps) {
	// 1. Credentials (active wallet + password; offline).
	mux.HandleFunc("POST /wallet/pool/credentials", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		v, err := po.Credentials(req.Password)
		serve(w, v, err)
	})

	// 2. KES period (node tip + genesis; gated on a queryable node).
	mux.HandleFunc("GET /wallet/pool/kes-period", gated(st, func(w http.ResponseWriter, r *http.Request) {
		v, err := po.KESPeriod(r.Context())
		serve(w, v, err)
	}))

	// 2. Operational certificate: issue (seed).
	mux.HandleFunc("POST /wallet/pool/opcert", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password    string `json:"password"`
			KESIndex    uint32 `json:"kes_index"`
			IssueNumber uint64 `json:"issue_number"`
			KESPeriod   uint64 `json:"kes_period"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		v, err := po.IssueOpCert(req.Password, req.KESIndex, req.IssueNumber, req.KESPeriod)
		serve(w, v, err)
	})

	// 2. Operational certificate: KES rotation (seed) — new KES key + counter bump.
	mux.HandleFunc("POST /wallet/pool/opcert/rotate", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password        string `json:"password"`
			NewKESIndex     uint32 `json:"new_kes_index"`
			PrevIssueNumber uint64 `json:"prev_issue_number"`
			KESPeriod       uint64 `json:"kes_period"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		v, err := po.RotateKES(req.Password, req.NewKESIndex, req.PrevIssueNumber, req.KESPeriod)
		serve(w, v, err)
	})

	// Air-gap: opcert to-be-signed payload (no wallet needed).
	mux.HandleFunc("POST /wallet/pool/opcert/payload", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			KESVKeyHex  string `json:"kes_vkey_hex"`
			IssueNumber uint64 `json:"issue_number"`
			KESPeriod   uint64 `json:"kes_period"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		v, err := po.OpCertPayload(req.KESVKeyHex, req.IssueNumber, req.KESPeriod)
		serve(w, v, err)
	})

	// Air-gap: assemble opcert from an externally-produced cold-key signature.
	mux.HandleFunc("POST /wallet/pool/opcert/assemble", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ColdVKeyHex  string `json:"cold_vkey_hex"`
			KESVKeyHex   string `json:"kes_vkey_hex"`
			SignatureHex string `json:"signature_hex"`
			IssueNumber  uint64 `json:"issue_number"`
			KESPeriod    uint64 `json:"kes_period"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		v, err := po.AssembleOpCert(req.ColdVKeyHex, req.KESVKeyHex, req.SignatureHex, req.IssueNumber, req.KESPeriod)
		serve(w, v, err)
	})

	// 6. Metadata builder (pure transform; no wallet/node).
	mux.HandleFunc("POST /wallet/pool/metadata", func(w http.ResponseWriter, r *http.Request) {
		var in poolops.MetadataInput
		if !decodeBody(w, r, &in) {
			return
		}
		v, err := po.BuildMetadata(in)
		serve(w, v, err)
	})

	// Air-gap import: pool ID from an external cold vkey (pure transform).
	mux.HandleFunc("POST /wallet/pool/id", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ColdVKeyHex string `json:"cold_vkey_hex"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		id, idHex, err := po.PoolIDFromColdVKey(req.ColdVKeyHex)
		serve(w, map[string]string{"pool_id": id, "pool_id_hex": idHex}, err)
	})

	// 3/4. Registration / update certificate (seed): build the canonical cert.
	mux.HandleFunc("POST /wallet/pool/registration", func(w http.ResponseWriter, r *http.Request) {
		var req poolRegistrationSeedRequest
		if !decodeBody(w, r, &req) {
			return
		}
		v, err := po.BuildRegistrationFromSeed(req.Password, req.params())
		serve(w, v, err)
	})

	// 3/4. Registration / update certificate (air-gap): build from imported keys.
	mux.HandleFunc("POST /wallet/pool/registration/airgap", func(w http.ResponseWriter, r *http.Request) {
		var req poolRegistrationAirGapRequest
		if !decodeBody(w, r, &req) {
			return
		}
		v, err := po.BuildRegistrationAirGap(poolops.AirGapRegistrationParams{
			RegistrationParams: req.params(),
			VRFKeyHashHex:      req.VRFKeyHashHex,
		})
		serve(w, v, err)
	})

	// 5. Retirement certificate (seed or air-gap cold vkey).
	mux.HandleFunc("POST /wallet/pool/retirement/cert", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password    string `json:"password"`
			ColdVKeyHex string `json:"cold_vkey_hex"`
			Epoch       uint64 `json:"epoch"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		v, err := po.BuildRetirementCert(req.Password, req.ColdVKeyHex, req.Epoch)
		serve(w, v, err)
	})

	// 5. Retirement transaction submission (seed; needs a fully synced node).
	mux.HandleFunc("POST /wallet/pool/retirement/submit", readyGate(st, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
			Epoch    uint64 `json:"epoch"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		v, err := po.SubmitRetirement(r.Context(), req.Password, req.Epoch)
		serve(w, v, err)
	}))
}

// decodeBody decodes a JSON request body into v, writing a 400 and returning
// false on malformed input.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return false
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
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
	case errors.Is(err, chain.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errBody(err)) // 404: node has no record of this transaction
	case errors.Is(err, vault.ErrNoVault):
		writeJSON(w, http.StatusNotFound, errBody(err)) // 404: no vault yet
	case errors.Is(err, vault.ErrVaultExists):
		writeJSON(w, http.StatusConflict, errBody(err)) // 409: vault already exists
	case errors.Is(err, vault.ErrUnknownWallet):
		writeJSON(w, http.StatusNotFound, errBody(err)) // 404
	case errors.Is(err, vault.ErrDuplicateWallet):
		writeJSON(w, http.StatusConflict, errBody(err)) // 409
	case errors.Is(err, vault.ErrLocked), errors.Is(err, vault.ErrNoActiveWallet),
		errors.Is(err, wallet.ErrNoWallet), errors.Is(err, spend.ErrNoWallet),
		errors.Is(err, poolops.ErrNoWallet):
		writeJSON(w, http.StatusConflict, errBody(err)) // 409: locked / no active wallet
	case errors.Is(err, spend.ErrWalletChanged):
		writeJSON(w, http.StatusConflict, errBody(err)) // 409: active wallet switched during build
	case errors.Is(err, vault.ErrTPMUnavailable):
		writeJSON(w, http.StatusConflict, errBody(err)) // 409: TPM not available on this machine
	case errors.Is(err, vault.ErrWrongPassword), errors.Is(err, spend.ErrWrongPassword),
		errors.Is(err, poolops.ErrWrongPassword):
		writeJSON(w, http.StatusUnauthorized, errBody(err)) // 401
	case errors.Is(err, spend.ErrInvalidRequest),
		errors.Is(err, spend.ErrInvalidTx),
		errors.Is(err, spend.ErrInvalidWitness),
		errors.Is(err, poolops.ErrInvalidRequest):
		writeJSON(w, http.StatusBadRequest, errBody(err)) // 400
	case errors.Is(err, spend.ErrUnknownPending):
		writeJSON(w, http.StatusNotFound, errBody(err)) // 404
	case errors.Is(err, spend.ErrExpiredPending):
		writeJSON(w, http.StatusGone, errBody(err)) // 410
	case errors.Is(err, spend.ErrInsufficientFunds), errors.Is(err, spend.ErrSubmitRejected),
		errors.Is(err, spend.ErrNoChange), errors.Is(err, poolops.ErrSubmitRejected):
		// 422: the request was understood but cannot be fulfilled; the node's
		// structured rejection reason (for submit), the funding shortfall, or the
		// "already in the requested state" note rides along in the message.
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
