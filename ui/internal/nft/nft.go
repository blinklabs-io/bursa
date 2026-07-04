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

// Package nft discovers an active wallet's NFTs (node-local, via the embedded
// node's asset metadata) and, when the user has explicitly enabled NFT media,
// fetches their images over IPFS using an embedded peer-to-peer client (boxo:
// libp2p + DHT + bitswap) into a content-addressed on-disk cache.
//
// Identity model. The embedded IPFS client is treated as the user's OWN
// node-like infrastructure (like the embedded Cardano node), not a remote
// service. It is therefore OFF by default: nothing touches the IPFS network
// until the user makes a one-time, deliberate opt-in via the settings toggle.
// While disabled, the libp2p host is never started, the bootstrap peers are
// never dialled, and no fetch occurs. There are no per-image prompts and no
// third-party HTTP gateway — retrieval is direct p2p only.
package nft

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/blinklabs-io/bursa/ui/internal/chain"
)

// ErrMediaDisabled is returned by image operations when NFT media is off. It
// maps to HTTP 403 at the API layer: the request is understood but refused
// until the user enables media.
var ErrMediaDisabled = errors.New("nft: media disabled")

// ErrNoWallet is returned when no active wallet account has been set.
var ErrNoWallet = errors.New("nft: no wallet set")

// assetQuerier is the slice of the chain client the service needs (satisfied by
// *chain.Client); it exists so tests can supply a fake.
type assetQuerier interface {
	Asset(ctx context.Context, asset string) (chain.AssetInfo, error)
}

// fetcher is the IPFS retrieval surface the service depends on, decoupling it
// from the concrete IPFS client. It is satisfied by the real boxo client in the
// `-tags nftmedia` build (client_ipfs.go) and by a no-op stub in the default
// build (client_stub.go); tests supply a fake so they never touch the network.
type fetcher interface {
	fetch(ctx context.Context, cid string) ([]byte, error)
	Close() error
}

// UnitsProvider yields the active wallet's native-asset units (policy ID + hex
// asset name; lovelace excluded). It is the single source of truth for which
// assets the wallet holds, evaluated on demand so the NFT view tracks the live
// balance rather than a cached account snapshot. It returns ErrNoWallet when no
// wallet is loaded.
type UnitsProvider func(ctx context.Context) ([]string, error)

// NFT is one discovered token: its unit (asset id), human name, the IPFS CID of
// its image (empty if none/unsupported), and whether the image is cached.
type NFT struct {
	Unit        string `json:"unit"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	ImageCID    string `json:"image_cid,omitempty"`
	Cached      bool   `json:"cached"`
}

// fetcherFactory builds the IPFS client; overridable in tests. The real factory
// is newIPFSClient, whose implementation is build-tag selected (real boxo
// client under `nftmedia`, a no-op stub returning ErrMediaUnavailable
// otherwise).
type fetcherFactory func(ctx context.Context) (fetcher, error)

// Service discovers NFTs from the active wallet and, when enabled, fetches and
// caches their images. It owns the enable setting (persisted), the IPFS client
// lifecycle (started only when enabled), and the on-disk cache.
type Service struct {
	chain   assetQuerier
	units   UnitsProvider
	cache   *cache
	logger  *slog.Logger
	setPath string // settings file path

	// rootCtx scopes the lifetime of any started IPFS client; derived from the
	// process context passed to NewService.
	rootCtx context.Context
	factory fetcherFactory

	mu      sync.Mutex
	enabled bool
	client  fetcher
	images  map[string]imageMemo
}

type imageMemo struct {
	cid     string
	expires time.Time
}

const imageMemoTTL = 30 * time.Second

// Config configures the service.
type Config struct {
	Chain   assetQuerier
	Units   UnitsProvider
	DataDir string
	Logger  *slog.Logger
	// factory overrides the IPFS client constructor (tests only).
	factory fetcherFactory
}

// NewService builds the NFT service. ctx scopes any IPFS client the service
// later starts (cancel it to tear everything down). The persisted enable
// setting is loaded; if it was previously enabled, the IPFS client is started
// now so media works immediately on next launch.
func NewService(ctx context.Context, cfg Config) (*Service, error) {
	if cfg.Chain == nil {
		return nil, errors.New("nft: Config.Chain must not be nil")
	}
	c, err := newCache(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	factory := cfg.factory
	if factory == nil {
		factory = func(ctx context.Context) (fetcher, error) { return newIPFSClient(ctx) }
	}
	s := &Service{
		chain:   cfg.Chain,
		units:   cfg.Units,
		cache:   c,
		logger:  logger,
		setPath: filepath.Join(cfg.DataDir, "nft-settings.json"),
		rootCtx: ctx,
		factory: factory,
		images:  make(map[string]imageMemo),
	}
	s.enabled = s.loadEnabled()
	if s.enabled {
		// Persisted opt-in: bring the client up so media is available without a
		// second toggle. A start failure is non-fatal — the setting stays on and
		// fetches retry to start lazily.
		if err := s.startClient(); err != nil {
			s.logger.Warn("nft: failed to start IPFS client at boot", "err", err)
		}
	}
	return s, nil
}

// settingsFile is the persisted enable toggle.
type settingsFile struct {
	Enabled bool `json:"enabled"`
}

func (s *Service) loadEnabled() bool {
	b, err := os.ReadFile(s.setPath)
	if err != nil {
		return false // absent/unreadable → off (the safe default)
	}
	var sf settingsFile
	if err := json.Unmarshal(b, &sf); err != nil {
		return false
	}
	return sf.Enabled
}

func (s *Service) saveEnabled(enabled bool) error {
	b, err := json.Marshal(settingsFile{Enabled: enabled})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.setPath), ".nft-settings-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.setPath)
}

// Enabled reports whether NFT media is currently on.
func (s *Service) Enabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enabled
}

// SetEnabled turns NFT media on or off and persists the choice. Turning it on
// starts the embedded IPFS client; turning it off stops it (no further network
// activity). Idempotent.
func (s *Service) SetEnabled(enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if enabled == s.enabled {
		return nil
	}
	if err := s.saveEnabled(enabled); err != nil {
		return fmt.Errorf("nft: persist setting: %w", err)
	}
	s.enabled = enabled
	if enabled {
		if err := s.startClientLocked(); err != nil {
			// Keep both the persisted and in-memory intent enabled. Image can
			// then retry startup lazily after a transient constructor failure.
			return err
		}
	} else {
		s.stopClientLocked()
	}
	return nil
}

// startClient starts the IPFS client (acquiring the lock).
func (s *Service) startClient() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startClientLocked()
}

func (s *Service) startClientLocked() error {
	// Enabled may have changed after an Image call's initial check but before
	// its lazy-start path acquired the lifecycle lock. Never start networking
	// after a concurrent disable won that race.
	if !s.enabled {
		return ErrMediaDisabled
	}
	if s.client != nil {
		return nil
	}
	c, err := s.factory(s.rootCtx)
	if err != nil {
		return fmt.Errorf("nft: start IPFS client: %w", err)
	}
	s.client = c
	s.logger.Info("nft: embedded IPFS client started")
	return nil
}

func (s *Service) stopClientLocked() {
	if s.client == nil {
		return
	}
	_ = s.client.Close()
	s.client = nil
	s.logger.Info("nft: embedded IPFS client stopped")
}

// Close stops the IPFS client and releases resources.
func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopClientLocked()
	return nil
}

// walletUnits returns the active wallet's native-asset units, or ErrNoWallet
// when no wallet is loaded (or no units provider was configured).
func (s *Service) walletUnits(ctx context.Context) ([]string, error) {
	if s.units == nil {
		return nil, ErrNoWallet
	}
	return s.units(ctx)
}

// List discovers the active wallet's NFTs: for each native-asset unit it
// queries the node for on-chain metadata and extracts the name + image CID.
// This is NODE-LOCAL — it never touches IPFS. The `cached` flag reports whether
// the image bytes are already on disk. Units whose metadata yields no IPFS image
// are still listed (with an empty ImageCID) so the UI can show the token.
func (s *Service) List(ctx context.Context) ([]NFT, error) {
	units, err := s.walletUnits(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]NFT, 0, len(units))
	for _, unit := range units {
		info, err := s.chain.Asset(ctx, unit)
		if err != nil {
			if errors.Is(err, chain.ErrNotFound) {
				// Node hasn't indexed it yet; list it bare.
				out = append(out, NFT{Unit: unit})
				continue
			}
			s.logger.Warn("nft: skipping asset metadata lookup failure", "unit", unit, "err", err)
			continue
		}
		md := parseMetadata(info.OnchainMetadata)
		s.rememberImage(unit, md.ImageCID)
		out = append(out, NFT{
			Unit:        unit,
			Name:        md.Name,
			Description: md.Description,
			ImageCID:    md.ImageCID,
			Cached:      md.ImageCID != "" && s.cache.has(md.ImageCID),
		})
	}
	// Deterministic order (by unit) for stable UI rendering.
	sort.Slice(out, func(i, j int) bool { return out[i].Unit < out[j].Unit })
	return out, nil
}

// imageForUnit resolves the image CID for an already-authorized asset unit by
// querying the node's asset metadata. Returns "" (no error) when the asset has
// no IPFS image. Image performs the live ownership check before calling this.
func (s *Service) imageForUnit(ctx context.Context, unit string) (string, error) {
	info, err := s.chain.Asset(ctx, unit)
	if err != nil {
		if errors.Is(err, chain.ErrNotFound) {
			return "", nil
		}
		return "", err
	}
	cid := parseMetadata(info.OnchainMetadata).ImageCID
	s.rememberImage(unit, cid)
	return cid, nil
}

func (s *Service) rememberImage(unit, cid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for rememberedUnit, memo := range s.images {
		if !now.Before(memo.expires) {
			delete(s.images, rememberedUnit)
		}
	}
	s.images[unit] = imageMemo{cid: cid, expires: now.Add(imageMemoTTL)}
}

func (s *Service) cachedImage(unit string) ([]byte, bool) {
	s.mu.Lock()
	memo, ok := s.images[unit]
	if ok && time.Now().After(memo.expires) {
		delete(s.images, unit)
		ok = false
	}
	s.mu.Unlock()
	if !ok || memo.cid == "" {
		return nil, false
	}
	b, err := s.cache.get(memo.cid)
	return b, err == nil
}

func (s *Service) ownsUnit(ctx context.Context, unit string) (bool, error) {
	units, err := s.walletUnits(ctx)
	if err != nil {
		return false, err
	}
	for _, u := range units {
		if u == unit {
			return true, nil
		}
	}
	return false, nil
}

// Image returns the image bytes for a wallet-held asset unit. When media is
// disabled it returns ErrMediaDisabled and touches nothing. When enabled it
// serves from the content-addressed cache, fetching over IPFS on a miss and
// caching the result (immutable — cached forever). Returns (nil, nil) when the
// asset has no IPFS image.
func (s *Service) Image(ctx context.Context, unit string) ([]byte, error) {
	if !s.Enabled() {
		return nil, ErrMediaDisabled
	}
	// Ownership is live authorization, not metadata: revalidate it even when
	// both the unit-to-CID memo and content cache hit.
	ok, err := s.ownsUnit(ctx, unit)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNoWallet
	}
	if b, ok := s.cachedImage(unit); ok {
		return b, nil
	}
	cid, err := s.imageForUnit(ctx, unit)
	if err != nil {
		return nil, err
	}
	if cid == "" {
		return nil, nil // no image for this asset
	}
	if b, err := s.cache.get(cid); err == nil {
		return b, nil
	}
	// Cache miss: fetch over IPFS.
	s.mu.Lock()
	client := s.client
	s.mu.Unlock()
	if client == nil {
		// Enabled but the client failed to start earlier; try once more.
		if err := s.startClient(); err != nil {
			return nil, err
		}
		s.mu.Lock()
		client = s.client
		s.mu.Unlock()
	}
	data, err := client.fetch(ctx, cid)
	if err != nil {
		return nil, err
	}
	// Validate before either caching or returning bytes. The compressed-size
	// network cap alone does not prevent a tiny image from expanding into a
	// hostile browser allocation.
	if err := validateImage(data); err != nil {
		return nil, err
	}
	if err := s.cache.put(cid, data); err != nil {
		// Non-fatal: serve the bytes even if caching them failed.
		s.logger.Warn("nft: cache write failed", "cid", cid, "err", err)
	}
	return data, nil
}

// ServeImage writes the image for unit as an HTTP response, mapping the service
// errors to status codes. It is a convenience for the API layer.
func (s *Service) ServeImage(ctx context.Context, w http.ResponseWriter, unit string) {
	data, err := s.Image(ctx, unit)
	switch {
	case errors.Is(err, ErrMediaDisabled):
		http.Error(w, "nft media disabled", http.StatusForbidden)
		return
	case errors.Is(err, ErrNoWallet):
		http.Error(w, "asset not held by active wallet", http.StatusNotFound)
		return
	case errors.Is(err, ErrUnsafeImage):
		http.Error(w, "unsupported or unsafe NFT media", http.StatusUnsupportedMediaType)
		return
	case err != nil:
		http.Error(w, err.Error(), http.StatusBadGateway) // upstream IPFS fetch failed
		return
	case data == nil:
		http.Error(w, "no image for asset", http.StatusNotFound)
		return
	}
	// Defense in depth at the trust boundary: never hand unvalidated bytes to
	// the browser even if a future Image implementation bypasses the cache.
	if err := validateImage(data); err != nil {
		http.Error(w, "unsupported or unsafe NFT media", http.StatusUnsupportedMediaType)
		return
	}
	contentType := http.DetectContentType(data)
	if !allowedImageContentType(contentType) {
		http.Error(w, "unsupported NFT media type", http.StatusUnsupportedMediaType)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Content-addressed: immutable, cache aggressively in the browser too.
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func allowedImageContentType(contentType string) bool {
	switch contentType {
	case "image/jpeg", "image/png", "image/gif", "image/webp":
		return true
	default:
		return false
	}
}
