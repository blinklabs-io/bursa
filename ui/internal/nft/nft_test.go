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

package nft

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/chain"
)

// fakeChain is an assetQuerier returning canned metadata per unit.
type fakeChain struct {
	infos map[string]chain.AssetInfo
	err   error
	calls int
}

func (f *fakeChain) Asset(_ context.Context, asset string) (chain.AssetInfo, error) {
	f.calls++
	if f.err != nil {
		return chain.AssetInfo{}, f.err
	}
	info, ok := f.infos[asset]
	if !ok {
		return chain.AssetInfo{}, chain.ErrNotFound
	}
	return info, nil
}

// fakeFetcher records fetch calls and returns canned bytes; it never touches
// the network. A test that expects NO IPFS activity asserts calls == 0.
type fakeFetcher struct {
	mu     sync.Mutex
	data   []byte
	err    error
	calls  int
	closed bool
}

func (f *fakeFetcher) fetch(_ context.Context, _ string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.data, nil
}

func (f *fakeFetcher) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeFetcher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// newTestService builds a Service over the supplied fakes with media OFF and a
// throwaway data dir. The fetcher factory hands back ff (and records that a
// client was requested) so no real libp2p host is ever created.
func newTestService(t *testing.T, fc *fakeChain, units UnitsProvider, ff *fakeFetcher) (*Service, *int) {
	t.Helper()
	starts := 0
	factory := func(_ context.Context) (fetcher, error) {
		starts++
		return ff, nil
	}
	s, err := NewService(context.Background(), Config{
		Chain:   fc,
		Units:   units,
		DataDir: t.TempDir(),
		factory: factory,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return s, &starts
}

func staticUnits(units ...string) UnitsProvider {
	return func(_ context.Context) ([]string, error) { return units, nil }
}

func TestOffByDefault(t *testing.T) {
	ff := &fakeFetcher{data: []byte("img")}
	s, starts := newTestService(t, &fakeChain{}, staticUnits("u"), ff)
	if s.Enabled() {
		t.Fatal("media must be OFF by default")
	}
	if *starts != 0 {
		t.Fatalf("IPFS client started %d times before opt-in; want 0", *starts)
	}
	// Image must refuse and touch nothing while disabled.
	_, err := s.Image(context.Background(), "u")
	if !errors.Is(err, ErrMediaDisabled) {
		t.Fatalf("Image while disabled = %v, want ErrMediaDisabled", err)
	}
	if *starts != 0 || ff.callCount() != 0 {
		t.Fatalf("disabled Image started=%d fetched=%d; want 0/0 (nothing should touch IPFS)", *starts, ff.callCount())
	}
}

func TestEnableStartsClientAndPersists(t *testing.T) {
	ff := &fakeFetcher{}
	dir := t.TempDir()
	starts := 0
	factory := func(_ context.Context) (fetcher, error) { starts++; return ff, nil }
	s, err := NewService(context.Background(), Config{Chain: &fakeChain{}, Units: staticUnits("u"), DataDir: dir, factory: factory})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := s.SetEnabled(true); err != nil {
		t.Fatalf("SetEnabled(true): %v", err)
	}
	if !s.Enabled() {
		t.Fatal("Enabled() = false after SetEnabled(true)")
	}
	if starts != 1 {
		t.Fatalf("client started %d times, want 1", starts)
	}

	// A fresh Service over the SAME data dir must load the persisted opt-in and
	// start the client at boot (no second toggle needed).
	starts2 := 0
	ff2 := &fakeFetcher{}
	factory2 := func(_ context.Context) (fetcher, error) { starts2++; return ff2, nil }
	s2, err := NewService(context.Background(), Config{Chain: &fakeChain{}, Units: staticUnits("u"), DataDir: dir, factory: factory2})
	if err != nil {
		t.Fatalf("NewService (reload): %v", err)
	}
	if !s2.Enabled() {
		t.Fatal("persisted enable not loaded on reload")
	}
	if starts2 != 1 {
		t.Fatalf("reloaded service started client %d times, want 1 (persisted opt-in)", starts2)
	}
}

func TestDisableStopsClient(t *testing.T) {
	ff := &fakeFetcher{}
	s, _ := newTestService(t, &fakeChain{}, staticUnits("u"), ff)
	if err := s.SetEnabled(true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if err := s.SetEnabled(false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if s.Enabled() {
		t.Fatal("Enabled() = true after disable")
	}
	if !ff.closed {
		t.Fatal("IPFS client not closed on disable")
	}
}

func ipfsMeta(name, image string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"name": name, "image": image})
	return b
}

func TestListDiscoversFromMetadata(t *testing.T) {
	fc := &fakeChain{infos: map[string]chain.AssetInfo{
		"policyAname1": {Asset: "policyAname1", OnchainMetadata: ipfsMeta("Token One", "ipfs://QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG")},
		"policyBname2": {Asset: "policyBname2", OnchainMetadata: ipfsMeta("Token Two", "https://example.com/x.png")}, // non-ipfs → no CID
	}}
	s, _ := newTestService(t, fc, staticUnits("policyBname2", "policyAname1"), &fakeFetcher{})
	got, err := s.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(List) = %d, want 2", len(got))
	}
	// Sorted by unit: policyAname1 first.
	if got[0].Unit != "policyAname1" || got[0].Name != "Token One" || got[0].ImageCID == "" {
		t.Fatalf("nft[0] = %+v, want Token One with an ipfs CID", got[0])
	}
	if got[1].Unit != "policyBname2" || got[1].ImageCID != "" {
		t.Fatalf("nft[1] = %+v, want Token Two with NO CID (non-ipfs image)", got[1])
	}
}

func TestListNoWallet(t *testing.T) {
	s, _ := newTestService(t, &fakeChain{}, func(context.Context) ([]string, error) { return nil, ErrNoWallet }, &fakeFetcher{})
	_, err := s.List(context.Background())
	if !errors.Is(err, ErrNoWallet) {
		t.Fatalf("List with no wallet = %v, want ErrNoWallet", err)
	}
}

func TestImageFetchesCachesAndReuses(t *testing.T) {
	cid := "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
	fc := &fakeChain{infos: map[string]chain.AssetInfo{
		"policyAname1": {OnchainMetadata: ipfsMeta("Token One", "ipfs://"+cid)},
	}}
	ff := &fakeFetcher{data: []byte("\x89PNG\r\n\x1a\nIMAGE")}
	s, _ := newTestService(t, fc, staticUnits("policyAname1"), ff)
	if err := s.SetEnabled(true); err != nil {
		t.Fatalf("enable: %v", err)
	}

	// First Image: cache miss → one fetch.
	b, err := s.Image(context.Background(), "policyAname1")
	if err != nil {
		t.Fatalf("Image: %v", err)
	}
	if string(b) != "\x89PNG\r\n\x1a\nIMAGE" {
		t.Fatalf("image bytes = %q", b)
	}
	if ff.callCount() != 1 {
		t.Fatalf("fetch calls = %d after first Image, want 1", ff.callCount())
	}

	// Second Image: cache hit → no additional fetch.
	if _, err := s.Image(context.Background(), "policyAname1"); err != nil {
		t.Fatalf("Image (cached): %v", err)
	}
	if ff.callCount() != 1 {
		t.Fatalf("fetch calls = %d after cached Image, want 1 (served from cache)", ff.callCount())
	}

	// List should now report cached=true for the asset.
	got, err := s.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || !got[0].Cached {
		t.Fatalf("List after fetch = %+v, want cached=true", got)
	}
}

func TestImageRefusesAssetNotHeld(t *testing.T) {
	fc := &fakeChain{infos: map[string]chain.AssetInfo{
		"heldUnit": {OnchainMetadata: ipfsMeta("Held", "ipfs://QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG")},
	}}
	ff := &fakeFetcher{data: []byte("img")}
	s, _ := newTestService(t, fc, staticUnits("heldUnit"), ff)
	if err := s.SetEnabled(true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	// Request an asset the wallet does NOT hold → refused, no fetch.
	_, err := s.Image(context.Background(), "notHeldUnit")
	if !errors.Is(err, ErrNoWallet) {
		t.Fatalf("Image for unheld asset = %v, want ErrNoWallet", err)
	}
	if ff.callCount() != 0 {
		t.Fatalf("fetch called %d times for unheld asset; want 0", ff.callCount())
	}
}

func TestImageNoImageForAsset(t *testing.T) {
	fc := &fakeChain{infos: map[string]chain.AssetInfo{
		"u": {OnchainMetadata: ipfsMeta("No Image", "")},
	}}
	s, _ := newTestService(t, fc, staticUnits("u"), &fakeFetcher{})
	if err := s.SetEnabled(true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	b, err := s.Image(context.Background(), "u")
	if err != nil {
		t.Fatalf("Image: %v", err)
	}
	if b != nil {
		t.Fatalf("Image with no CID = %q, want nil", b)
	}
}

func TestServeImageStatusCodes(t *testing.T) {
	cid := "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
	fc := &fakeChain{infos: map[string]chain.AssetInfo{
		"u": {OnchainMetadata: ipfsMeta("T", "ipfs://"+cid)},
	}}

	// Disabled → 403.
	s, _ := newTestService(t, fc, staticUnits("u"), &fakeFetcher{data: []byte("\x89PNGdata")})
	rec := httptest.NewRecorder()
	s.ServeImage(context.Background(), rec, "u")
	if rec.Code != 403 {
		t.Fatalf("ServeImage disabled = %d, want 403", rec.Code)
	}

	// Enabled → 200 with bytes + immutable cache header.
	if err := s.SetEnabled(true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	rec = httptest.NewRecorder()
	s.ServeImage(context.Background(), rec, "u")
	if rec.Code != 200 {
		t.Fatalf("ServeImage enabled = %d, want 200", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc == "" {
		t.Fatal("ServeImage missing Cache-Control header")
	}
}
