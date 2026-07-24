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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/ui/internal/chain"
)

// fakeChain is an assetQuerier returning canned metadata per unit.
type fakeChain struct {
	infos map[string]chain.AssetInfo
	errs  map[string]error
	err   error
	calls int
}

func (f *fakeChain) Asset(_ context.Context, asset string) (chain.AssetInfo, error) {
	f.calls++
	if err := f.errs[asset]; err != nil {
		return chain.AssetInfo{}, err
	}
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
	ff := &fakeFetcher{data: validTestPNG()}
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
	info, err := os.Stat(s.setPath)
	if err != nil {
		t.Fatalf("stat settings: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("settings mode = %v, want 0600", info.Mode().Perm())
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

func TestEnableStartFailureKeepsIntentAndImageRetries(t *testing.T) {
	cid := "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
	dir := t.TempDir()
	ff := &fakeFetcher{data: validTestPNG()}
	starts := 0
	factory := func(_ context.Context) (fetcher, error) {
		starts++
		if starts == 1 {
			return nil, errors.New("temporary startup failure")
		}
		return ff, nil
	}
	s, err := NewService(context.Background(), Config{
		Chain: &fakeChain{infos: map[string]chain.AssetInfo{
			"u": {OnchainMetadata: ipfsMeta("Token", "ipfs://"+cid)},
		}},
		Units:   staticUnits("u"),
		DataDir: dir,
		factory: factory,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := s.SetEnabled(true); err == nil {
		t.Fatal("SetEnabled(true) after startup failure = nil, want error")
	}
	if !s.Enabled() {
		t.Fatal("Enabled() = false after transient startup failure")
	}
	if _, err := s.Image(context.Background(), "u"); err != nil {
		t.Fatalf("Image lazy startup retry: %v", err)
	}
	if starts != 2 {
		t.Fatalf("client startup attempts = %d, want 2", starts)
	}
	if ff.callCount() != 1 {
		t.Fatalf("fetch calls = %d, want 1", ff.callCount())
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

func TestDisablePreventsConcurrentLazyStart(t *testing.T) {
	enteredUnits := make(chan struct{})
	resumeUnits := make(chan struct{})
	units := func(context.Context) ([]string, error) {
		close(enteredUnits)
		<-resumeUnits
		return []string{"u"}, nil
	}
	ff := &fakeFetcher{data: validTestPNG()}
	s, starts := newTestService(t, &fakeChain{infos: map[string]chain.AssetInfo{
		"u": {OnchainMetadata: ipfsMeta("Token", "ipfs://QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG")},
	}}, units, ff)

	// Model an enabled service whose earlier client startup failed, so Image
	// will take the lazy-start path after its initial Enabled check.
	s.mu.Lock()
	s.enabled = true
	s.mu.Unlock()
	errCh := make(chan error, 1)
	go func() {
		_, err := s.Image(context.Background(), "u")
		errCh <- err
	}()
	<-enteredUnits // Image has passed Enabled and is now between check and start.
	if err := s.SetEnabled(false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	close(resumeUnits)
	if err := <-errCh; !errors.Is(err, ErrMediaDisabled) {
		t.Fatalf("concurrent Image = %v, want ErrMediaDisabled", err)
	}
	if *starts != 0 {
		t.Fatalf("IPFS client started %d times after disable, want 0", *starts)
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

func TestListSkipsAssetLookupFailure(t *testing.T) {
	failing := errors.New("node lookup failed")
	fc := &fakeChain{
		infos: map[string]chain.AssetInfo{
			"good": {OnchainMetadata: ipfsMeta("Good", "")},
		},
		errs: map[string]error{"bad": failing},
	}
	s, _ := newTestService(t, fc, staticUnits("bad", "missing", "good"), &fakeFetcher{})
	got, err := s.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 || got[0].Unit != "good" || got[1].Unit != "missing" {
		t.Fatalf("List = %+v, want good metadata and bare missing asset", got)
	}
}

func TestImageFetchesCachesAndReuses(t *testing.T) {
	cid := "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
	fc := &fakeChain{infos: map[string]chain.AssetInfo{
		"policyAname1": {OnchainMetadata: ipfsMeta("Token One", "ipfs://"+cid)},
	}}
	imageData := validTestPNG()
	ff := &fakeFetcher{data: imageData}
	s, _ := newTestService(t, fc, staticUnits("policyAname1"), ff)
	if err := s.SetEnabled(true); err != nil {
		t.Fatalf("enable: %v", err)
	}

	// First Image: cache miss → one fetch.
	b, err := s.Image(context.Background(), "policyAname1")
	if err != nil {
		t.Fatalf("Image: %v", err)
	}
	if !bytes.Equal(b, imageData) {
		t.Fatalf("image bytes differ from fetched PNG")
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

func TestImageMemoRevalidatesOwnershipWithoutMetadataLookup(t *testing.T) {
	cid := "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
	fc := &fakeChain{infos: map[string]chain.AssetInfo{
		"u": {OnchainMetadata: ipfsMeta("Token", "ipfs://"+cid)},
	}}
	unitCalls := 0
	units := func(context.Context) ([]string, error) {
		unitCalls++
		return []string{"u"}, nil
	}
	s, _ := newTestService(t, fc, units, &fakeFetcher{data: validTestPNG()})
	if err := s.SetEnabled(true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if _, err := s.Image(context.Background(), "u"); err != nil {
		t.Fatalf("first Image: %v", err)
	}
	if _, err := s.Image(context.Background(), "u"); err != nil {
		t.Fatalf("cached Image: %v", err)
	}
	if unitCalls != 2 || fc.calls != 1 {
		t.Fatalf("lookup calls after cached image = units:%d asset:%d, want 2/1", unitCalls, fc.calls)
	}
}

func TestRememberImageSweepsExpiredUnits(t *testing.T) {
	s, _ := newTestService(t, &fakeChain{}, staticUnits(), &fakeFetcher{})
	s.images["old"] = imageMemo{
		cid:     "old-cid",
		expires: time.Now().Add(-time.Second),
	}
	s.images["live"] = imageMemo{
		cid:     "live-cid",
		expires: time.Now().Add(time.Minute),
	}

	s.rememberImage("new", "new-cid")

	if _, ok := s.images["old"]; ok {
		t.Fatal("expired image memo was retained")
	}
	if _, ok := s.images["live"]; !ok {
		t.Fatal("unexpired image memo was removed")
	}
	if _, ok := s.images["new"]; !ok {
		t.Fatal("new image memo was not added")
	}
}

func TestImageMemoRefusesTransferredAsset(t *testing.T) {
	cid := "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
	fc := &fakeChain{infos: map[string]chain.AssetInfo{
		"u": {OnchainMetadata: ipfsMeta("Token", "ipfs://"+cid)},
	}}
	held := true
	units := func(context.Context) ([]string, error) {
		if held {
			return []string{"u"}, nil
		}
		return nil, nil
	}
	s, _ := newTestService(t, fc, units, &fakeFetcher{data: validTestPNG()})
	if err := s.SetEnabled(true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if _, err := s.Image(context.Background(), "u"); err != nil {
		t.Fatalf("first Image: %v", err)
	}
	held = false
	if _, err := s.Image(context.Background(), "u"); !errors.Is(err, ErrNoWallet) {
		t.Fatalf("memoized Image after transfer = %v, want ErrNoWallet", err)
	}
}

func TestImageMemoCacheMissRechecksOwnership(t *testing.T) {
	cid := "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
	fc := &fakeChain{infos: map[string]chain.AssetInfo{
		"u": {OnchainMetadata: ipfsMeta("Token", "ipfs://"+cid)},
	}}
	held := true
	units := func(context.Context) ([]string, error) {
		if held {
			return []string{"u"}, nil
		}
		return nil, nil
	}
	ff := &fakeFetcher{data: validTestPNG()}
	s, _ := newTestService(t, fc, units, ff)
	if err := s.SetEnabled(true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if _, err := s.Image(context.Background(), "u"); err != nil {
		t.Fatalf("first Image: %v", err)
	}
	if err := os.Remove(s.cache.path(cid)); err != nil {
		t.Fatalf("remove cached image: %v", err)
	}
	held = false
	if _, err := s.Image(context.Background(), "u"); !errors.Is(err, ErrNoWallet) {
		t.Fatalf("Image after ownership change = %v, want ErrNoWallet", err)
	}
	if ff.callCount() != 1 {
		t.Fatalf("fetch calls after ownership change = %d, want 1", ff.callCount())
	}
}

func TestImageRefusesAssetNotHeld(t *testing.T) {
	fc := &fakeChain{infos: map[string]chain.AssetInfo{
		"heldUnit": {OnchainMetadata: ipfsMeta("Held", "ipfs://QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG")},
	}}
	ff := &fakeFetcher{data: validTestPNG()}
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
	s, _ := newTestService(t, fc, staticUnits("u"), &fakeFetcher{data: validTestPNG()})
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

func TestServeImageRejectsExecutableContent(t *testing.T) {
	cid := "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
	fc := &fakeChain{infos: map[string]chain.AssetInfo{
		"u": {OnchainMetadata: ipfsMeta("T", "ipfs://"+cid)},
	}}
	s, _ := newTestService(t, fc, staticUnits("u"), &fakeFetcher{
		data: []byte("<!doctype html><script>alert(document.domain)</script>"),
	})
	if err := s.SetEnabled(true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	rec := httptest.NewRecorder()
	s.ServeImage(context.Background(), rec, "u")
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("ServeImage HTML = %d, want %d", rec.Code, http.StatusUnsupportedMediaType)
	}
	if got := rec.Header().Get("Cache-Control"); got != "" {
		t.Fatalf("rejected response Cache-Control = %q, want empty", got)
	}
}

func TestServeImageRejectsDecompressionBomb(t *testing.T) {
	cid := "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
	fc := &fakeChain{infos: map[string]chain.AssetInfo{
		"u": {OnchainMetadata: ipfsMeta("T", "ipfs://"+cid)},
	}}
	s, _ := newTestService(t, fc, staticUnits("u"), &fakeFetcher{
		data: pngWithDimensions(5000, 5000),
	})
	if err := s.SetEnabled(true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	rec := httptest.NewRecorder()
	s.ServeImage(context.Background(), rec, "u")
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("ServeImage bomb = %d, want %d", rec.Code, http.StatusUnsupportedMediaType)
	}
	if s.cache.has(cid) {
		t.Fatal("decompression bomb was cached")
	}
}
