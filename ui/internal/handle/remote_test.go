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

package handle

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/chain"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func remoteResolverResponse(status int, body, contentType string, inspect func(*http.Request)) *APIResolver {
	return &APIResolver{client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if inspect != nil {
			inspect(req)
		}
		return &http.Response{
			StatusCode: status,
			Header:     http.Header{"Content-Type": []string{contentType}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	})}}
}

func mainnetAddress(t *testing.T) string {
	t.Helper()
	hash := make([]byte, lcommon.AddressHashSize)
	hash[0] = 1
	addr, err := lcommon.NewAddressFromParts(lcommon.AddressTypeKeyNone, lcommon.AddressNetworkMainnet, hash, nil)
	if err != nil {
		t.Fatalf("build address: %v", err)
	}
	return addr.String()
}

func TestAPIResolverReturnsValidatedMainnetAddress(t *testing.T) {
	address := mainnetAddress(t)
	resolver := remoteResolverResponse(http.StatusOK, `{
		"name":"chris",
		"policy":"`+PolicyID+`",
		"utxo":"012345#0",
		"resolved_addresses":{"ada":"`+address+`"}
	}`, "application/json; charset=utf-8", func(req *http.Request) {
		if req.URL.String() != apiBaseURL+"chris" {
			t.Fatalf("request URL = %q", req.URL.String())
		}
		if req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" || req.Header.Get("Proxy-Authorization") != "" {
			t.Fatal("external lookup forwarded credentials")
		}
	})
	name, got, err := resolver.Resolve(context.Background(), "mainnet", "$Chris")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if name != "chris" || got != address {
		t.Fatalf("Resolve = (%q, %q), want (chris, %q)", name, got, address)
	}
}

func TestAPIResolverDistinguishesMissingFromServiceFailure(t *testing.T) {
	missing := remoteResolverResponse(http.StatusNotFound, `{}`, "application/json", nil)
	if _, _, err := missing.Resolve(context.Background(), "mainnet", "missing"); !errors.Is(err, chain.ErrNotFound) {
		t.Fatalf("404 error = %v, want chain.ErrNotFound", err)
	}
	for _, status := range []int{http.StatusAccepted, http.StatusTooManyRequests, http.StatusInternalServerError} {
		resolver := remoteResolverResponse(status, `{}`, "application/json", nil)
		if _, _, err := resolver.Resolve(context.Background(), "mainnet", "chris"); !errors.Is(err, ErrRemoteUnavailable) {
			t.Fatalf("status %d error = %v, want ErrRemoteUnavailable", status, err)
		}
	}
}

func TestAPIResolverRejectsAmbiguousOwnershipEvidence(t *testing.T) {
	address := mainnetAddress(t)
	rewardHash := make([]byte, lcommon.AddressHashSize)
	reward, err := lcommon.NewAddressFromParts(lcommon.AddressTypeNoneKey, lcommon.AddressNetworkMainnet, nil, rewardHash)
	if err != nil {
		t.Fatalf("build reward address: %v", err)
	}
	base := `{"name":"chris","policy":"` + PolicyID + `","utxo":"012345#0","resolved_addresses":{"ada":"` + address + `"}}`
	tests := []string{
		strings.Replace(base, `"name":"chris"`, `"name":"other"`, 1),
		strings.Replace(base, PolicyID, strings.Repeat("0", len(PolicyID)), 1),
		strings.Replace(base, `"utxo":"012345#0"`, `"utxo":""`, 1),
		strings.Replace(base, address, "addr_test1invalidnetwork", 1),
		strings.Replace(base, address, reward.String(), 1),
		strings.Replace(base, `"name":"chris"`, `"name":"chris","name":"other"`, 1),
	}
	for _, body := range tests {
		resolver := remoteResolverResponse(http.StatusOK, body, "application/json", nil)
		if _, _, err := resolver.Resolve(context.Background(), "mainnet", "chris"); !errors.Is(err, ErrAmbiguousHolder) && !errors.Is(err, ErrRemoteUnavailable) {
			t.Fatalf("ambiguous response error = %v", err)
		}
	}
}

func TestAPIResolverBoundsNameResponseAndNetwork(t *testing.T) {
	called := false
	resolver := remoteResolverResponse(http.StatusOK, strings.Repeat(" ", maxRemoteBodyBytes+1), "application/json", func(*http.Request) { called = true })
	if _, _, err := resolver.Resolve(context.Background(), "mainnet", strings.Repeat("a", maxRemoteNameBytes+1)); !errors.Is(err, chain.ErrNotFound) {
		t.Fatalf("oversized name error = %v, want not found", err)
	}
	if called {
		t.Fatal("invalid name reached external transport")
	}
	if _, _, err := resolver.Resolve(context.Background(), "preview", "chris"); !errors.Is(err, ErrRemoteUnavailable) {
		t.Fatalf("preview error = %v, want unavailable", err)
	}
	if called {
		t.Fatal("testnet lookup reached mainnet service")
	}
	if _, _, err := resolver.Resolve(context.Background(), "mainnet", "chris"); !errors.Is(err, ErrRemoteUnavailable) {
		t.Fatalf("oversized body error = %v, want unavailable", err)
	}
}

func TestAPIResolverRejectsRedirectAndWrongContentType(t *testing.T) {
	redirect := remoteResolverResponse(http.StatusFound, `{}`, "application/json", nil)
	if _, _, err := redirect.Resolve(context.Background(), "mainnet", "chris"); !errors.Is(err, ErrRemoteUnavailable) {
		t.Fatalf("redirect error = %v, want unavailable", err)
	}
	wrongType := remoteResolverResponse(http.StatusOK, `{}`, "text/html", nil)
	if _, _, err := wrongType.Resolve(context.Background(), "mainnet", "chris"); !errors.Is(err, ErrRemoteUnavailable) {
		t.Fatalf("content type error = %v, want unavailable", err)
	}
}

func TestPublicIPRejectsInternalAndSpecialUseDestinations(t *testing.T) {
	for _, raw := range []string{
		"127.0.0.1",
		"::ffff:127.0.0.1",
		"10.0.0.1",
		"100.64.0.1",
		"169.254.169.254",
		"192.0.2.1",
		"198.18.0.1",
		"::1",
		"fc00::1",
		"fe80::1",
		"2001:db8::1",
	} {
		if publicIP(netip.MustParseAddr(raw)) {
			t.Fatalf("publicIP(%s) = true", raw)
		}
	}
	for _, raw := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		if !publicIP(netip.MustParseAddr(raw)) {
			t.Fatalf("publicIP(%s) = false", raw)
		}
	}
}
