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
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/blinklabs-io/bursa/ui/internal/cardanonet"
	"github.com/blinklabs-io/bursa/ui/internal/chain"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

const (
	apiHost            = "api.handle.me"
	apiBaseURL         = "https://" + apiHost + "/handles/"
	maxRemoteNameBytes = 128
	maxRemoteBodyBytes = 32 * 1024
	remoteTimeout      = 5 * time.Second
)

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:10::/28"),
	netip.MustParsePrefix("2001:20::/28"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fec0::/10"),
}

// ErrRemoteUnavailable means an external Handle lookup did not produce a
// current, authoritative answer. Callers must not treat it as "not found".
var ErrRemoteUnavailable = errors.New("handle: external lookup unavailable")

// APIResolver resolves a Handle through the fixed api.handle.me endpoint. It
// sends no credentials, follows no redirects, accepts only bounded JSON, and
// validates that the returned name, UTxO, address type, and Cardano network agree
// before returning a recipient.
type APIResolver struct {
	client *http.Client
}

// NewAPIResolver constructs the production external resolver. The transport
// bypasses environment proxies and only dials public addresses for the fixed
// service hostname, so configuration cannot turn a Handle lookup into an SSRF
// or credential-forwarding primitive.
func NewAPIResolver() *APIResolver {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = dialHandleAPI
	return &APIResolver{client: &http.Client{
		Transport: transport,
		Timeout:   remoteTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

func dialHandleAPI(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || !strings.EqualFold(host, apiHost) || port != "443" {
		return nil, fmt.Errorf("%w: refused destination", ErrRemoteUnavailable)
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve service", ErrRemoteUnavailable)
	}
	dialer := net.Dialer{Timeout: remoteTimeout}
	for _, addr := range addrs {
		if !publicIP(addr) {
			continue
		}
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		err = dialErr
	}
	if err == nil {
		err = errors.New("service has no public address")
	}
	return nil, fmt.Errorf("%w: connect service: %w", ErrRemoteUnavailable, err)
}

func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() ||
		ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsUnspecified() {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// Resolve looks up input on api.handle.me. The hosted service is a mainnet
// index, so test networks fail closed instead of accepting a mainnet address.
func (r *APIResolver) Resolve(ctx context.Context, network, input string) (name, address string, err error) {
	name, err = normalizeRemoteName(input)
	if err != nil {
		return "", "", chain.ErrNotFound
	}
	if network != "mainnet" {
		return name, "", ErrRemoteUnavailable
	}
	if r == nil || r.client == nil {
		return name, "", ErrRemoteUnavailable
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBaseURL+url.PathEscape(name), nil)
	if err != nil {
		return name, "", fmt.Errorf("%w: build request", ErrRemoteUnavailable)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Bursa-Wallet/handle-resolution")
	resp, err := r.client.Do(req)
	if err != nil {
		return name, "", fmt.Errorf("%w: request failed", ErrRemoteUnavailable)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return name, "", chain.ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return name, "", fmt.Errorf("%w: service status %d", ErrRemoteUnavailable, resp.StatusCode)
	}
	if mediaType := strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0])); mediaType != "application/json" {
		return name, "", fmt.Errorf("%w: invalid content type", ErrRemoteUnavailable)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRemoteBodyBytes+1))
	if err != nil || len(body) > maxRemoteBodyBytes {
		return name, "", fmt.Errorf("%w: invalid response size", ErrRemoteUnavailable)
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return name, "", fmt.Errorf("%w: ambiguous response", ErrRemoteUnavailable)
	}
	var result struct {
		Name              string `json:"name"`
		UTxO              string `json:"utxo"`
		ResolvedAddresses struct {
			ADA string `json:"ada"`
		} `json:"resolved_addresses"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&result); err != nil {
		return name, "", fmt.Errorf("%w: invalid response", ErrRemoteUnavailable)
	}
	if result.Name != name || !validUTxO(result.UTxO) || result.ResolvedAddresses.ADA == "" {
		return name, "", ErrAmbiguousHolder
	}
	addr, err := lcommon.NewAddress(result.ResolvedAddresses.ADA)
	if err != nil {
		return name, "", ErrAmbiguousHolder
	}
	wantNetwork, err := cardanonet.AddressNetworkID(network)
	if err != nil || addr.NetworkId() != uint(wantNetwork) || addr.Type() > lcommon.AddressTypeScriptNone {
		return name, "", ErrAmbiguousHolder
	}
	return name, result.ResolvedAddresses.ADA, nil
}

func validUTxO(input string) bool {
	txID, index, ok := strings.Cut(input, "#")
	if !ok || len(txID) != 64 || index == "" || strings.Contains(index, "#") {
		return false
	}
	decoded, err := hex.DecodeString(txID)
	if err != nil || len(decoded) != 32 {
		return false
	}
	for _, ch := range index {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	_, err = strconv.ParseUint(index, 10, 32)
	return err == nil
}

func normalizeRemoteName(input string) (string, error) {
	name, err := Normalize(input)
	if err != nil || len(name) > maxRemoteNameBytes || !utf8.ValidString(name) {
		return "", ErrInvalidName
	}
	parts := strings.Split(name, "@")
	if len(parts) > 2 {
		return "", ErrInvalidName
	}
	for _, part := range parts {
		if part == "" {
			return "", ErrInvalidName
		}
		for _, ch := range part {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '.' && ch != '_' && ch != '-' {
				return "", ErrInvalidName
			}
		}
	}
	return name, nil
}

func rejectDuplicateJSONKeys(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("non-string object key")
			}
			if _, exists := seen[key]; exists {
				return errors.New("duplicate object key")
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated object")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated array")
		}
	default:
		return errors.New("unexpected delimiter")
	}
	return nil
}
