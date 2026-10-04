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

package survey

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ErrConsentRequired is returned when revealing a sealed survey would fetch a
// drand beacon from a relay and the caller has not consented to that request.
var ErrConsentRequired = errors.New("survey: fetching the drand beacon needs consent")

// drandRelay is the public relay a consented reveal asks for the beacon. It is
// the wallet's only drand contact: sealing is offline and nothing is fetched
// unless a user reveals a survey and agrees.
const drandRelay = "https://api.drand.sh"

// maxBeaconResponse bounds a relay's reply; a quicknet beacon is about 200 bytes.
const maxBeaconResponse = 8 << 10

// newRelayFetcher returns a function that GETs one quicknet beacon signature
// from the relay.
func newRelayFetcher(client *http.Client, relay string) func(context.Context, uint64) ([]byte, error) {
	return func(ctx context.Context, round uint64) ([]byte, error) {
		url := fmt.Sprintf("%s/%s/public/%d", relay, QuicknetChainHash, round)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("drand relay: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("drand relay: status %d for round %d", resp.StatusCode, round)
		}
		var beacon struct {
			Round     uint64 `json:"round"`
			Signature string `json:"signature"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxBeaconResponse)).Decode(&beacon); err != nil {
			return nil, fmt.Errorf("drand relay: %w", err)
		}
		sig, err := hex.DecodeString(beacon.Signature)
		if err != nil || len(sig) == 0 || beacon.Round != round {
			return nil, fmt.Errorf("drand relay: malformed beacon for round %d", round)
		}
		return sig, nil
	}
}

func defaultBeaconFetcher() func(context.Context, uint64) ([]byte, error) {
	return newRelayFetcher(&http.Client{Timeout: 10 * time.Second}, drandRelay)
}

func (s *Service) cachedBeacon(round uint64) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.beacons[round]
}

func (s *Service) cacheBeacon(round uint64, sig []byte) error {
	if err := VerifyBeacon(round, sig); err != nil {
		return err
	}
	s.mu.Lock()
	s.beacons[round] = sig
	s.mu.Unlock()
	return nil
}

// RevealRequest asks for a sealed survey's responses to be unsealed. Beacon is
// an optional user-supplied hex signature for the reveal round; without one the
// beacon is fetched from a drand relay, which needs Consent.
type RevealRequest struct {
	Survey  string `json:"survey"`
	Consent bool   `json:"consent"`
	Beacon  string `json:"beacon,omitempty"`
}

// Reveal obtains and verifies the beacon for a sealed survey's reveal round,
// remembers it so later reads unseal automatically, and returns the survey with
// its revealed answers tallied.
func (s *Service) Reveal(ctx context.Context, req RevealRequest) (Detail, error) {
	sn, err := s.snapshot(ctx)
	if err != nil {
		return Detail{}, err
	}
	k, ok := sn.find(req.Survey)
	if !ok {
		return Detail{}, ErrNotFound
	}
	if err := k.def.Mode.checkQuicknet(); err != nil {
		return Detail{}, err
	}
	round := k.def.Mode.Round
	if s.cachedBeacon(round) == nil {
		if err := s.obtainBeacon(ctx, req, round); err != nil {
			return Detail{}, err
		}
	}
	return s.detail(ctx, sn, k)
}

func (s *Service) obtainBeacon(ctx context.Context, req RevealRequest, round uint64) error {
	if req.Beacon != "" {
		sig, err := hex.DecodeString(req.Beacon)
		if err != nil {
			return invalidf("beacon is not hex")
		}
		return s.cacheBeacon(round, sig)
	}
	if current := CurrentRound(time.Now()); current < round {
		return invalidf("reveal round %d is not yet published (current round %d)", round, current)
	}
	if !req.Consent {
		return ErrConsentRequired
	}
	sig, err := s.fetchBeacon(ctx, round)
	if err != nil {
		return err
	}
	return s.cacheBeacon(round, sig)
}
