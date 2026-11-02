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

//go:build webview

package desktoptray

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// sessionFragmentPrefix introduces the control-session capability in the
// launch URL fragment.
const sessionFragmentPrefix = "session="

// sessionHeader carries the control-session capability on authenticated
// requests to the control surface.
const sessionHeader = "X-Bursa-Session"

// nodeStatus is the subset of GET /status the tray renders.
type nodeStatus struct {
	State    string `json:"state"`
	CaughtUp bool   `json:"caughtUp"`
}

// statusUnreachableError marks a transport failure, as opposed to a reachable
// server that returned an unusable response.
type statusUnreachableError struct{ err error }

func (e *statusUnreachableError) Error() string { return e.err.Error() }
func (e *statusUnreachableError) Unwrap() error { return e.err }

// SplitLaunchURL separates the authenticated launch URL into the fragment-free
// control-surface base URL and the session capability. A fragment appended to
// the base URL would swallow the "/status" path suffix.
func SplitLaunchURL(launchURL string) (base, token string) {
	base, frag, _ := strings.Cut(launchURL, "#")
	return base, strings.TrimPrefix(frag, sessionFragmentPrefix)
}

// fetchNodeStatus polls GET /status on the control surface, presenting the
// session capability the endpoint requires.
func fetchNodeStatus(ctx context.Context, client *http.Client, baseURL, token string) (nodeStatus, error) {
	var st nodeStatus
	// The launch URL's base ends in "/"; joining it verbatim would request
	// //status and cost a mux redirect on every poll.
	statusURL := strings.TrimSuffix(baseURL, "/") + "/status"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
	if err != nil {
		return st, err
	}
	if token != "" {
		req.Header.Set(sessionHeader, token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return st, &statusUnreachableError{err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return st, fmt.Errorf("status poll: unexpected status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return st, err
	}
	return st, nil
}
