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

// Package updatecheck checks the public Bursa GitHub release for a newer
// wallet version. It has no desktop dependencies so the response parsing and
// version comparison can be tested without a display or webview.
package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	latestReleaseURL = "https://api.github.com/repos/blinklabs-io/bursa/releases/latest"
	maxResponseBytes = 1 << 20
)

// Release is the public information needed to tell the user about an update.
type Release struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
}

// Check returns the latest stable release and whether it is newer than the
// supplied version. An empty current version is treated as a development build
// and never reports an update.
func Check(ctx context.Context, client *http.Client, currentVersion string) (Release, bool, error) {
	return checkAt(ctx, client, currentVersion, latestReleaseURL)
}

func checkAt(ctx context.Context, client *http.Client, currentVersion, endpoint string) (Release, bool, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Release{}, false, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Bursa-Wallet")
	resp, err := client.Do(req)
	if err != nil {
		return Release{}, false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return Release{}, false, fmt.Errorf("release check returned HTTP %d", resp.StatusCode)
	}
	var release Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&release); err != nil {
		return Release{}, false, err
	}
	if _, err := parseVersion(release.TagName); err != nil {
		return Release{}, false, fmt.Errorf("invalid release tag: %w", err)
	}
	if !validReleaseURL(release.HTMLURL, release.TagName) {
		return Release{}, false, errors.New("release response contains an unsafe URL")
	}
	if currentVersion == "" {
		return release, false, nil
	}
	current, err := parseVersion(currentVersion)
	if err != nil {
		return Release{}, false, fmt.Errorf("invalid current version: %w", err)
	}
	latest, _ := parseVersion(release.TagName)
	return release, latest.compare(current) > 0, nil
}

func validReleaseURL(raw, tag string) bool {
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return false
	}
	return u.Scheme == "https" && u.Host == "github.com" &&
		u.Path == "/blinklabs-io/bursa/releases/tag/"+tag && u.RawQuery == "" && u.Fragment == ""
}

type version struct {
	major, minor, patch int
	pre                 string
}

func parseVersion(raw string) (version, error) {
	raw = strings.TrimPrefix(raw, "v")
	core, pre, _ := strings.Cut(raw, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 || pre != "" && strings.Contains(pre, "/") {
		return version{}, errors.New("expected vMAJOR.MINOR.PATCH")
	}
	var values [3]int
	for i, part := range parts {
		if part == "" {
			return version{}, errors.New("expected vMAJOR.MINOR.PATCH")
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return version{}, errors.New("expected vMAJOR.MINOR.PATCH")
			}
		}
		var value int
		if _, err := fmt.Sscanf(part, "%d", &value); err != nil {
			return version{}, err
		}
		values[i] = value
	}
	return version{major: values[0], minor: values[1], patch: values[2], pre: pre}, nil
}

func (v version) compare(other version) int {
	for _, pair := range [][2]int{{v.major, other.major}, {v.minor, other.minor}, {v.patch, other.patch}} {
		if pair[0] != pair[1] {
			if pair[0] < pair[1] {
				return -1
			}
			return 1
		}
	}
	if v.pre == other.pre {
		return 0
	}
	if v.pre == "" {
		return 1
	}
	if other.pre == "" {
		return -1
	}
	if v.pre < other.pre {
		return -1
	}
	return 1
}
