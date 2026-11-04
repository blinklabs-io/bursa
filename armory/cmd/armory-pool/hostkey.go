// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/blinklabs-io/bursa/armory/device"
	"github.com/blinklabs-io/bursa/armory/hostkey"
)

const (
	hostKeyType = hostkey.Type
	hostKeyDesc = hostkey.Description
)

// newHostKey writes a new host signing key to file, which must not exist,
// and prints the /provision/host-key request body for its public key, which
// /provision/host-key/revoke takes as well. A multi image needs the scope the
// key is for in the request; scope is empty for a single-scope image.
func newHostKey(file, scope string, out io.Writer) error {
	if scope != "" {
		if err := checkScopeName(scope); err != nil {
			return err
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}

	// O_EXCL means this call created file, so a failed write removes it
	if _, err = f.Write(marshalEnvelope(hostKeyType, hostKeyDesc, vkeyCBOR(priv.Seed()))); err != nil {
		f.Close()
		_ = os.Remove(file)

		return err
	}

	if err = f.Close(); err != nil {
		_ = os.Remove(file)

		return err
	}

	req, err := json.Marshal(device.HostKeyRequest{PublicKey: pub, Scope: scope})
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(out, "%s\n", req)

	return err
}

// readHostKey reads a host signing key file, refusing one others can read.
func readHostKey(file string) (ed25519.PrivateKey, error) { return hostkey.Read(file) }

// sign posts a signing request, first authenticating it with the host key
// when the session has one.
func (s *session) sign(req device.SignRequest, resp *device.SignResponse) error {
	if s.hostKey != nil {
		var ch device.ChallengeResponse

		if err := s.c.post("/v1/challenge", struct{}{}, &ch); err != nil {
			return err
		}

		req = hostkey.Authenticate(req, s.hostKey, ch.Challenge)
	}

	return s.c.post("/v1/sign", req, resp)
}

// maxAdminRequest bounds a provisioning or wipe request read from stdin; the
// device refuses a larger one.
const maxAdminRequest = 64 << 10

// readAdminRequest reads a JSON request, taking an empty input as {}.
func readAdminRequest(in io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(in, maxAdminRequest+1))
	if err != nil {
		return nil, err
	}

	if len(body) > maxAdminRequest {
		return nil, errors.New("request is larger than the device accepts")
	}

	if len(bytes.TrimSpace(body)) == 0 {
		return []byte("{}"), nil
	}

	return body, nil
}

// adminRequest posts the JSON request on in to a provisioning or wipe route
// and prints the device's answer. With a host key it fetches a challenge and
// signs the request, as a device holding a host key requires; without one the
// request goes unsigned, which a device accepts only while it holds no host
// key, and always for /wipe/device and /wipe/objects.
func adminRequest(c *client, route, hostKeyFile string, in io.Reader, out io.Writer) error {
	signed := device.AdminRoutes()[route]

	if !signed && route != "/wipe/device" && route != "/wipe/objects" {
		return fmt.Errorf("unknown route %s", route)
	}

	body, err := readAdminRequest(in)
	if err != nil {
		return err
	}

	// the device wipe and the object listing are never signed
	if hostKeyFile != "" && signed {
		key, err := readHostKey(hostKeyFile)
		if err != nil {
			return err
		}

		var ch device.ChallengeResponse

		if err = c.post("/v1/challenge", struct{}{}, &ch); err != nil {
			return err
		}

		if body, err = device.SignAdminRequest(route, body, key, ch.Challenge); err != nil {
			return err
		}
	}

	var resp json.RawMessage

	if err = c.post(route, json.RawMessage(body), &resp); err != nil {
		return err
	}

	_, err = fmt.Fprintf(out, "%s\n", bytes.TrimSpace(resp))

	return err
}

// adminKeyFile returns the host key file that signs the request on in for
// route, and the request itself, read so its scope can be named: file when
// given, else the key of the request's scope in dir. Requests the device does
// not authenticate take no key.
func adminKeyFile(route, file, dir, scope string, in io.Reader) (string, io.Reader, error) {
	switch {
	case dir == "":
		return file, in, nil
	case file != "":
		return "", nil, errors.New("-host-key and -host-key-dir are exclusive")
	case !device.AdminRoutes()[route]:
		return "", in, nil
	}

	body, err := readAdminRequest(in)
	if err != nil {
		return "", nil, err
	}

	if scope, err = requestScope(route, body, scope); err != nil {
		return "", nil, err
	}

	file, err = scopedHostKeyFile(dir, scope)

	return file, bytes.NewReader(body), err
}

// profileScope is the scope a profile name belongs to: its "@<chain>-mainnet"
// suffix, else testnet.
func profileScope(name string) string {
	if i := strings.LastIndexByte(name, '@'); i >= 0 && strings.HasSuffix(name[i+1:], "-mainnet") {
		return name[i+1:]
	}

	return "testnet"
}

// checkScopeName refuses a scope label that is not a plain name, so it can
// not pick a path outside the key directory.
func checkScopeName(scope string) error {
	if scope == "" || strings.Trim(scope, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
		return fmt.Errorf("scope %q must be testnet or a chain label such as prime-mainnet", scope)
	}

	return nil
}

// scopedHostKeyFile is the host key file of scope in dir.
func scopedHostKeyFile(dir, scope string) (string, error) {
	if scope == "" {
		return "", errors.New("-host-key-dir needs the scope: a profile name or -scope")
	}

	if err := checkScopeName(scope); err != nil {
		return "", err
	}

	return filepath.Join(dir, scope+".key"), nil
}

// requestScope is the scope of the host key that signs body, a request for
// route: -scope when given, else the scope the request names (a host key's
// scope, or a profile's). Requests that name none, cold keys and the
// device-wide ones, need -scope.
func requestScope(route string, body []byte, override string) (string, error) {
	if override != "" {
		return override, nil
	}

	var req struct {
		Scope     string `json:"scope"`
		Profile   string `json:"profile"`
		Name      string `json:"name"`
		NetworkID uint8  `json:"network_id"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		return "", fmt.Errorf("malformed request for %s", route)
	}

	switch {
	case req.Scope != "":
		return req.Scope, nil
	case req.Profile != "":
		return profileScope(req.Profile), nil
	case req.Name != "" && route == device.RouteProvisionProfile && req.NetworkID == 0:
		return "testnet", nil
	case req.Name != "" && route == device.RouteProvisionProfile:
		return profileScope(req.Name), nil
	}

	return "", fmt.Errorf("%s names no profile or scope: give -scope", route)
}
