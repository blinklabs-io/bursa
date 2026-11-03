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

package device

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

// adminDomain separates host signatures over provisioning and wipe requests
// from every other signature the host key could make.
const adminDomain = "bursa-armory-admin/1"

// Provisioning and wipe routes that require host authentication once a host
// key is registered.
const (
	RouteProvisionProfile    = "/provision/profile"
	RouteProvisionFloor      = "/provision/floor"
	RouteProvisionReward     = "/provision/reward"
	RouteProvisionCold       = "/provision/cold"
	RouteProvisionIdentity   = "/provision/identity"
	RouteProvisionHostKey    = "/provision/host-key"
	RouteProvisionHostRevoke = "/provision/host-key/revoke"
	RouteWipeProfile         = "/wipe/profile"
	RouteWipeSignLog         = "/wipe/signlog"
)

// HostAuth authenticates a provisioning or wipe request: the host key signs
// AdminBinding over the route, the request with these fields empty, and a
// challenge from /v1/challenge.
type HostAuth struct {
	Challenge     []byte `json:"challenge,omitempty"`
	HostKey       []byte `json:"host_key,omitempty"`
	HostSignature []byte `json:"host_signature,omitempty"`
}

func (a *HostAuth) hostAuth() *HostAuth { return a }

// hostAuthed is a request that carries HostAuth.
type hostAuthed interface {
	hostAuth() *HostAuth
}

// IdentityRequest asks the device to create or return its identity key.
type IdentityRequest struct {
	HostAuth
}

// WipeSignLogRequest confirms the reset of the signing log head, as
// WipeDeviceRequest, and authenticates it with a host key.
type WipeSignLogRequest struct {
	IdentityPublicKey string `json:"identity_public_key"`
	HostAuth
}

// adminRequests creates the request type of each authenticated route.
var adminRequests = map[string]func() hostAuthed{
	RouteProvisionProfile:    func() hostAuthed { return &ProvisionRequest{} },
	RouteProvisionFloor:      func() hostAuthed { return &FloorRequest{} },
	RouteProvisionReward:     func() hostAuthed { return &RewardRequest{} },
	RouteProvisionCold:       func() hostAuthed { return &ColdRequest{} },
	RouteProvisionIdentity:   func() hostAuthed { return &IdentityRequest{} },
	RouteProvisionHostKey:    func() hostAuthed { return &HostKeyRequest{} },
	RouteProvisionHostRevoke: func() hostAuthed { return &HostKeyRequest{} },
	RouteWipeProfile:         func() hostAuthed { return &WipeProfileRequest{} },
	RouteWipeSignLog:         func() hostAuthed { return &WipeSignLogRequest{} },
}

// AdminRoutes returns the routes that take host authentication.
func AdminRoutes() map[string]bool {
	routes := make(map[string]bool, len(adminRequests))
	for route := range adminRequests {
		routes[route] = true
	}

	return routes
}

// secretHolder is a request that carries private keys.
type secretHolder interface {
	secrets() []*secretHex
}

// secrets returns the decoded cborHex signing key of the request.
func (r *ColdRequest) secrets() []*secretHex { return []*secretHex{&r.SigningKey} }

// secrets returns the decoded cborHex owner signing key of the request.
func (r *ProvisionRequest) secrets() []*secretHex { return []*secretHex{&r.OwnerSigningKey} }

// keyDigest is the SHA-256 of the bytes a cborHex private key decodes to:
// the canonical request binds the key by it, so the key itself never passes
// through encoding/json, whose pooled buffers are not cleared. secretHex
// marshals it as the same hex string a host computes from the cborHex.
func keyDigest(key secretHex) secretHex {
	sum := sha256.Sum256(key)

	return secretHex(sum[:])
}

// canonicalRequest is the JSON of req with its authentication fields empty
// and each private key replaced by its keyDigest: what the host key signs a
// digest of.
func canonicalRequest(req hostAuthed) ([]byte, error) {
	a := req.hostAuth()
	saved := *a
	*a = HostAuth{}

	defer func() { *a = saved }()

	if h, ok := req.(secretHolder); ok {
		for _, p := range h.secrets() {
			if len(*p) == 0 {
				continue
			}

			key, digest := *p, keyDigest(*p)
			*p = digest

			defer func() { *p = key; clear(digest) }()
		}
	}

	return json.Marshal(req)
}

// AdminBinding is the digest a host key signs to authenticate a request to
// route: the domain string, the route, the canonical request and the
// challenge, length-prefixed as in RequestBinding.
func AdminBinding(route string, canonical, challenge []byte) []byte {
	h := sha256.New()

	for _, field := range [][]byte{
		[]byte(adminDomain), []byte(route), canonical, challenge,
	} {
		h.Write([]byte(strconv.Itoa(len(field)) + ":"))
		h.Write(field)
	}

	return h.Sum(nil)
}

// SignAdminRequest returns body, the JSON request for route, carrying the
// challenge, the public key of key and its signature. Fields the route does
// not take are refused, as the device does.
func SignAdminRequest(route string, body []byte, key ed25519.PrivateKey, challenge []byte) ([]byte, error) {
	mk, ok := adminRequests[route]
	if !ok {
		return nil, fmt.Errorf("route %s does not take host authentication", route)
	}

	req := mk()

	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()

	if err := dec.Decode(req); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		return nil, fmt.Errorf("malformed request for %s", route)
	}

	canonical, err := canonicalRequest(req)
	if err != nil {
		return nil, err
	}

	*req.hostAuth() = HostAuth{
		Challenge:     challenge,
		HostKey:       key.Public().(ed25519.PublicKey),
		HostSignature: ed25519.Sign(key, AdminBinding(route, canonical, challenge)),
	}

	return json.Marshal(req)
}

// handleAdmin is handle for a route that changes the device. With no host key
// registered for any network or chain the first request is served unsigned,
// so a fresh device can be set up. Once one exists the request must carry a
// signature from a key this build trusts; the device wipe is the way out
// when every such key is lost.
func handleAdmin[Req any, P interface {
	*Req
	hostAuthed
}, Resp any](s *Service, route string, fn func(Req) (Resp, error)) http.HandlerFunc {
	return handle(s, func(req Req) (Resp, error) {
		var zero Resp

		if err := s.authorizeAdmin(route, P(&req)); err != nil {
			return zero, err
		}

		return fn(req)
	})
}

// errProvisioningClosed refuses the firmware's unsigned cold key import once
// a host key is registered.
var errProvisioningClosed = errors.New("a host key is registered: send a signed /provision/cold request")

// UnsignedProvisioningLocked reports why provisioning requests cannot be taken
// unsigned, or nil when they can: no host key of any network or chain is
// registered and the stored list is readable. The firmware's unsigned cold
// key import (/provision) is served only then. The caller holds the lock
// passed to New across this check and the import, so a host key registered
// in between cannot let the import through.
func (s *Service) UnsignedProvisioningLocked() error {
	switch {
	case s.chip == nil:
		return errNoChip
	case s.hostKeysBad:
		return errHostKeysBad
	case len(s.hostEntries) > 0:
		return errProvisioningClosed
	}

	return nil
}

// authorizeAdmin checks req's host authentication for route.
func (s *Service) authorizeAdmin(route string, req hostAuthed) error {
	if s.hostKeysBad {
		return errHostKeysBad
	}

	// no host key of any scope: the bootstrap state
	if len(s.hostEntries) == 0 {
		return nil
	}

	canonical, err := canonicalRequest(req)
	if err != nil {
		s.logf("canonical request: %v", err)
		return errDevice
	}

	a := req.hostAuth()

	return s.authenticateHost(a.HostKey, a.HostSignature, a.Challenge, AdminBinding(route, canonical, a.Challenge))
}
