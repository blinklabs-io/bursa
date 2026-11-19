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

package kesagent

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
)

// hasAuthorizedClients reports whether any profile lists a remote signing or
// control client.
func (a *Agent) hasAuthorizedClients() bool {
	for _, p := range a.profiles {
		if len(p.cfg.SignClientSPKI) > 0 || len(p.cfg.ControlClientSPKI) > 0 {
			return true
		}
	}
	return false
}

// controlProfilesFor returns the profiles whose control list has the client's
// public key; fingerprint is nil for a connection without a verified client
// certificate, which controls nothing.
func (a *Agent) controlProfilesFor(fingerprint *[sha256.Size]byte) []*profile {
	return a.profilesFor(fingerprint, func(p *profile) [][sha256.Size]byte {
		return p.cfg.ControlClientSPKI
	})
}

// signProfilesFor returns the profiles whose signing list has the client's
// public key. Control authority never implies signing authority.
func (a *Agent) signProfilesFor(fingerprint *[sha256.Size]byte) []*profile {
	return a.profilesFor(fingerprint, func(p *profile) [][sha256.Size]byte {
		return p.cfg.SignClientSPKI
	})
}

func (a *Agent) profilesFor(
	fingerprint *[sha256.Size]byte,
	clientKeys func(*profile) [][sha256.Size]byte,
) []*profile {
	if fingerprint == nil {
		return nil
	}
	var out []*profile
	for _, p := range a.profiles {
		for _, entry := range clientKeys(p) {
			if subtle.ConstantTimeCompare(fingerprint[:], entry[:]) == 1 {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// peerSPKIFingerprint returns the SHA-256 SPKI fingerprint of the client
// certificate on conn, or nil unless the TLS stack verified it.
func peerSPKIFingerprint(conn net.Conn) *[sha256.Size]byte {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return nil
	}
	sum := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
	return &sum
}

// handleRemoteControl serves control commands on an attested control session.
func (a *Agent) handleRemoteControl(
	ctx context.Context,
	conn net.Conn,
	permitted []*profile,
) {
	for {
		if ctx.Err() != nil {
			return
		}
		var cmd Command
		if err := readFrame(conn, &cmd); err != nil {
			if !errors.Is(err, io.EOF) {
				a.logger.Debug("remote control read failed", "error", err)
			}
			return
		}
		if err := writeFrame(conn, a.dispatchRemote(ctx, cmd, permitted)); err != nil {
			a.logger.Debug("remote control write failed", "error", err)
			return
		}
	}
}

// dispatchRemote runs gen-staged-key, install-key and info on a profile the
// client is listed for. drop-key is local-socket only. The profile is
// resolved and checked before dispatch, and set on the command, so info
// never takes the all-profiles branch.
func (a *Agent) dispatchRemote(
	ctx context.Context,
	cmd Command,
	permitted []*profile,
) Reply {
	switch cmd.Command {
	case CmdGenStagedKey, CmdInstallKey, CmdInfo:
	case CmdDropKey:
		return Reply{
			Ok:    false,
			Error: "kesagent: drop-key is not served on a remote control session",
		}
	default:
		return Reply{
			Ok:    false,
			Error: fmt.Sprintf("unknown command %q", cmd.Command),
		}
	}
	p, err := a.profileByName(cmd.Profile)
	if err != nil {
		return Reply{Ok: false, Error: err.Error()}
	}
	for _, allowed := range permitted {
		if allowed == p {
			cmd.Profile = p.cfg.Name
			return a.dispatch(ctx, cmd)
		}
	}
	return Reply{
		Ok: false,
		Error: fmt.Sprintf(
			"kesagent: client is not permitted to control profile %q",
			p.cfg.Name,
		),
	}
}
