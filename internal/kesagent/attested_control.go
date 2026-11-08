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
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
)

// controlClients maps each client public key in a profile's control list to
// the profiles it may open control sessions for.
func (a *Agent) controlClients() map[[sha256.Size]byte][]*profile {
	out := make(map[[sha256.Size]byte][]*profile)
	for _, p := range a.profiles {
		for _, fingerprint := range p.cfg.ControlClientSPKI {
			out[fingerprint] = append(out[fingerprint], p)
		}
	}
	return out
}

// listedControlProfiles returns the profiles whose control list has the
// client's key; fingerprint is nil for a client without a verified
// certificate.
func (cfg AttestedServiceConfig) listedControlProfiles(
	fingerprint *[sha256.Size]byte,
) []*profile {
	if fingerprint == nil {
		return nil
	}
	return cfg.controlClients[*fingerprint]
}

// controlAnyClient reports whether any profile takes control sessions from
// any client.
func (a *Agent) controlAnyClient() bool {
	for _, p := range a.profiles {
		if p.cfg.ControlAnyClient {
			return true
		}
	}
	return false
}

// controlProfilesFor returns the profiles a client may control: those whose
// control list has it (listed) and those that take any client.
func (a *Agent) controlProfilesFor(listed []*profile) []*profile {
	out := append([]*profile(nil), listed...)
	for _, p := range a.profiles {
		if p.cfg.ControlAnyClient && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// handleRemoteControl serves control commands on an attested session. A
// command acts on the profile it names, which must be one the client is
// listed for; it may name none only when the agent has one profile.
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
		if err := writeFrame(conn, a.dispatchRemote(cmd, permitted)); err != nil {
			a.logger.Debug("remote control write failed", "error", err)
			return
		}
	}
}

func (a *Agent) dispatchRemote(cmd Command, permitted []*profile) Reply {
	switch cmd.Command {
	case CmdGenStagedKey, CmdInstallKey, CmdDropKey, CmdInfo:
	default:
		return Reply{Ok: false, Error: fmt.Sprintf("unknown command %q", cmd.Command)}
	}
	p, err := a.selectProfile(cmd.Profile, nil)
	if err != nil {
		return Reply{Ok: false, Error: err.Error()}
	}
	for _, allowed := range permitted {
		if allowed == p {
			cmd.Profile = p.cfg.Name
			return a.dispatch(cmd)
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
