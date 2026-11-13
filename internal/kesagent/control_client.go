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
	"fmt"
	"net"
	"time"
)

// ControlRequestTimeout bounds one control request when ctx has no earlier
// deadline. gen-staged-key and install-key can wait on the shared key store.
const ControlRequestTimeout = 30 * time.Second

// ControlRequest sends one command to the agent's control socket at path and
// returns its reply. A command the agent refuses is a reply with Ok false,
// not an error; an error means no reply was read.
func ControlRequest(
	ctx context.Context,
	path string,
	cmd Command,
) (Reply, error) {
	ctx, cancel := context.WithTimeout(ctx, ControlRequestTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return Reply{}, fmt.Errorf("connect to control socket %s: %w", path, err)
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return Reply{}, err
		}
	}
	var hello Hello
	if err := readFrame(conn, &hello); err != nil {
		return Reply{}, fmt.Errorf("read control hello: %w", err)
	}
	if hello.Protocol != ProtocolID {
		return Reply{}, fmt.Errorf(
			"control socket %s speaks %q, not %q",
			path,
			hello.Protocol,
			ProtocolID,
		)
	}
	if err := writeFrame(conn, cmd); err != nil {
		return Reply{}, fmt.Errorf("send %s: %w", cmd.Command, err)
	}
	var reply Reply
	if err := readFrame(conn, &reply); err != nil {
		return Reply{}, fmt.Errorf("read %s reply: %w", cmd.Command, err)
	}
	return reply, nil
}
