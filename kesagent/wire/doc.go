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

// Package wire defines the bursa KES agent wire protocol: the frame types,
// protocol, mode and command constants, frame length limits, and the
// length-prefixed JSON framing. It is shared by the agent
// (internal/kesagent) and by block producers that speak to it.
//
// The package sets no I/O deadlines; callers own them.
//
// # Framing
//
//	frame = uint32(len, big-endian) || payload
//	payload = JSON object (UTF-8)
//
// ReadFrameLimit and WriteFrameLimit take the maximum payload length from the
// caller, capped at MaxFrameLen. ReadFrameLimit accepts an optional body guard
// that runs between the header and the body, where a caller can bound the body
// read. A zero-length frame is a protocol error. []byte fields are
// base64-encoded by encoding/json. MaxFrameLen is the agent's own limit;
// MaxHelloFrameLen, MaxKeyPushFrameLen and MaxSignFrameLen are suggested
// per-message limits for clients.
//
// # Handshake
//
// Immediately after a client connects the server sends a Hello frame
// carrying ProtocolID (or AttestedProtocolID) and the socket mode. A client
// MUST verify the protocol string before proceeding.
//
// # Service socket
//
// In ModeServeKey the server pushes KeyPush frames and the client sends
// nothing. In ModeSign the client sends SignRequest frames and the server
// replies with a SignResponse for each.
//
// # Attested service
//
// After an AttestedProtocolID Hello the client sends an AttestationRequest
// and the server replies with an AttestationResponse before sign requests are
// admitted.
//
// # Control socket
//
// The control socket is request/response: a Command frame (CmdGenStagedKey,
// CmdInstallKey, CmdDropKey, CmdInfo) is answered by a Reply frame.
//
// See docs/signer/kes-agent-protocol.md for the full specification.
package wire
