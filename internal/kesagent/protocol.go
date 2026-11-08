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

// Package kesagent implements a KES (Key Evolving Signature) agent daemon: a
// Go replica of IOG's kes-agent, serving a Go block producer (dingo) rather
// than cardano-node.
//
// The agent holds the block-production KES signing key in locked (mlock'd)
// secure memory, evolves it forward-securely each KES period, and serves it to
// the producer over Unix-domain sockets. The pool cold signing key never
// touches the agent; the agent holds only the cold verification key and the
// operational certificate the cold signer issued.
//
// # Wire format
//
// The types and framing are defined in the public kesagent/wire package.
//
// Both the service socket and the control socket speak the same framed
// message protocol:
//
//	frame = uint32(len, big-endian) || payload
//	payload = JSON object (UTF-8)
//
// The maximum payload length is maxFrameLen (1 MiB); larger frames are
// rejected. []byte fields are base64-encoded by encoding/json.
//
// # Handshake
//
// Immediately after a client connects the server sends a Hello frame
// describing the protocol version and the socket mode:
//
//	{"protocol":"bursa-kes-agent/1","mode":"serve-key"|"sign"}
//
// A client MUST verify the protocol string before proceeding.
//
// # Service socket, serve-key mode
//
// After the Hello, and whenever the active key becomes available, evolves, or
// is (re)installed, the server pushes a KeyPush frame:
//
//	{"type":"key_push","period":<abs KES period>,"depth":6,
//	 "kes_sign_key":<b64 raw KES secret key bytes>,
//	 "kes_vkey":<b64 32-byte KES verification key>,
//	 "opcert":<b64 CBOR operational certificate>}
//
// The client consumes frames; it sends nothing.
//
// # Service socket, sign mode
//
// After the Hello the client sends SignRequest frames and the server replies
// with a SignResponse for each; the KES key never leaves the agent:
//
//	-> {"type":"sign_request","period":<abs KES period>,"message":<b64>}
//	<- {"type":"sign_response","period":<abs>,"signature":<b64>,"error":""}
//
// # Control socket
//
// The control socket is request/response. Each request is a Command frame and
// the server replies with a Reply frame:
//
//	-> {"command":"gen-staged-key"}
//	<- {"ok":true,"kes_vkey":<b64>}
//
//	-> {"command":"install-key","opcert":<b64 CBOR opcert>}
//	<- {"ok":true,"info":{...}}
//
//	-> {"command":"drop-key","target":"active"|"staged"|"all"}
//	<- {"ok":true}
//
//	-> {"command":"info"}
//	<- {"ok":true,"info":{...}}
//
// The agent validates an installed opcert against the configured cold
// verification key (cold-signature check), confirms it commits to the
// staged/active KES verification key, and checks the KES period is sane before
// promoting the staged key to active and serving it. The agent never issues an
// opcert; that stays with the cold signer / cardano-cli.
package kesagent

import "github.com/blinklabs-io/bursa/kesagent/wire"

// The wire protocol lives in the public kesagent/wire package; these aliases
// keep the agent code and its callers unchanged.
const (
	// ProtocolID is the handshake protocol/version string.
	ProtocolID = wire.ProtocolID

	maxFrameLen    = wire.MaxFrameLen
	frameIOTimeout = wire.FrameIOTimeout

	// Socket modes for the service socket.
	ModeServeKey = wire.ModeServeKey
	ModeSign     = wire.ModeSign

	// Control command names.
	CmdGenStagedKey = wire.CmdGenStagedKey
	CmdInstallKey   = wire.CmdInstallKey
	CmdDropKey      = wire.CmdDropKey
	CmdInfo         = wire.CmdInfo

	// AttestedProtocolID is the protocol spoken by an attested KES workload.
	AttestedProtocolID = wire.AttestedProtocolID
	// NoEvidenceProvider is the attestation provider for a workload that
	// supplies no platform evidence.
	NoEvidenceProvider = wire.NoEvidenceProvider
)

type (
	Hello               = wire.Hello
	KeyPush             = wire.KeyPush
	SignRequest         = wire.SignRequest
	SignResponse        = wire.SignResponse
	Command             = wire.Command
	Reply               = wire.Reply
	AgentInfo           = wire.AgentInfo
	AttestationRequest  = wire.AttestationRequest
	AttestationResponse = wire.AttestationResponse
)

func writeFrame(w wire.DeadlineWriter, v any) error { return wire.WriteFrame(w, v) }
func readFrame(r wire.DeadlineReader, v any) error  { return wire.ReadFrame(r, v) }
