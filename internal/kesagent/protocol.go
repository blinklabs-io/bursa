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

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	// ProtocolID is the handshake protocol/version string.
	ProtocolID = "bursa-kes-agent/1"

	// maxFrameLen caps a single frame payload to guard against abuse.
	maxFrameLen = 1 << 20 // 1 MiB
)

// Socket modes for the service socket.
const (
	ModeServeKey = "serve-key"
	ModeSign     = "sign"
)

// Hello is the first frame the server sends after a client connects.
type Hello struct {
	Protocol string `json:"protocol"`
	Mode     string `json:"mode"`
}

// KeyPush is sent by the server in serve-key mode to deliver the current KES
// signing key, its verification key, its absolute KES period, and the
// operational certificate.
type KeyPush struct {
	Type       string `json:"type"` // "key_push"
	Period     uint64 `json:"period"`
	Depth      uint64 `json:"depth"`
	KESSignKey []byte `json:"kes_sign_key"`
	KESVKey    []byte `json:"kes_vkey"`
	OpCert     []byte `json:"opcert"`
}

// SignRequest is sent by the client in sign mode.
type SignRequest struct {
	Type    string `json:"type"` // "sign_request"
	Period  uint64 `json:"period"`
	Message []byte `json:"message"`
}

// SignResponse is the server's reply to a SignRequest.
type SignResponse struct {
	Type      string `json:"type"` // "sign_response"
	Period    uint64 `json:"period"`
	Signature []byte `json:"signature"`
	Error     string `json:"error,omitempty"`
}

// Command is a control-socket request.
type Command struct {
	Command string `json:"command"`
	OpCert  []byte `json:"opcert,omitempty"`
	Target  string `json:"target,omitempty"` // drop-key: active|staged|all
}

// Reply is a control-socket response.
type Reply struct {
	Ok      bool       `json:"ok"`
	Error   string     `json:"error,omitempty"`
	KESVKey []byte     `json:"kes_vkey,omitempty"`
	Info    *AgentInfo `json:"info,omitempty"`
}

// AgentInfo is the status snapshot returned by the info command.
type AgentInfo struct {
	Version          string `json:"version"`
	Mode             string `json:"mode"`
	HasActiveKey     bool   `json:"has_active_key"`
	ActivePeriod     uint64 `json:"active_period"`     // current absolute KES period of the active key
	ActiveStart      uint64 `json:"active_start"`      // absolute KES period the opcert was issued for
	ActiveEnd        uint64 `json:"active_end"`        // last absolute KES period the key can serve
	ActiveKESVKey    []byte `json:"active_kes_vkey"`   // 32-byte KES vkey (nil if none)
	StagedKESVKey    []byte `json:"staged_kes_vkey"`   // 32-byte staged KES vkey (nil if none)
	Exhausted        bool   `json:"exhausted"`         // active key has run out of evolutions
	CurrentPeriod    uint64 `json:"current_period"`    // agent's computed current KES period
	MonotonicFloor   uint64 `json:"monotonic_floor"`   // period guard floor
	FloorInitialized bool   `json:"floor_initialized"` // whether the guard floor is set
}

// writeFrame writes a single length-prefixed JSON frame.
func writeFrame(w io.Writer, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("kesagent: marshal frame: %w", err)
	}
	if len(payload) > maxFrameLen {
		return fmt.Errorf("kesagent: frame too large (%d bytes)", len(payload))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload))) // #nosec G115 -- bounded by maxFrameLen
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("kesagent: write frame header: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("kesagent: write frame payload: %w", err)
	}
	return nil
}

// readFrame reads a single length-prefixed JSON frame into v.
func readFrame(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err // may be io.EOF; callers distinguish
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return errors.New("kesagent: zero-length frame")
	}
	if n > maxFrameLen {
		return fmt.Errorf("kesagent: frame too large (%d bytes)", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return fmt.Errorf("kesagent: read frame payload: %w", err)
	}
	if err := json.Unmarshal(payload, v); err != nil {
		return fmt.Errorf("kesagent: unmarshal frame: %w", err)
	}
	return nil
}
