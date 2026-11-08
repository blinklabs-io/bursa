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

// Package wire defines the KES agent wire protocol: the framing, the
// handshake, and the messages exchanged with a bursa KES agent over its
// service, attested and control sockets.
//
// Stability: the package is wire-compatible within the protocol version
// bursa-attested-kes/1 (AttestedProtocolID) and bursa-kes-agent/1
// (ProtocolID). Existing JSON field names and meanings do not change; new
// fields are added only as optional ones. Decoders must be lenient and ignore
// unknown fields, so older peers tolerate additions. An incompatible change
// takes a new protocol string.
//
// # Framing
//
//	frame = uint32(len, big-endian) || payload
//	payload = JSON object (UTF-8)
//
// The maximum payload length is MaxFrameLen (1 MiB). []byte fields are
// base64-encoded by encoding/json. WriteFrame and ReadFrame apply
// FrameIOTimeout to each frame.
//
// # Handshake
//
// The server sends a Hello frame first. A client MUST verify the protocol
// string before proceeding.
//
// # Service socket
//
// In ModeServeKey the server pushes KeyPush frames and the client sends
// nothing. In ModeSign the client sends SignRequest frames and the server
// answers each with a SignResponse; the KES key never leaves the agent.
//
// # Attested service
//
// After a Hello with AttestedProtocolID in ModeSign, the client sends an
// AttestationRequest carrying a fresh 32-byte nonce and the server answers
// with an AttestationResponse. For the NoEvidenceProvider the response carries no
// attestation; otherwise Attestation holds provider evidence that commits to
// AttestationBinding. Sign requests follow on the same connection.
//
// # Control socket
//
// Each request is a Command frame answered by a Reply frame.
package wire
