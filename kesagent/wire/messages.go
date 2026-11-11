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

package wire

const (
	// ProtocolID is the handshake protocol/version string.
	ProtocolID = "bursa-kes-agent/1"
	// AttestedProtocolID is the protocol spoken by an attested KES workload.
	AttestedProtocolID = "bursa-attested-kes/1"
	// NoEvidenceProvider is the attestation provider for a workload that
	// supplies no platform evidence. The attestation field is empty and the
	// protocol measures nothing; any transport authentication is configured
	// separately on the client and the agent.
	NoEvidenceProvider = "none"
)

// Socket modes for the service socket.
const (
	ModeServeKey = "serve-key"
	ModeSign     = "sign"
)

// Control-socket command names.
const (
	CmdGenStagedKey = "gen-staged-key"
	CmdInstallKey   = "install-key"
	CmdDropKey      = "drop-key"
	CmdInfo         = "info"
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
	// Profile optionally names the profile the header is for. The agent
	// routes a header by its issuer key and operational certificate either
	// way; when set, the routed profile must be this one.
	Profile string `json:"profile,omitempty"`
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
	// Profile names the profile a key command acts on. It may be omitted
	// when the agent has one profile. info without it lists every profile.
	Profile string `json:"profile,omitempty"`
}

// Reply is a control-socket response.
type Reply struct {
	Ok      bool       `json:"ok"`
	Error   string     `json:"error,omitempty"`
	KESVKey []byte     `json:"kes_vkey,omitempty"`
	Info    *AgentInfo `json:"info,omitempty"`
	// Profiles is the status of every profile, returned by info when the
	// agent has several and no profile was named.
	Profiles []AgentInfo `json:"profiles,omitempty"`
}

// AgentInfo is the status snapshot returned by the info command.
type AgentInfo struct {
	Version       string `json:"version"`
	Mode          string `json:"mode"`
	Profile       string `json:"profile,omitempty"`
	HasActiveKey  bool   `json:"has_active_key"`
	ActivePeriod  uint64 `json:"active_period"`   // current absolute KES period of the active key
	ActiveStart   uint64 `json:"active_start"`    // absolute KES period the opcert was issued for
	ActiveEnd     uint64 `json:"active_end"`      // last absolute KES period the key can serve
	ActiveKESVKey []byte `json:"active_kes_vkey"` // 32-byte KES vkey (nil if none)
	// ActiveIssueNumber is the opcert issue counter the agent is serving. It is
	// the field the network uses to decide whether to accept the pool's blocks,
	// so an operator needs it to confirm a rotation actually took effect.
	ActiveIssueNumber uint64 `json:"active_issue_number"`
	// ActiveOpCert is the installed opcert CBOR. In sign mode the producer never
	// receives the key, so this is the only way to confirm the agent and the
	// producer agree on the certificate after a KES rotation.
	ActiveOpCert     []byte `json:"active_opcert,omitempty"`
	StagedKESVKey    []byte `json:"staged_kes_vkey"`   // 32-byte staged KES vkey (nil if none)
	Exhausted        bool   `json:"exhausted"`         // active key has run out of evolutions
	CurrentPeriod    uint64 `json:"current_period"`    // agent's computed current KES period
	MonotonicFloor   uint64 `json:"monotonic_floor"`   // period guard floor
	FloorInitialized bool   `json:"floor_initialized"` // whether the guard floor is set
}

// AttestationRequest is the first client message after the attested protocol
// hello. Nonce must be fresh and exactly 32 bytes. KESVKey and Profile are
// optional and select which profile's key state the server attests: KESVKey
// matches the profile whose active key it is, and Profile, when also set, must
// name that profile. With neither, the server uses its sole profile.
type AttestationRequest struct {
	Type     string `json:"type"`
	Protocol string `json:"protocol"`
	Nonce    []byte `json:"nonce"`
	KESVKey  []byte `json:"kes_vkey,omitempty"`
	Profile  string `json:"profile,omitempty"`
}

// AttestationResponse binds the active KES state to measured-workload
// evidence. The KES signing key is deliberately absent.
type AttestationResponse struct {
	Type        string `json:"type"`
	Protocol    string `json:"protocol"`
	Nonce       []byte `json:"nonce"`
	Provider    string `json:"provider"`
	KESVKey     []byte `json:"kes_vkey,omitempty"`
	OpCert      []byte `json:"opcert,omitempty"`
	Period      uint64 `json:"period,omitempty"`
	Attestation []byte `json:"attestation,omitempty"`
	Error       string `json:"error,omitempty"`
}
