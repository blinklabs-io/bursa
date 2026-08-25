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

package backend

// PKCS11Config is the resolved input to NewPKCS11Backend. It is shared by the
// tagged (CGO) implementation and the pure-Go stub so setup wiring compiles in
// both build configurations. The PIN is resolved from an env var by the wiring
// layer and never read from plaintext config.
type PKCS11Config struct {
	Name       string
	Module     string // filesystem path to the PKCS#11 module (.so)
	TokenLabel string // token label used to select the slot
	Slot       *uint  // explicit slot id (alternative to TokenLabel)
	PIN        string // user PIN (resolved from an env var by the caller)
	// Keys is an optional allowlist: when non-empty, only objects whose
	// CKA_LABEL is listed are loaded, each with the given Cardano key type.
	// When empty, every Ed25519 signing key on the token is loaded as payment.
	Keys []PKCS11KeyConfig
}

// PKCS11KeyConfig maps a PKCS#11 object label to a Cardano key type.
type PKCS11KeyConfig struct {
	Label string
	Type  KeyType
}
