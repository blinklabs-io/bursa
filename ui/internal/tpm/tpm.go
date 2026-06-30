// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package tpm is the platform-gated seam to a local TPM 2.0 device. It exposes a
// cheap, side-effect-free capability probe (Available) and a transport Opener
// that yields a go-tpm transport.TPMCloser for the seal/unseal flow used by the
// vault's TPM key protector.
//
// The real device is reached only on the supported desktop/server platforms
// (Linux via /dev/tpmrm0 -> /dev/tpm0, Windows via TBS). Every other GOOS
// (darwin, freebsd, android, ...) compiles against a stub whose Available always
// reports false and whose Open always errors, so the feature builds CGO-free on
// every target in the matrix and falls back to the password-only path there.
//
// All transports here are pure Go (no cgo). The probe must never panic and must
// never block: it does the cheapest possible open and immediately closes.
package tpm

import (
	"errors"
	"strings"

	"github.com/google/go-tpm/tpm2/transport"
)

// ErrUnavailable is the sentinel returned by Open when no usable TPM is present
// (no device, permission denied, unsupported platform). Callers fall back to the
// password protector on this — it must never brick a vault.
var ErrUnavailable = errors.New("tpm: not available")

func unavailableReason(err error) string {
	if err == nil {
		return ""
	}
	return strings.TrimPrefix(err.Error(), ErrUnavailable.Error()+": ")
}

// Opener returns a live connection to the TPM. Production uses Open (the
// platform device); tests inject a fake that returns an in-memory transport so
// the seal/unseal command path runs under CGO_ENABLED=0 without real hardware.
type Opener func() (transport.TPMCloser, error)

// Open connects to the local TPM 2.0 device on supported platforms. On
// unsupported platforms, or when no device is reachable, it returns an error
// wrapping ErrUnavailable. The concrete implementation is selected by build tag
// (transport_linux.go, transport_windows.go, transport_stub.go).
func Open() (transport.TPMCloser, error) {
	return openDevice()
}

// Available reports whether a TPM can be used in the current environment, with a
// human-readable reason when it cannot (e.g. "no TPM device", "permission
// denied: add your user to the tss group", "TPM not supported on this
// platform"). The probe is cheap and side-effect-free: it opens the device and
// immediately closes it, issuing no TPM commands. It never panics and never
// blocks vault unlock.
//
// availableVia lets callers (and tests) supply the Opener to probe; Available
// uses the production Open.
func Available() (bool, string) {
	return availableVia(Open)
}

// availableVia probes availability using the supplied Opener. A nil/erroring
// Opener yields (false, reason); a successful open is immediately closed.
func availableVia(open Opener) (bool, string) {
	if open == nil {
		return false, "tpm: no opener"
	}
	tp, err := open()
	if err != nil {
		return false, reasonFor(err)
	}
	// A nil transport with no error (a misbehaving/test Opener) must not reach
	// Close — that would panic and break the never-panic contract of the probe.
	if tp == nil {
		return false, "tpm: opener returned nil transport"
	}
	// Close immediately — the probe must be side-effect-free. A close error is
	// not fatal to availability; the device opened.
	_ = tp.Close()
	return true, ""
}
