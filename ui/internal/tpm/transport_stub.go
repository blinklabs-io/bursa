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

//go:build !linux && !windows

// This stub covers every non-desktop/server platform in the build matrix
// (darwin, freebsd, android via gomobile, and any other GOOS). It pulls in NO
// go-tpm transport package, so it adds no platform-specific dependency and keeps
// the build CGO-free everywhere. The TPM is always reported unavailable here, so
// the vault uses the password-only fallback path.

package tpm

import (
	"fmt"

	"github.com/google/go-tpm/tpm2/transport"
)

// openDevice always fails on unsupported platforms: there is no user-accessible
// TPM on macOS, and FreeBSD/mobile targets are explicitly fallback-only.
func openDevice() (transport.TPMCloser, error) {
	return nil, fmt.Errorf("%w: TPM not supported on this platform", ErrUnavailable)
}

// reasonFor reports the reason wrapped by openDevice without duplicating it.
func reasonFor(err error) string {
	return unavailableReason(err)
}
