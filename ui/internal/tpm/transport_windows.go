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

//go:build windows

package tpm

import (
	"fmt"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

// openDevice opens the Windows TPM via TBS (TPM Base Services), a pure-Go
// syscall wrapper around tbs.dll — no cgo. Any failure (no TPM 2.0, TBS error)
// is wrapped in ErrUnavailable so the caller falls back to the password path.
func openDevice() (transport.TPMCloser, error) {
	tp, err := windowstpm.Open()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return tp, nil
}

// reasonFor maps a Windows open error to a human-readable reason.
func reasonFor(err error) string {
	return fmt.Sprintf("TPM unavailable: %s", unavailableReason(err))
}
