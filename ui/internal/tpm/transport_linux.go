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

//go:build linux

package tpm

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// linuxTPMDevices is the preferred-first list of device files. The kernel
// resource-manager device (/dev/tpmrm0) multiplexes access and handles context
// gap/save; the raw device (/dev/tpm0) is the fallback for older kernels.
var linuxTPMDevices = []string{"/dev/tpmrm0", "/dev/tpm0"}

// openDevice opens the first reachable Linux TPM device. It does not issue any
// TPM command — it only opens the device file (cheap, side-effect-free). The
// open error is wrapped in ErrUnavailable so callers fall back cleanly.
func openDevice() (transport.TPMCloser, error) {
	return openFirstDevice(linuxtpm.Open, linuxTPMDevices)
}

// openFirstDevice probes devs in order with open, returning the first success.
// When every probe fails, a permission error is preserved over any other — a
// device that exists but is unreadable must surface the fix-your-group
// guidance, not a later "no such file" from a device that was never there.
func openFirstDevice(
	open func(string) (transport.TPMCloser, error),
	devs []string,
) (transport.TPMCloser, error) {
	var keptErr error
	for _, dev := range devs {
		tp, err := open(dev)
		if err == nil {
			return tp, nil
		}
		if keptErr == nil || !errors.Is(keptErr, fs.ErrPermission) {
			keptErr = err
		}
	}
	if keptErr == nil {
		keptErr = ErrUnavailable
	}
	return nil, fmt.Errorf("%w: %w", ErrUnavailable, keptErr)
}

// reasonFor maps an open error to a human-readable availability reason,
// distinguishing the two common Linux causes so the UI can guide the user.
func reasonFor(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "no TPM device (/dev/tpmrm0, /dev/tpm0)"
	case errors.Is(err, fs.ErrPermission), errors.Is(err, os.ErrPermission):
		return "permission denied: add your user to the tss group"
	default:
		return "TPM unavailable: " + unavailableReason(err)
	}
}
