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
	"io/fs"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
)

func pathErr(path string, cause error) error {
	return &fs.PathError{Op: "open", Path: path, Err: cause}
}

// A permission error on one device must not be masked by a later not-exist:
// the UI guidance differs completely (fix tss group vs. no TPM present).
func TestOpenFirstDevicePreservesPermissionError(t *testing.T) {
	cases := map[string]map[string]error{
		"permission then not-exist": {
			"/dev/tpmrm0": pathErr("/dev/tpmrm0", fs.ErrPermission),
			"/dev/tpm0":   pathErr("/dev/tpm0", fs.ErrNotExist),
		},
		"not-exist then permission": {
			"/dev/tpmrm0": pathErr("/dev/tpmrm0", fs.ErrNotExist),
			"/dev/tpm0":   pathErr("/dev/tpm0", fs.ErrPermission),
		},
	}
	for name, failures := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := openFirstDevice(func(dev string) (transport.TPMCloser, error) {
				return nil, failures[dev]
			}, linuxTPMDevices)
			if err == nil {
				t.Fatal("openFirstDevice should error when every device fails")
			}
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("error must wrap ErrUnavailable, got %v", err)
			}
			if !errors.Is(err, fs.ErrPermission) {
				t.Fatalf("permission error must survive the probe loop, got %v", err)
			}
			if got := reasonFor(err); !strings.Contains(got, "tss group") {
				t.Fatalf("reasonFor(%v) = %q, want tss group guidance", err, got)
			}
		})
	}
}

func TestOpenFirstDeviceAllNotExistReportsNoDevice(t *testing.T) {
	_, err := openFirstDevice(func(dev string) (transport.TPMCloser, error) {
		return nil, pathErr(dev, fs.ErrNotExist)
	}, linuxTPMDevices)
	if err == nil {
		t.Fatal("openFirstDevice should error when every device fails")
	}
	if got := reasonFor(err); !strings.Contains(got, "no TPM device") {
		t.Fatalf("reasonFor(%v) = %q, want no-TPM-device reason", err, got)
	}
}

func TestOpenFirstDeviceReturnsFirstSuccess(t *testing.T) {
	stub := &closerStub{}
	tp, err := openFirstDevice(func(dev string) (transport.TPMCloser, error) {
		if dev == "/dev/tpmrm0" {
			return nil, pathErr(dev, fs.ErrPermission)
		}
		return stub, nil
	}, linuxTPMDevices)
	if err != nil {
		t.Fatalf("openFirstDevice = %v, want fallback success on /dev/tpm0", err)
	}
	if tp != stub {
		t.Fatal("openFirstDevice should return the opened transport")
	}
}
