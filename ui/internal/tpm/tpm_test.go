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

package tpm

import (
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
)

// closerStub is a no-op transport.TPMCloser used to prove Available closes what
// it opens without issuing any TPM command.
type closerStub struct{ closed bool }

func (c *closerStub) Send([]byte) ([]byte, error) { return nil, errors.New("not used") }
func (c *closerStub) Close() error                { c.closed = true; return nil }

func TestAvailableViaSuccess(t *testing.T) {
	stub := &closerStub{}
	ok, reason := availableVia(func() (transport.TPMCloser, error) { return stub, nil })
	if !ok {
		t.Fatalf("availableVia success = (false, %q), want true", reason)
	}
	if !stub.closed {
		t.Fatal("availableVia must close the transport it opened (side-effect-free probe)")
	}
}

func TestAvailableViaOpenError(t *testing.T) {
	ok, reason := availableVia(func() (transport.TPMCloser, error) {
		return nil, errors.New("no device")
	})
	if ok {
		t.Fatal("availableVia should report unavailable when Open errors")
	}
	if reason == "" {
		t.Fatal("availableVia should give a non-empty reason on failure")
	}
}

func TestAvailableViaNilOpener(t *testing.T) {
	ok, _ := availableVia(nil)
	if ok {
		t.Fatal("availableVia(nil) must report unavailable, not panic")
	}
}

// TestAvailableNeverPanics exercises the production probe. On a CI box with no
// TPM (or no permission) it must simply report unavailable, never panic or
// block.
func TestAvailableNeverPanics(t *testing.T) {
	// The result depends on the host; we only assert it returns and, when
	// unavailable, carries a reason.
	ok, reason := Available()
	if !ok && reason == "" {
		t.Fatal("Available() unavailable result must carry a reason")
	}
}
