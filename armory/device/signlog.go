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

package device

import (
	"errors"
	"fmt"

	"github.com/blinklabs-io/bursa/armory/signlog"
)

// SigningLog is the durable record the service appends to before it releases
// a signature. *signlog.Writer implements it.
type SigningLog interface {
	Append(signlog.Record) (signlog.Entry, error)
	Head() signlog.Head
}

var (
	errLogUnavailable = errors.New("signing log unavailable")
	errLogFull        = errors.New("signing log is full; the device refuses to sign")
	errLogWrite       = errors.New("signing log write failed; the device refuses to sign")
)

// RequireSigningLog makes the service refuse every signing request until
// SetSigningLog installs a log, so a device that could not open its log does
// not sign. Inventory, challenges and provisioning are not affected. Call it
// before SetChip.
func (s *Service) RequireSigningLog() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logRequired = true
}

// SetSigningLog installs the log every signature is recorded in. medium is
// the block device holding it, served read-only to the host.
func (s *Service) SetSigningLog(l SigningLog, medium signlog.Medium) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.log, s.logMedium, s.logErr = l, medium, nil
}

// SigningLogFailed records why the log could not be opened; signing requests
// are refused with this reason while the log is required and not installed.
func (s *Service) SigningLogFailed(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logErr = err
}

// logReady reports why a signing request must be refused for want of a log.
func (s *Service) logReady() error {
	if s.log != nil || !s.logRequired {
		return nil
	}

	if s.logErr != nil {
		return fmt.Errorf("%w: %w", errLogUnavailable, s.logErr)
	}

	return fmt.Errorf("%w: not open", errLogUnavailable)
}

// appendLog records rec before the signature it describes is made. Any error
// refuses the request.
func (s *Service) appendLog(rec signlog.Record) error {
	if err := s.logReady(); err != nil {
		return err
	}

	if s.log == nil {
		return nil
	}

	if _, err := s.log.Append(rec); err != nil {
		s.logf("signing log: append: %v", err)

		if errors.Is(err, signlog.ErrFull) {
			return errLogFull
		}

		return errLogWrite
	}

	return nil
}
