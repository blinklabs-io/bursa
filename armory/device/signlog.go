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
	"golang.org/x/crypto/blake2b"
)

// SigningLog is the durable record the service appends to before it releases
// a signature. *signlog.Writer implements it.
type SigningLog interface {
	Append(signlog.Record) (signlog.Entry, error)
	Head() signlog.Head
}

// MaxLogBlocks bounds the blocks one signing log read returns.
const MaxLogBlocks = 128

// SignLogRequest reads Count blocks of the signing log medium from block
// From. The medium is the raw card: block 0 is the header and each entry
// follows in a slot of signlog.RecordBlocks blocks. Only blocks up to the end
// of the slot after the head are served. It is authenticated like a
// signing request: the host key signs SignLogBinding over the request and a
// challenge from /v1/challenge.
type SignLogRequest struct {
	From          uint64 `json:"from"`
	Count         uint32 `json:"count"`
	Challenge     []byte `json:"challenge,omitempty"`
	HostKey       []byte `json:"host_key,omitempty"`
	HostSignature []byte `json:"host_signature,omitempty"`
}

// SignLogResponse returns the blocks with the device's current head and the
// medium's size in blocks. The head is the pin: a host verifies the blocks
// with signlog.Verify under the pinned identity key and compares the log's
// head with this one.
type SignLogResponse struct {
	Version   string `json:"version"`
	HeadSeq   uint64 `json:"head_seq"`
	HeadHash  []byte `json:"head_hash"`
	NumBlocks uint64 `json:"num_blocks"`
	From      uint64 `json:"from"`
	Blocks    []byte `json:"blocks"`
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

// signLogRead serves a range of the log medium. Reads and appends share the
// service lock, so the blocks and the head are one consistent view.
func (s *Service) signLogRead(req SignLogRequest) (SignLogResponse, error) {
	if err := s.authenticateHost(req.HostKey, req.HostSignature, req.Challenge, SignLogBinding(req)); err != nil {
		return SignLogResponse{}, err
	}

	if s.log == nil || s.logMedium == nil {
		if err := s.logReady(); err != nil {
			return SignLogResponse{}, err
		}

		return SignLogResponse{}, fmt.Errorf("%w: none installed", errLogUnavailable)
	}

	n := s.logMedium.NumBlocks()

	if req.Count > MaxLogBlocks {
		return SignLogResponse{}, fmt.Errorf("at most %d blocks per read", MaxLogBlocks)
	}

	// only the header, the entries and the slot after the head are served:
	// the rest of the card holds no entry
	head := s.log.Head()
	limit := min(n, 1+(head.Seq+1)*signlog.RecordBlocks)

	if req.From > limit || uint64(req.Count) > limit-req.From {
		return SignLogResponse{}, fmt.Errorf("blocks %d+%d are outside the %d blocks the log uses", req.From, req.Count, limit)
	}

	resp := SignLogResponse{Version: Protocol, NumBlocks: n, From: req.From}
	resp.HeadSeq, resp.HeadHash = head.Seq, head.Hash[:]
	resp.Blocks = make([]byte, int(req.Count)*signlog.BlockSize)

	if req.Count > 0 {
		if err := s.logMedium.ReadBlocks(req.From, resp.Blocks); err != nil {
			s.logf("signing log: read blocks %d+%d: %v", req.From, req.Count, err)
			return SignLogResponse{}, errDevice
		}
	}

	return resp, nil
}

// RecordRaw logs an unfiltered signature over msg, for the testnet bring-up
// build's /sign endpoint, and returns an error when the signature must be
// refused. The caller holds the lock it shares with the service and signs
// only when RecordRaw returns nil.
func (s *Service) RecordRaw(msg []byte) error {
	hash := blake2b.Sum256(msg)

	return s.appendLog(signlog.Record{
		Role: "cold", Purpose: signlog.PurposeRaw, BodyHash: hash[:],
		Summary: "unfiltered testnet signing",
	})
}
