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

package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"

	"github.com/blinklabs-io/bursa/armory/device"
	"github.com/blinklabs-io/bursa/armory/signlog"
)

// readLog posts one signing log read, authenticating it with the host key
// when the session has one.
func (s *session) readLog(from uint64, count uint32) (device.SignLogResponse, error) {
	nonce, err := randomNonce()
	if err != nil {
		return device.SignLogResponse{}, err
	}

	req := device.SignLogRequest{From: from, Count: count, Nonce: nonce}

	if s.hostKey != nil {
		var ch device.ChallengeResponse

		if err := s.c.post("/v1/challenge", struct{}{}, &ch); err != nil {
			return device.SignLogResponse{}, err
		}

		req.Challenge = ch.Challenge
		req.HostKey = s.hostKey.Public().(ed25519.PublicKey)
		req.HostSignature = ed25519.Sign(s.hostKey, device.SignLogBinding(req))
	}

	var resp device.SignLogResponse

	if err := s.c.post("/v1/signlog", req, &resp); err != nil {
		return resp, err
	}

	if count == 0 && (len(resp.Attestation) != ed25519.SignatureSize ||
		!ed25519.Verify(s.identity, device.SignLogResponseBinding(req, resp), resp.Attestation)) {
		return resp, errors.New("signing log snapshot attestation does not verify under the pinned identity key")
	}

	if resp.Version != device.Protocol {
		return resp, fmt.Errorf("response version %q, want %q", resp.Version, device.Protocol)
	}

	if resp.From != from || len(resp.Blocks) != int(count)*signlog.BlockSize || len(resp.HeadHash) != signlog.HashSize {
		return resp, errors.New("malformed signing log response")
	}

	return resp, nil
}

// fetchLog reads the used part of the device's log, verifies it under the
// pinned identity key and checks it against the head the device reports.
// The device's head is not a pin by itself: a host that holds the expected
// head compares with that.
func (s *session) fetchLog() (*signlog.Log, error) {
	first, err := s.readLog(0, 0)
	if err != nil {
		return nil, err
	}

	// the device reports the head; bound the read by what a device formats
	if first.HeadSeq > signlog.DefaultMaxEntries {
		return nil, fmt.Errorf("device reports entry %d, beyond the log's capacity of %d", first.HeadSeq, signlog.DefaultMaxEntries)
	}

	// one slot beyond the head shows an entry written but not yet headed
	slots := first.HeadSeq + 1
	want := min(first.NumBlocks, 1+slots*signlog.RecordBlocks)

	var prefix []byte

	for uint64(len(prefix))/signlog.BlockSize < want {
		from := uint64(len(prefix)) / signlog.BlockSize
		count := uint32(min(uint64(device.MaxLogBlocks), want-from)) //nolint:gosec // bounded by MaxLogBlocks

		part, err := s.readLog(from, count)
		if err != nil {
			return nil, err
		}

		if part.NumBlocks != first.NumBlocks {
			return nil, errors.New("device changed its signing log medium during the read")
		}

		prefix = append(prefix, part.Blocks...)
	}

	m, err := signlog.NewSparseMedium(first.NumBlocks, prefix)
	if err != nil {
		return nil, err
	}

	log, err := signlog.Verify(m, s.identity)
	if err != nil {
		return nil, err
	}

	head := log.Head()
	if head.Seq != first.HeadSeq || !bytes.Equal(head.Hash[:], first.HeadHash) {
		return nil, fmt.Errorf("log ends at entry %d %x but the device reports %d %x (retry if it signed meanwhile)",
			head.Seq, head.Hash, first.HeadSeq, first.HeadHash)
	}

	return log, nil
}

// signLog prints the verified log and, when pinSeq is not negative, checks
// its head against the pinned one.
func (s *session) signLog(pinSeq int64, pinHash []byte, out io.Writer) error {
	log, err := s.fetchLog()
	if err != nil {
		return err
	}

	head := log.Head()

	if pinSeq >= 0 && (head.Seq != uint64(pinSeq) || !bytes.Equal(head.Hash[:], pinHash)) { //nolint:gosec // pinSeq is non-negative here
		return fmt.Errorf("latest entry is %d %x, expected %d %x", head.Seq, head.Hash, pinSeq, pinHash)
	}

	for _, e := range log.Entries {
		fmt.Fprintln(out, signlog.FormatEntry(e))
	}

	fmt.Fprintf(out, "ok: %d entries, head %d %x\n", len(log.Entries), head.Seq, head.Hash)

	return nil
}
