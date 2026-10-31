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

// Command signlog-verify verifies an armory signing log read from a raw
// microSD card image or block device against the device's pinned identity
// key, and prints one line per entry:
//
//	signlog-verify -identity HEX -image FILE [-head-seq N -head-hash HEX] [-allow-torn-tail]
//
// It checks the header, every signature, the hash chain and contiguous
// sequence numbers, and that nothing but zeros follows the last entry. It
// exits nonzero on any failure, including an incomplete final record unless
// -allow-torn-tail is given. A card cannot be told from an older copy of
// itself by the card alone: -head-seq and -head-hash pin the latest entry
// the operator expects.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/blinklabs-io/bursa/armory/signlog"
)

func printEntry(w io.Writer, e signlog.Entry) {
	if e.SummaryTruncated {
		e.Summary += " [summary truncated]"
	}

	switch e.Purpose {
	case signlog.PurposeOpCertNext:
		fmt.Fprintf(w, "%d %s %s %s issue=%d kes-period=%d kes-vkey-hash=%x %s\n",
			e.Seq, e.Purpose, e.Profile, e.Role, e.IssueCounter, e.KESPeriod, e.KESKeyHash, e.Summary)
	default:
		fmt.Fprintf(w, "%d %s %s %s body=%x %s\n", e.Seq, e.Purpose, e.Profile, e.Role, e.BodyHash, e.Summary)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("signlog-verify", flag.ContinueOnError)
	identityHex := fs.String("identity", "", "device identity public key (hex), pinned")
	image := fs.String("image", "", "raw card image or block device")
	headSeq := fs.Int64("head-seq", -1, "expected number of the latest entry")
	headHash := fs.String("head-hash", "", "expected hash of the latest entry (hex)")
	allowTorn := fs.Bool("allow-torn-tail", false, "accept an incomplete final record")

	if err := fs.Parse(args); err != nil {
		return err
	}

	identity, err := hex.DecodeString(*identityHex)
	if err != nil || len(identity) != ed25519.PublicKeySize {
		return errors.New("-identity must be the 32-byte identity public key in hex")
	}

	if *image == "" {
		return errors.New("-image is required")
	}

	var wantHash []byte

	if *headSeq >= 0 || *headHash != "" {
		if wantHash, err = hex.DecodeString(*headHash); err != nil || len(wantHash) != signlog.HashSize || *headSeq < 0 {
			return errors.New("-head-seq and a 32-byte hex -head-hash must be given together")
		}
	}

	f, err := os.Open(*image)
	if err != nil {
		return err
	}

	defer f.Close()

	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}

	log, err := signlog.Verify(signlog.NewReaderMedium(f, size), identity)
	torn := errors.Is(err, signlog.ErrTornTail)

	if err != nil && (!torn || !*allowTorn) {
		return err
	}

	for _, e := range log.Entries {
		printEntry(stdout, e)
	}

	head := log.Head()

	if wantHash != nil && (head.Seq != uint64(*headSeq) || head.Hash != [signlog.HashSize]byte(wantHash)) { //nolint:gosec // headSeq is non-negative here
		return fmt.Errorf("latest entry is %d %x, expected %d %x", head.Seq, head.Hash, *headSeq, wantHash)
	}

	fmt.Fprintf(stdout, "ok: %d entries, head %d %x\n", len(log.Entries), head.Seq, head.Hash)

	if torn {
		fmt.Fprintln(stdout, "warning: incomplete final record ignored (torn write)")
	}

	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "signlog-verify:", err)
		os.Exit(1)
	}
}
