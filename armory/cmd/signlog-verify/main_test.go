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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/armory/signlog"
)

// card writes an image holding n entries of a fresh device to a file and
// returns the path with the identity key in hex.
func card(t *testing.T, n int) (path, identity string, pub ed25519.PublicKey, w *signlog.Writer, m *signlog.MemMedium) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	m = signlog.NewMemMedium(1 + 8*signlog.RecordBlocks)

	w, err = signlog.Open(m, signlog.NewMemHeadStore(signlog.Head{}), signlog.NewKeySigner(priv))
	if err != nil {
		t.Fatal(err)
	}

	for i := range n {
		rec := signlog.Record{
			Profile: "otg@preview", Role: "stake", Purpose: signlog.PurposeTxBody,
			BodyHash: bytes.Repeat([]byte{byte(i + 1)}, 32), Summary: "fee=170000",
		}
		if i%2 == 1 {
			rec = signlog.Record{
				Profile: "otg@preview", Role: "pool", Purpose: signlog.PurposeOpCertNext,
				IssueCounter: 5, KESPeriod: 700, KESKeyHash: bytes.Repeat([]byte{0xab}, 32),
				Summary: "chain 4 issue 5 period 700",
			}
		}

		if _, err = w.Append(rec); err != nil {
			t.Fatal(err)
		}
	}

	path = filepath.Join(t.TempDir(), "card.img")
	if err = os.WriteFile(path, m.Image(), 0o600); err != nil {
		t.Fatal(err)
	}

	return path, hex.EncodeToString(pub), pub, w, m
}

func TestVerifyPrintsEntries(t *testing.T) {
	t.Parallel()

	path, id, _, w, _ := card(t, 3)

	var out bytes.Buffer
	if err := run([]string{"-identity", id, "-image", path}, &out); err != nil {
		t.Fatalf("run: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("got %d lines, want 3 entries and a summary:\n%s", len(lines), out.String())
	}

	for i, want := range []string{"tx-body", "opcert-next", "tx-body"} {
		if !strings.HasPrefix(lines[i], []string{"1 ", "2 ", "3 "}[i]) || !strings.Contains(lines[i], want) ||
			!strings.Contains(lines[i], "otg@preview") {
			t.Errorf("line %d: %q", i, lines[i])
		}
	}

	if !strings.Contains(lines[0], hex.EncodeToString(bytes.Repeat([]byte{1}, 32))) ||
		!strings.Contains(lines[0], "fee=170000") {
		t.Errorf("tx-body line lacks the body hash or summary: %q", lines[0])
	}

	if !strings.Contains(lines[1], "issue=5") || !strings.Contains(lines[1], "kes-period=700") ||
		!strings.Contains(lines[1], hex.EncodeToString(bytes.Repeat([]byte{0xab}, 32))) {
		t.Errorf("opcert line lacks counters or KES key hash: %q", lines[1])
	}

	head := w.Head()
	if !strings.Contains(lines[3], "3 entries") || !strings.Contains(lines[3], hex.EncodeToString(head.Hash[:])) {
		t.Errorf("summary line %q", lines[3])
	}
}

func TestVerifyRefusals(t *testing.T) {
	t.Parallel()

	path, id, _, _, m := card(t, 3)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	tampered := m.Image()
	tampered[(1+signlog.RecordBlocks)*signlog.BlockSize+40] ^= 1
	tamperedPath := filepath.Join(t.TempDir(), "tampered.img")

	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	torn := m.Image()
	clear(torn[(1+2*signlog.RecordBlocks)*signlog.BlockSize+signlog.BlockSize:][:signlog.BlockSize*3])
	tornPath := filepath.Join(t.TempDir(), "torn.img")

	if err := os.WriteFile(tornPath, torn, 0o600); err != nil {
		t.Fatal(err)
	}

	for name, args := range map[string][]string{
		"wrong identity":  {"-identity", hex.EncodeToString(otherPub), "-image", path},
		"tampered":        {"-identity", id, "-image", tamperedPath},
		"torn tail":       {"-identity", id, "-image", tornPath},
		"missing image":   {"-identity", id, "-image", path + ".none"},
		"no identity":     {"-image", path},
		"short identity":  {"-identity", "abcd", "-image", path},
		"no image":        {"-identity", id},
		"head too old":    {"-identity", id, "-image", path, "-head-seq", "4", "-head-hash", strings.Repeat("00", 32)},
		"head hash wrong": {"-identity", id, "-image", path, "-head-seq", "3", "-head-hash", strings.Repeat("00", 32)},
		// a positional token stops flag parsing; the pin after it must not vanish
		"pin after argument": {"-identity", id, "-image", path, "unexpected", "-head-seq", "4", "-head-hash", strings.Repeat("00", 32)},
	} {
		var out bytes.Buffer
		if err := run(args, &out); err == nil {
			t.Errorf("%s: run succeeded:\n%s", name, out.String())
		}
	}
}

func TestVerifyTornTailAllowed(t *testing.T) {
	t.Parallel()

	_, id, _, _, m := card(t, 3)

	torn := m.Image()
	clear(torn[(1+2*signlog.RecordBlocks)*signlog.BlockSize+signlog.BlockSize:][:signlog.BlockSize*3])

	path := filepath.Join(t.TempDir(), "torn.img")
	if err := os.WriteFile(path, torn, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := run([]string{"-identity", id, "-image", path, "-allow-torn-tail"}, &out); err != nil {
		t.Fatalf("run: %v", err)
	}

	if !strings.Contains(out.String(), "torn") || !strings.Contains(out.String(), "2 entries") {
		t.Errorf("output does not report the torn tail:\n%s", out.String())
	}
}

func TestVerifyHeadPin(t *testing.T) {
	t.Parallel()

	path, id, _, w, _ := card(t, 3)
	head := w.Head()

	var out bytes.Buffer
	if err := run([]string{
		"-identity", id, "-image", path,
		"-head-seq", "3", "-head-hash", hex.EncodeToString(head.Hash[:]),
	}, &out); err != nil {
		t.Fatalf("run: %v", err)
	}
}

func TestExitCode(t *testing.T) {
	t.Parallel()

	path, id, _, _, _ := card(t, 2)

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	run := func(identity string) error {
		cmd := exec.Command(exe, "-test.run=^TestHelperMain$")
		cmd.Env = append(os.Environ(), "SIGNLOG_VERIFY_HELPER=1",
			"SIGNLOG_VERIFY_ARGS=-identity="+identity+" -image="+path)

		return cmd.Run()
	}

	if err := run(id); err != nil {
		t.Fatalf("valid card: %v", err)
	}

	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	err = run(hex.EncodeToString(otherPub))

	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("wrong identity: got %v, want exit status 1", err)
	}
}

// TestHelperMain runs main when re-executed by TestExitCode.
func TestHelperMain(t *testing.T) {
	if os.Getenv("SIGNLOG_VERIFY_HELPER") != "1" {
		t.Skip("helper for TestExitCode")
	}

	os.Args = append([]string{"signlog-verify"}, strings.Fields(os.Getenv("SIGNLOG_VERIFY_ARGS"))...)
	main()
}

func TestVerifyShowsTruncatedSummary(t *testing.T) {
	t.Parallel()

	path, id, _, w, m := card(t, 1)

	if _, err := w.Append(signlog.Record{
		Profile: "otg@preview", Role: "stake", Purpose: signlog.PurposeTxBody,
		BodyHash: bytes.Repeat([]byte{9}, 32), Summary: strings.Repeat("x", signlog.MaxSummary+1),
	}); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, m.Image(), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := run([]string{"-identity", id, "-image", path}, &out); err != nil {
		t.Fatalf("run: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if strings.Contains(lines[0], "truncated") || !strings.Contains(lines[1], "[summary truncated]") {
		t.Errorf("truncation marks wrong:\n%s", out.String())
	}
}
