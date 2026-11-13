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
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bursa "github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/kesagent"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/stretchr/testify/require"
)

func TestControlSocketPathPrefersTheFlag(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "agent.yaml")
	require.NoError(t, os.WriteFile(
		cfgFile,
		[]byte("kes_agent:\n  control_socket: /run/from-config.sock\n"),
		0o600,
	))

	path, err := controlSocketPath(cfgFile, "/run/flag.sock")
	require.NoError(t, err)
	require.Equal(t, "/run/flag.sock", path)

	path, err = controlSocketPath(cfgFile, "")
	require.NoError(t, err)
	require.Equal(t, "/run/from-config.sock", path)

	t.Setenv("BURSA_CONFIG", "")
	_, err = controlSocketPath("", "")
	require.ErrorContains(t, err, "--socket")
}

func TestReadOpCertFileReturnsTheCertificateCBOR(t *testing.T) {
	kesVKey := bytes.Repeat([]byte{7}, 32)
	_, coldSKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	oc, err := bursa.CreateOperationalCertificate(kesVKey, 3, 100, coldSKey)
	require.NoError(t, err)
	certCBOR, err := cbor.Encode([]any{
		[]any{oc.KesVkey, oc.IssueNumber, oc.KesPeriod, oc.ColdSignature},
		oc.ColdVkey,
	})
	require.NoError(t, err)
	dir := t.TempDir()
	certFile := filepath.Join(dir, "node.cert")
	writeEnvelope(t, certFile, "NodeOperationalCertificate", certCBOR)

	got, err := readOpCertFile(certFile)
	require.NoError(t, err)
	require.Equal(t, certCBOR, got)
	dec, err := bursa.DecodeOpCert(got)
	require.NoError(t, err)
	require.Equal(t, uint64(3), dec.IssueNumber)

	vkeyFile := filepath.Join(dir, "kes.vkey")
	require.NoError(t, writeKESVKeyFile(vkeyFile, kesVKey))
	_, err = readOpCertFile(vkeyFile)
	require.ErrorContains(t, err, "not an operational certificate")
}

func TestWriteKESVKeyFileWritesAnEnvelopeOnce(t *testing.T) {
	vkey := bytes.Repeat([]byte{9}, 32)
	path := filepath.Join(t.TempDir(), "kes.vkey")
	require.NoError(t, writeKESVKeyFile(path, vkey))

	key, err := bursa.LoadKeyFromFile(path)
	require.NoError(t, err)
	require.Equal(t, "KesVerificationKey_ed25519_kes_2^6", key.Type)
	require.Equal(t, vkey, key.VKey)

	require.Error(t, writeKESVKeyFile(path, vkey),
		"an existing file is not replaced")
}

func TestPrintControlReplyShowsKeysInHexAndFailsOnARefusal(t *testing.T) {
	var out bytes.Buffer
	vkey := bytes.Repeat([]byte{0xab}, 32)
	err := printControlReply(&out, kesagent.Reply{
		Ok:      true,
		KESVKey: vkey,
		Info:    &kesagent.AgentInfo{Version: "v", StagedKESVKey: vkey},
	})
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	require.Equal(t, hex.EncodeToString(vkey), got["kes_vkey"])
	info, ok := got["info"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, hex.EncodeToString(vkey), info["staged_kes_vkey"])

	out.Reset()
	err = printControlReply(&out, kesagent.Reply{Error: "no staged key"})
	require.ErrorContains(t, err, "no staged key")
	require.True(t, strings.Contains(out.String(), "no staged key"))
}

func TestDropKeyRefusesAnUnknownTarget(t *testing.T) {
	cmd := kesAgentControlCommand()
	cmd.SetArgs([]string{"drop-key", "--socket", "/nonexistent.sock", "--target", "everything"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	require.ErrorContains(t, err, "--target must be staged, active or all")
}

func writeEnvelope(t *testing.T, path, typ string, cborData []byte) {
	t.Helper()
	data, err := json.Marshal(map[string]string{
		"type":        typ,
		"description": "",
		"cborHex":     hex.EncodeToString(cborData),
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
}
