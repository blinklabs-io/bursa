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

package signer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/kesagent"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/policy"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/kes"
	"github.com/blinklabs-io/gouroboros/ledger"
	"github.com/blinklabs-io/gouroboros/ledger/babbage"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/vrf"
)

const embeddedBPMaxFrame = 1 << 20

type embeddedBPConn interface {
	io.Reader
	io.Writer
	SetDeadline(time.Time) error
}

func writeEmbeddedBPFrame(t *testing.T, conn embeddedBPConn, value any) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal frame: %v", err)
	}
	if len(payload) > embeddedBPMaxFrame {
		t.Fatalf("frame is %d bytes, exceeds %d", len(payload), embeddedBPMaxFrame)
	}
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set frame deadline: %v", err)
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(payload))) // #nosec G115 -- bounded above
	writeEmbeddedBPBytes(t, conn, length[:])
	writeEmbeddedBPBytes(t, conn, payload)
}

func writeEmbeddedBPBytes(t *testing.T, conn embeddedBPConn, data []byte) {
	t.Helper()
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			t.Fatalf("write frame: %v", err)
		}
		if n == 0 {
			t.Fatal("write frame: zero-byte write")
		}
		data = data[n:]
	}
}

func readEmbeddedBPFrame(t *testing.T, conn embeddedBPConn, value any) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set frame deadline: %v", err)
	}
	var length [4]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		t.Fatalf("read frame length: %v", err)
	}
	n := binary.BigEndian.Uint32(length[:])
	if n == 0 || n > embeddedBPMaxFrame {
		t.Fatalf("invalid frame length %d", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("read frame payload: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(value); err != nil {
		t.Fatalf("decode frame: %v", err)
	}
}

func dialEmbeddedBPAgent(t *testing.T, path string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.Dial("unix", path)
		if err == nil {
			t.Cleanup(func() { _ = conn.Close() })
			return conn
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial KES agent: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func embeddedBPHeader(
	t *testing.T,
	slot uint64,
	coldVkey, kesVkey, coldSignature, vrfVkey, vrfSecret []byte,
) []byte {
	t.Helper()
	eta0 := make([]byte, 32)
	vrfInput, err := vrf.MkInputVrf(int64(slot), eta0) // #nosec G115 -- test slots are small
	if err != nil {
		t.Fatalf("build VRF input: %v", err)
	}
	proof, output, err := vrf.Prove(vrfSecret, vrfInput)
	if err != nil {
		t.Fatalf("prove VRF: %v", err)
	}
	verified, err := vrf.VerifyAndHash(vrfVkey, proof, vrfInput)
	if err != nil {
		t.Fatalf("verify VRF proof: %v", err)
	}
	if !bytes.Equal(verified, output) {
		t.Fatal("VRF output changed during verification")
	}

	var issuer lcommon.IssuerVkey
	copy(issuer[:], coldVkey)
	header := babbage.BabbageBlockHeaderBody{
		BlockNumber: 1,
		Slot:        slot,
		IssuerVkey:  issuer,
		VrfKey:      append([]byte(nil), vrfVkey...),
		VrfResult: lcommon.VrfResult{
			Output: output,
			Proof:  proof,
		},
		OpCert: babbage.BabbageOpCert{
			HotVkey:        append([]byte(nil), kesVkey...),
			SequenceNumber: 1,
			KesPeriod:      0,
			Signature:      append([]byte(nil), coldSignature...),
		},
		ProtoVersion: babbage.BabbageProtoVersion{Major: 10},
	}
	encoded, err := cbor.Encode(&header)
	if err != nil {
		t.Fatalf("encode block header body: %v", err)
	}
	return encoded
}

func signEmbeddedBPHeader(
	t *testing.T,
	socket string,
	period uint64,
	header []byte,
) []byte {
	t.Helper()
	conn := dialEmbeddedBPAgent(t, socket)
	var hello kesagent.Hello
	readEmbeddedBPFrame(t, conn, &hello)
	if hello.Protocol != kesagent.ProtocolID || hello.Mode != kesagent.ModeSign {
		t.Fatalf("KES agent hello = %+v", hello)
	}
	writeEmbeddedBPFrame(t, conn, kesagent.SignRequest{
		Type:    "sign_request",
		Period:  period,
		Message: header,
	})
	var response kesagent.SignResponse
	readEmbeddedBPFrame(t, conn, &response)
	if response.Type != "sign_response" || response.Period != period || response.Error != "" {
		t.Fatalf("KES sign response = %+v", response)
	}
	return response.Signature
}

func TestEmbeddedBlockProducerRemoteCustody(t *testing.T) {
	_, coldPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate cold key: %v", err)
	}
	coldPublic := coldPrivate.Public().(ed25519.PublicKey)
	vault := fakeVault(t, coldPrivate, "pool-cold")
	t.Cleanup(vault.Close)
	t.Setenv("VAULT_TOKEN", "test-token")

	vaultBackend, err := buildVaultBackend(t.Context(), config.SignerBackendConfig{
		Name:    "vault",
		Type:    "vault",
		Address: vault.URL,
		Keys: []config.SignerBackendKeyConfig{{
			Name: "pool-cold",
			Type: string(backend.KeyTypePool),
		}},
	})
	if err != nil {
		t.Fatalf("build Vault backend: %v", err)
	}
	coldHash := backend.HashPublicKey(coldPublic)
	policies, err := policy.NewEngine([]policy.KeyPolicy{{
		Hash:            coldHash.String(),
		Backend:         "vault",
		AllowedRequests: []string{"opcert"},
	}})
	if err != nil {
		t.Fatalf("build signing policy: %v", err)
	}
	coordinator := New(Deps{
		Resolver:  backend.NewResolver(vaultBackend),
		Policy:    policies,
		Watermark: watermark.NewMemWatermark(),
		WMMode:    watermark.ModeEnforce,
		Cardano:   fakeCardano{},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	const periodDuration = 500 * time.Millisecond
	systemStart := time.Now().Add(-periodDuration / 10)
	agent, err := kesagent.New(kesagent.Config{
		Mode:              kesagent.ModeSign,
		Depth:             kes.CardanoKesDepth,
		SystemStart:       systemStart,
		SlotLength:        periodDuration / 100,
		SlotsPerKESPeriod: 100,
		MaxKESEvolutions:  62,
		ColdVKey:          coldPublic,
		EvolveInterval:    time.Hour,
		GuardPath:         filepath.Join(t.TempDir(), "guard.json"),
		Version:           "test",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("create KES agent: %v", err)
	}
	t.Cleanup(agent.Close)

	kesVkey, err := agent.GenStagedKey()
	if err != nil {
		t.Fatalf("generate staged KES key: %v", err)
	}
	opcertResult, code, err := coordinator.SignOpCert(
		t.Context(), kesVkey, 1, 0, coldHash.String(),
	)
	if err != nil {
		t.Fatalf("remote opcert signature: code=%s err=%v", code, err)
	}
	coldSignature, err := hex.DecodeString(opcertResult.SignatureHex)
	if err != nil {
		t.Fatalf("decode cold signature: %v", err)
	}
	opcert, err := cbor.Encode([]any{
		[]any{kesVkey, uint64(1), uint64(0), coldSignature},
		[]byte(coldPublic),
	})
	if err != nil {
		t.Fatalf("encode operational certificate: %v", err)
	}
	installed, err := agent.InstallKey(opcert)
	if err != nil {
		t.Fatalf("install KES key: %v", err)
	}
	initialPeriod := installed.ActivePeriod

	socketDir, err := os.MkdirTemp("", "bursa-bp-")
	if err != nil {
		t.Fatalf("create socket directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "kes.sock")
	listener, err := kesagent.ListenUnix(socket, 0o600)
	if err != nil {
		t.Fatalf("listen on KES socket: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	serveDone := make(chan error, 1)
	go func() { serveDone <- agent.ServeService(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("serve KES agent: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("KES agent did not stop")
		}
	})

	vrfSeed := make([]byte, vrf.SeedSize)
	if _, err := rand.Read(vrfSeed); err != nil {
		t.Fatalf("generate VRF seed: %v", err)
	}
	vrfVkey, vrfSecret, err := vrf.KeyGen(vrfSeed)
	if err != nil {
		t.Fatalf("generate VRF key: %v", err)
	}

	firstHeader := embeddedBPHeader(
		t, initialPeriod*100, coldPublic, kesVkey, coldSignature, vrfVkey, vrfSecret,
	)
	firstSignature := signEmbeddedBPHeader(t, socket, initialPeriod, firstHeader)
	if !kes.VerifySignedKES(kesVkey, initialPeriod, firstHeader, firstSignature) {
		t.Fatal("initial KES signature does not verify")
	}

	deadline := time.Now().Add(2 * time.Second)
	for agent.Info().CurrentPeriod <= initialPeriod && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if agent.Info().CurrentPeriod <= initialPeriod {
		t.Fatalf("current KES period = %d, want greater than %d", agent.Info().CurrentPeriod, initialPeriod)
	}
	agent.Tick()
	rotatedPeriod := agent.Info().ActivePeriod
	if rotatedPeriod <= initialPeriod {
		t.Fatalf("active KES period = %d after evolution, want greater than %d", rotatedPeriod, initialPeriod)
	}

	rotatedHeader := embeddedBPHeader(
		t, rotatedPeriod*100, coldPublic, kesVkey, coldSignature, vrfVkey, vrfSecret,
	)
	rotatedSignature := signEmbeddedBPHeader(t, socket, rotatedPeriod, rotatedHeader)
	if !kes.VerifySignedKES(kesVkey, rotatedPeriod, rotatedHeader, rotatedSignature) {
		t.Fatal("evolved KES signature does not verify after reconnect")
	}

	missing := backend.KeyHash{1}
	if result, code, err := coordinator.SignOpCert(
		t.Context(), kesVkey, 2, 1, missing.String(),
	); result != nil || code != CodeNotFound || err == nil {
		t.Fatalf("missing cold key = result=%v code=%s err=%v", result, code, err)
	}
}

func TestEmbeddedBlockProducerRemoteCustodyFailures(t *testing.T) {
	_, coldPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate cold key: %v", err)
	}
	vault := fakeVault(t, coldPrivate, "pool-cold")
	t.Cleanup(vault.Close)

	t.Run("missing Vault token", func(t *testing.T) {
		t.Setenv("VAULT_TOKEN", "")
		_, err := buildVaultBackend(t.Context(), config.SignerBackendConfig{
			Name: "vault", Type: "vault", Address: vault.URL,
			Keys: []config.SignerBackendKeyConfig{{Name: "pool-cold", Type: "pool"}},
		})
		if err == nil || !strings.Contains(err.Error(), "vault token env var VAULT_TOKEN is empty") {
			t.Fatalf("missing token error = %v", err)
		}
	})

	t.Run("rejected Vault token", func(t *testing.T) {
		t.Setenv("VAULT_TOKEN", "expired-token")
		_, err := buildVaultBackend(t.Context(), config.SignerBackendConfig{
			Name: "vault", Type: "vault", Address: vault.URL,
			Keys: []config.SignerBackendKeyConfig{{Name: "pool-cold", Type: "pool"}},
		})
		if err == nil || !strings.Contains(err.Error(), "vault key \"pool-cold\"") || !strings.Contains(err.Error(), "Code: 403") {
			t.Fatalf("rejected token error = %v", err)
		}
	})

	t.Run("missing active KES key", func(t *testing.T) {
		coldPublic := coldPrivate.Public().(ed25519.PublicKey)
		agent, err := kesagent.New(kesagent.Config{
			Mode:              kesagent.ModeSign,
			Depth:             kes.CardanoKesDepth,
			SystemStart:       time.Now().Add(-time.Second),
			SlotLength:        time.Second,
			SlotsPerKESPeriod: 10,
			MaxKESEvolutions:  3,
			ColdVKey:          coldPublic,
			EvolveInterval:    time.Hour,
			GuardPath:         filepath.Join(t.TempDir(), "guard.json"),
		}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
		if err != nil {
			t.Fatalf("create KES agent: %v", err)
		}
		t.Cleanup(agent.Close)
		if _, err := agent.SignHeader(0, []byte{0x80}); err == nil || !strings.Contains(err.Error(), "no active KES key installed") {
			t.Fatalf("missing KES key error = %v", err)
		}
	})

	t.Run("expired operational certificate", func(t *testing.T) {
		coldPublic := coldPrivate.Public().(ed25519.PublicKey)
		agent, err := kesagent.New(kesagent.Config{
			Mode:              kesagent.ModeSign,
			Depth:             kes.CardanoKesDepth,
			SystemStart:       time.Now().Add(-2 * time.Second),
			SlotLength:        time.Second,
			SlotsPerKESPeriod: 1,
			MaxKESEvolutions:  1,
			ColdVKey:          coldPublic,
			EvolveInterval:    time.Hour,
			GuardPath:         filepath.Join(t.TempDir(), "guard.json"),
		}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
		if err != nil {
			t.Fatalf("create KES agent: %v", err)
		}
		t.Cleanup(agent.Close)
		kesVkey, err := agent.GenStagedKey()
		if err != nil {
			t.Fatalf("generate KES key: %v", err)
		}
		opcert, err := ledger.CreateOpCert(kesVkey, 1, 0, coldPrivate)
		if err != nil {
			t.Fatalf("create operational certificate: %v", err)
		}
		envelope, err := cbor.Encode([]any{
			[]any{opcert.KesVkey, uint64(1), uint64(0), opcert.ColdSignature},
			[]byte(coldPublic),
		})
		if err != nil {
			t.Fatalf("encode operational certificate: %v", err)
		}
		if _, err := agent.InstallKey(envelope); err == nil || !strings.Contains(err.Error(), "opcert expired") {
			t.Fatalf("expired opcert error = %v", err)
		}
	})
}
