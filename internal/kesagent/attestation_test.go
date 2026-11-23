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

package kesagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/gouroboros/kes"
)

func TestGenStagedKeyAttestation(t *testing.T) {
	t.Parallel()
	cold := newColdKey(t)
	_, id, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("local control socket", func(t *testing.T) {
		t.Parallel()
		a := testAgent(t, ModeServeKey, cold, kes.CardanoKesDepth, atPeriod(5))
		a.SetStagedKeyIdentity(id)
		conn := startControl(t, a)
		reply := request(t, conn, Command{Command: CmdGenStagedKey})
		assertAttests(t, reply, cold, DefaultProfileName)
	})

	t.Run("remote control session", func(t *testing.T) {
		t.Parallel()
		a := testAgent(t, ModeServeKey, cold, kes.CardanoKesDepth, atPeriod(5))
		a.SetStagedKeyIdentity(id)
		reply := a.dispatchRemote(
			context.Background(),
			Command{Command: CmdGenStagedKey},
			[]*profile{sole(t, a)},
		)
		assertAttests(t, reply, cold, DefaultProfileName)
	})

	t.Run("no identity key", func(t *testing.T) {
		t.Parallel()
		a := testAgent(t, ModeServeKey, cold, kes.CardanoKesDepth, atPeriod(5))
		conn := startControl(t, a)
		reply := request(t, conn, Command{Command: CmdGenStagedKey})
		if !reply.Ok || reply.StagedKeyAttestation != nil {
			t.Fatalf("reply without an identity key: %+v", reply)
		}
	})

	t.Run("identity removed", func(t *testing.T) {
		t.Parallel()
		a := testAgent(t, ModeServeKey, cold, kes.CardanoKesDepth, atPeriod(5))
		a.SetStagedKeyIdentity(id)
		a.SetStagedKeyIdentity(nil)
		conn := startControl(t, a)
		reply := request(t, conn, Command{Command: CmdGenStagedKey})
		if !reply.Ok || reply.StagedKeyAttestation != nil {
			t.Fatalf("reply after clearing the identity key: %+v", reply)
		}
	})
}

func assertAttests(t *testing.T, reply Reply, cold coldKeyPair, profile string) {
	t.Helper()
	if !reply.Ok || len(reply.KESVKey) != kes.PublicKeySize {
		t.Fatalf("gen-staged-key reply: %+v", reply)
	}
	att := reply.StagedKeyAttestation
	if att == nil {
		t.Fatal("reply carries no attestation")
	}
	if err := att.Verify(); err != nil {
		t.Fatalf("attestation does not verify: %v", err)
	}
	coldHash := backend.HashPublicKey(cold.pub)
	if att.Profile != profile ||
		!bytes.Equal(att.KESVKey, reply.KESVKey) ||
		!bytes.Equal(att.ColdKeyHash, coldHash[:]) {
		t.Fatalf("attestation binds %q %x %x, want %q %x %x",
			att.Profile, att.KESVKey, att.ColdKeyHash,
			profile, reply.KESVKey, coldHash[:])
	}
}
