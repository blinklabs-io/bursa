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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

package bursa

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/ledger"
)

// A StakeSigningKeyShelley_ed25519 envelope holds a plain RFC 8032 seed.
// Witnessing with it must sign under the plain public key.
func TestWitnessTransaction_PlainStakeSigningKey(t *testing.T) {
	t.Parallel()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	wantPub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	seedCbor, err := cbor.Encode(seed)
	if err != nil {
		t.Fatalf("encode seed: %v", err)
	}
	env, err := json.Marshal(map[string]string{
		"type":        "StakeSigningKeyShelley_ed25519",
		"description": "Stake Signing Key",
		"cborHex":     hex.EncodeToString(seedCbor),
	})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	path := filepath.Join(t.TempDir(), "owner.skey")
	if err := os.WriteFile(path, env, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	lk, err := LoadSecretKeyFromFile(path)
	if err != nil {
		t.Fatalf("LoadSecretKeyFromFile: %v", err)
	}
	txBytes := mustTestTx(t)
	wit, err := WitnessTransaction(txBytes, lk)
	if err != nil {
		t.Fatalf("WitnessTransaction: %v", err)
	}
	if hex.EncodeToString(wit.Vkey) != hex.EncodeToString(wantPub) {
		t.Fatalf("witness vkey = %x, want plain public key %x", wit.Vkey, wantPub)
	}
	txType, err := ledger.DetermineTransactionType(txBytes)
	if err != nil {
		t.Fatalf("tx type: %v", err)
	}
	tx, err := ledger.NewTransactionFromCbor(txType, txBytes)
	if err != nil {
		t.Fatalf("decode tx: %v", err)
	}
	if !ed25519.Verify(wantPub, tx.Hash().Bytes(), wit.Signature) {
		t.Fatalf("witness signature does not verify under the plain public key")
	}
}
