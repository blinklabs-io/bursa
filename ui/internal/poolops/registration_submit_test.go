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

package poolops

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/wallet"
	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/conway"
)

type fakePoolRegistry struct {
	registered bool
	err        error
	calls      []string
}

func (f *fakePoolRegistry) PoolRegistered(
	_ context.Context,
	poolID string,
) (bool, error) {
	f.calls = append(f.calls, poolID)
	return f.registered, f.err
}

func registrationParams() RegistrationParams {
	return RegistrationParams{
		Pledge:      1_000_000,
		Cost:        340_000_000,
		MarginNum:   1,
		MarginDenom: 100,
	}
}

type registrationFixture struct {
	svc   *Service
	chain *retirementFakeChain
	reg   *fakePoolRegistry
	acct  *wallet.Account
}

func newRegistrationFixture(
	t *testing.T,
	lovelace uint64,
	registered bool,
) registrationFixture {
	t.Helper()
	acct, err := wallet.Derive(testMnemonic, "preview", 2)
	if err != nil {
		t.Fatalf("derive account: %v", err)
	}
	chain := newRetirementFakeChain(acct.ReceiveAddresses[0], lovelace)
	ks := &fakeKeystore{
		mnemonic: testMnemonic,
		password: "spend-password",
		exists:   true,
	}
	s := NewService(chain, ks, fakeGenesis{}, fakeTip{slot: 259200})
	s.SetAccount("wallet-a", acct)
	reg := &fakePoolRegistry{registered: registered}
	s.SetPoolRegistry(reg)
	return registrationFixture{svc: s, chain: chain, reg: reg, acct: acct}
}

func decodeSubmitted(t *testing.T, raw []byte) conway.ConwayTransaction {
	t.Helper()
	if len(raw) == 0 {
		t.Fatal("no transaction was submitted")
	}
	var tx conway.ConwayTransaction
	if _, err := cbor.Decode(raw, &tx); err != nil {
		t.Fatalf("decode submitted tx: %v", err)
	}
	return tx
}

// netDeposit is inputs - outputs - fee for a single-input transaction funded
// with inLovelace: the lovelace the transaction locks as certificate deposit.
func netDeposit(tx conway.ConwayTransaction, inLovelace uint64) *big.Int {
	net := new(big.Int).SetUint64(inLovelace)
	for _, out := range tx.Body.TxOutputs {
		net.Sub(net, out.Amount())
	}
	return net.Sub(net, new(big.Int).SetUint64(tx.Body.TxFee))
}

func witnessKeyHashes(
	t *testing.T,
	tx conway.ConwayTransaction,
) map[lcommon.Blake2b224]bool {
	t.Helper()
	out := map[lcommon.Blake2b224]bool{}
	for _, w := range tx.WitnessSet.VkeyWitnesses.Items() {
		out[lcommon.Blake2b224Hash(w.Vkey)] = true
	}
	return out
}

func assertRegistrationTx(
	t *testing.T,
	f registrationFixture,
	res RegistrationTxResult,
	wantDeposit int64,
	inLovelace uint64,
) {
	t.Helper()
	if res.TxHash == "" {
		t.Fatal("empty tx hash")
	}
	tx := decodeSubmitted(t, f.chain.submitCbor)

	// The submitted certificate is byte-identical to the canonical certificate
	// the build endpoint returns (correct 29-byte reward account).
	built, err := f.svc.BuildRegistrationFromSeed(
		"spend-password",
		registrationParams(),
	)
	if err != nil {
		t.Fatalf("BuildRegistrationFromSeed: %v", err)
	}
	if len(tx.Body.TxCertificates) != 1 {
		t.Fatalf("certificate count = %d, want 1", len(tx.Body.TxCertificates))
	}
	gotCert, err := cbor.Encode(&tx.Body.TxCertificates[0])
	if err != nil {
		t.Fatalf("encode submitted certificate: %v", err)
	}
	if got := hex.EncodeToString(gotCert); got != built.CBORHex {
		t.Fatalf("submitted certificate = %s, want %s", got, built.CBORHex)
	}

	if got := netDeposit(tx, inLovelace); got.Cmp(
		big.NewInt(wantDeposit),
	) != 0 {
		t.Fatalf("locked deposit = %s, want %d", got, wantDeposit)
	}
	finalMinFee := uint64(
		int64(
			len(f.chain.submitCbor),
		)*f.chain.pp.MinFeeCoefficient + f.chain.pp.MinFeeConstant,
	) //nolint:gosec // small test params
	if tx.Body.TxFee < finalMinFee {
		t.Fatalf("fee = %d, below final min fee %d", tx.Body.TxFee, finalMinFee)
	}

	// Witnesses: payment key, owner stake key, pool cold key.
	creds, err := f.svc.Credentials("spend-password")
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	coldHash := lcommon.Blake2b224Hash(mustHex(t, creds.Cold.VKeyHex))
	stakeAddr, err := lcommon.NewAddress(f.acct.StakeAddress)
	if err != nil {
		t.Fatalf("stake address: %v", err)
	}
	payAddr, err := lcommon.NewAddress(f.acct.ReceiveAddresses[0])
	if err != nil {
		t.Fatalf("payment address: %v", err)
	}
	have := witnessKeyHashes(t, tx)
	for name, want := range map[string]lcommon.Blake2b224{
		"cold":    coldHash,
		"stake":   stakeAddr.StakeKeyHash(),
		"payment": payAddr.PaymentKeyHash(),
	} {
		if !have[want] {
			t.Errorf("missing %s key witness", name)
		}
	}
	if n := len(tx.WitnessSet.VkeyWitnesses.Items()); n != 3 {
		t.Errorf("vkey witness count = %d, want 3", n)
	}
	// Every witness signs the submitted transaction body.
	bodyHash := lcommon.Blake2b256Hash(tx.Body.Cbor())
	for _, w := range tx.WitnessSet.VkeyWitnesses.Items() {
		if !ed25519.Verify(
			ed25519.PublicKey(w.Vkey),
			bodyHash.Bytes(),
			w.Signature,
		) {
			t.Errorf(
				"witness %s does not verify over the transaction body",
				lcommon.Blake2b224Hash(w.Vkey),
			)
		}
	}
}

func TestSubmitRegistrationNewPoolLocksDepositAndWitnesses(t *testing.T) {
	t.Parallel()
	const funds = 700_000_000
	f := newRegistrationFixture(t, funds, false)
	res, err := f.svc.SubmitRegistration(
		context.Background(),
		"spend-password",
		registrationParams(),
	)
	if err != nil {
		t.Fatalf("SubmitRegistration: %v", err)
	}
	if res.Update {
		t.Fatal("Update = true for an unregistered pool")
	}
	assertRegistrationTx(t, f, res, 500_000_000, funds)
}

func TestSubmitRegistrationExistingPoolLocksNoDeposit(t *testing.T) {
	t.Parallel()
	const funds = 5_000_000
	f := newRegistrationFixture(t, funds, true)
	res, err := f.svc.SubmitRegistration(
		context.Background(),
		"spend-password",
		registrationParams(),
	)
	if err != nil {
		t.Fatalf("SubmitRegistration: %v", err)
	}
	if !res.Update {
		t.Fatal("Update = false for an already-registered pool")
	}
	assertRegistrationTx(t, f, res, 0, funds)
	if len(f.reg.calls) != 1 {
		t.Fatalf("registry lookups = %d, want 1", len(f.reg.calls))
	}
}

func TestSubmitRegistrationRefusals(t *testing.T) {
	t.Parallel()
	otherOwner := "stake_test1uqehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gssrtvn"
	cases := []struct {
		name    string
		funds   uint64
		setup   func(f *registrationFixture, p *RegistrationParams)
		wantErr error
		wantMsg string
	}{
		{
			name:  "owner not controlled by wallet",
			funds: 700_000_000,
			setup: func(_ *registrationFixture, p *RegistrationParams) {
				p.Owners = []string{otherOwner}
			},
			wantErr: ErrInvalidRequest,
		},
		{
			name:  "external cold key",
			funds: 700_000_000,
			setup: func(_ *registrationFixture, p *RegistrationParams) {
				p.ColdVKeyHex = "00"
			},
			wantErr: ErrInvalidRequest,
		},
		{
			name:  "registry lookup fails",
			funds: 700_000_000,
			setup: func(f *registrationFixture, _ *RegistrationParams) {
				f.reg.err = errors.New("node unavailable")
			},
			wantMsg: "check pool registration: node unavailable",
		},
		{
			name:  "no registry configured",
			funds: 700_000_000,
			setup: func(f *registrationFixture, _ *RegistrationParams) {
				f.svc.SetPoolRegistry(nil)
			},
			wantMsg: "no pool registry configured",
		},
		{
			name:    "new registration cannot cover deposit",
			funds:   5_000_000,
			wantMsg: "insufficient UTxOs to cover required value",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newRegistrationFixture(t, tc.funds, false)
			p := registrationParams()
			if tc.setup != nil {
				tc.setup(&f, &p)
			}
			_, err := f.svc.SubmitRegistration(
				context.Background(),
				"spend-password",
				p,
			)
			if err == nil {
				t.Fatal("SubmitRegistration succeeded, want an error")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantMsg != "" && !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.wantMsg)
			}
			if len(f.chain.submitCbor) != 0 {
				t.Fatal("a transaction was submitted despite the refusal")
			}
		})
	}
}

func TestSubmitRegistrationWrongPassword(t *testing.T) {
	t.Parallel()
	f := newRegistrationFixture(t, 700_000_000, false)
	_, err := f.svc.SubmitRegistration(
		context.Background(),
		"nope",
		registrationParams(),
	)
	if !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("err = %v, want ErrWrongPassword", err)
	}
	if !bytes.Equal(f.chain.submitCbor, nil) {
		t.Fatal("a transaction was submitted")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}
	return b
}
