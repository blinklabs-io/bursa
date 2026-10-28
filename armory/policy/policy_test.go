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

package policy

import (
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/armory/profile"
	"github.com/blinklabs-io/gouroboros/ledger"
	"golang.org/x/crypto/blake2b"
)

var testProfile = profile.Profile{
	Name:          "otg@preview",
	ColdKeyID:     0x20e50010,
	RewardAccount: "e0" + strings.Repeat("ee", 28),
}

func TestEvaluate(t *testing.T) {
	k := testKeys
	conway := uint(ledger.TxTypeConway)
	dijkstra := uint(ledger.TxTypeDijkstra)
	reg := func(c ...[]any) []byte { return baseBody().with(4, certs(c...)).cbor() }

	type tc struct {
		name  string
		role  Role
		era   uint
		body  []byte
		allow bool
	}

	cases := []tc{
		{"cold pool re-registration", RoleCold, conway, reg(poolReg(k.Pool, k.Owner)), true},
		{"owner pool re-registration", RoleOwner, conway, reg(poolReg(k.Pool, k.Owner)), true},
		{"cold retirement of own pool", RoleCold, conway, reg(retire(k.Pool)), true},
		{"cold SPO vote by own pool", RoleCold, conway, baseBody().with(19, votes(4, k.Pool)).cbor(), true},
		{"owner reg-deleg to own pool", RoleOwner, conway, reg(regDeleg(k.Owner, k.Pool)), true},
		{"owner registration then delegation", RoleOwner, conway,
			reg(registration(k.Owner), delegation(k.Owner, k.Pool)), true},
		{"owner shelley stake registration", RoleOwner, conway, reg(stakeReg(k.Owner)), true},
		{"payer pays any fee", RoleCold, conway,
			baseBody().with(2, uint64(50_000_000)).with(4, certs(retire(k.Pool))).cbor(), true},
		{"outputs to several payer addresses", RoleCold, conway,
			baseBody().with(1, []any{output(enterprise(0, payer)), output(base(0, foreign, foreign))}).
				with(4, certs(retire(k.Pool))).cbor(), true},
		{"matching network id", RoleCold, conway,
			baseBody().with(15, uint64(0)).with(4, certs(retire(k.Pool))).cbor(), true},
		{"dijkstra pool reg with leios key", RoleCold, dijkstra,
			reg(poolRegFields(k.Pool, leiosKey(), rewardAddr(rewardHash, false), k.Owner)), true},

		{"pool reg with foreign reward account", RoleCold, conway,
			reg(poolRegFields(k.Pool, nil, rewardAddr(foreign, false), k.Owner)), false},
		{"pool reg with script reward of the pinned hash", RoleCold, conway,
			reg(poolRegFields(k.Pool, nil, rewardAddr(rewardHash, true), k.Owner)), false},
		{"pool reg with mainnet reward account", RoleOwner, conway,
			reg(poolRegFields(k.Pool, nil, append([]byte{0xe1}, rewardHash[:]...), k.Owner)), false},
		{"pool reg with second owner", RoleCold, conway, reg(poolReg(k.Pool, k.Owner, foreign)), false},
		{"pool reg with no owner", RoleCold, conway, reg(poolReg(k.Pool)), false},
		{"pool reg with foreign operator", RoleCold, conway, reg(poolReg(foreign, k.Owner)), false},
		{"retirement of foreign pool", RoleCold, conway, reg(retire(foreign)), false},
		{"foreign stake registration beside pool reg", RoleCold, conway,
			reg(poolReg(k.Pool, k.Owner), registration(foreign)), false},
		{"owner delegation to foreign pool", RoleOwner, conway, reg(delegation(k.Owner, foreign)), false},
		{"vote by foreign pool", RoleCold, conway, baseBody().with(19, votes(4, foreign)).cbor(), false},
		{"drep vote", RoleCold, conway, baseBody().with(19, votes(2, k.Pool)).cbor(), false},
		{"withdrawal", RoleOwner, conway,
			baseBody().with(5, map[string]uint64{}).with(4, certs(stakeReg(k.Owner))).cbor(), false},
		{"mint", RoleCold, conway, baseBody().with(9, map[string]uint64{}).with(4, certs(retire(k.Pool))).cbor(), false},
		{"proposal procedure", RoleCold, conway, baseBody().with(20, []any{}).with(4, certs(retire(k.Pool))).cbor(), false},
		{"donation", RoleCold, conway, baseBody().with(22, uint64(1)).with(4, certs(retire(k.Pool))).cbor(), false},
		{"no fee key", RoleCold, dijkstra, baseBody().without(2).with(4, certs(retire(k.Pool))).cbor(), false},
		{"key 23", RoleCold, dijkstra, baseBody().with(23, []any{}).with(4, certs(retire(k.Pool))).cbor(), false},
		{"unknown key 99", RoleCold, conway, baseBody().with(99, uint64(1)).cbor(), false},
		{"duplicate map key", RoleCold, conway, duplicateFee(), false},
		{"indefinite body map", RoleCold, conway, indefiniteBody(), false},
		{"trailing bytes", RoleCold, conway, append(reg(retire(k.Pool)), 0x00), false},
		{"shelley stake registration under dijkstra", RoleOwner, dijkstra, reg(stakeReg(k.Owner)), false},
		{"mainnet output on testnet profile", RoleCold, conway,
			baseBody().with(1, []any{output(enterprise(1, payer))}).with(4, certs(retire(k.Pool))).cbor(), false},
		{"mainnet network id on testnet profile", RoleCold, conway,
			baseBody().with(15, uint64(1)).with(4, certs(retire(k.Pool))).cbor(), false},
		{"cold with only owner certs", RoleCold, conway, reg(regDeleg(k.Owner, k.Pool)), false},
		{"owner with only retirement", RoleOwner, conway, reg(retire(k.Pool)), false},
		{"cold with nothing to authorize", RoleCold, conway, baseBody().cbor(), false},
		{"unknown role", Role(2), conway, reg(poolReg(k.Pool, k.Owner)), false},
		{"babbage era", RoleCold, uint(ledger.TxTypeBabbage), reg(retire(k.Pool)), false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := Evaluate(testProfile, k, c.role, c.era, c.body)

			if err != nil {
				t.Log(err)
			}

			if c.allow && err != nil {
				t.Fatalf("denied: %v", err)
			}

			if !c.allow && err == nil {
				t.Fatalf("allowed: %s", d.Summary)
			}

			if c.allow && d.BodyHash != blake2b.Sum256(c.body) {
				t.Fatal("body hash is not blake2b-256 of the received bytes")
			}
		})
	}
}

func TestEvaluateSummary(t *testing.T) {
	body := baseBody().with(4, certs(poolReg(testKeys.Pool, testKeys.Owner))).cbor()

	d, err := Evaluate(testProfile, testKeys, RoleCold, uint(ledger.TxTypeConway), body)

	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"pool-reg", "pledge=500000000", "cost=170000000", "relays=1"} {
		if !strings.Contains(d.Summary, want) {
			t.Errorf("summary %q lacks %q", d.Summary, want)
		}
	}
}

func TestEvaluateMainnetProfile(t *testing.T) {
	p := testProfile
	p.NetworkID = 1
	p.RewardAccount = "e1" + strings.Repeat("ee", 28)

	main := baseBody().with(1, []any{output(enterprise(1, payer))})
	reward := append([]byte{0xe1}, rewardHash[:]...)

	body := main.with(4, certs(poolRegFields(testKeys.Pool, nil, reward, testKeys.Owner))).cbor()

	if _, err := Evaluate(p, testKeys, RoleCold, uint(ledger.TxTypeConway), body); err != nil {
		t.Fatalf("mainnet registration denied: %v", err)
	}

	if _, err := Evaluate(p, testKeys, RoleCold, uint(ledger.TxTypeConway), baseBody().with(4, certs(retire(testKeys.Pool))).cbor()); err == nil {
		t.Fatal("testnet output allowed on mainnet profile")
	}
}

func TestEvaluateNoPinnedRewardAccount(t *testing.T) {
	p := testProfile
	p.RewardAccount = ""

	body := baseBody().with(4, certs(poolReg(testKeys.Pool, testKeys.Owner))).cbor()

	if _, err := Evaluate(p, testKeys, RoleCold, uint(ledger.TxTypeConway), body); err == nil {
		t.Fatal("registration signed without a pinned reward account")
	}

	retirement := baseBody().with(4, certs(retire(testKeys.Pool))).cbor()

	if _, err := Evaluate(p, testKeys, RoleCold, uint(ledger.TxTypeConway), retirement); err != nil {
		t.Fatalf("retirement needs no reward account: %v", err)
	}
}
