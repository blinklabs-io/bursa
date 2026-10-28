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

var testProfile = profile.Profile{Name: "otg@preview", ColdKeyID: 0x20e50010}

func TestEvaluate(t *testing.T) {
	k := testKeys
	conway := uint(ledger.TxTypeConway)
	dijkstra := uint(ledger.TxTypeDijkstra)

	type tc struct {
		name  string
		role  Role
		era   uint
		body  []byte
		allow bool
	}

	cases := []tc{
		{"cold pool re-registration", RoleCold, conway,
			baseBody().with(4, certs(poolReg(k.Pool, k.Owner))).cbor(), true},
		{"owner pool re-registration", RoleOwner, conway,
			baseBody().with(4, certs(poolReg(k.Pool, k.Owner))).cbor(), true},
		{"cold retirement of own pool", RoleCold, conway,
			baseBody().with(4, certs(retire(k.Pool))).cbor(), true},
		{"cold SPO vote by own pool", RoleCold, conway,
			baseBody().with(19, votes(4, k.Pool)).cbor(), true},
		{"owner reg-deleg to own pool", RoleOwner, conway,
			baseBody().with(4, certs(regDeleg(k.Owner, k.Pool))).cbor(), true},
		{"owner registration then delegation", RoleOwner, conway,
			baseBody().with(4, certs(registration(k.Owner), delegation(k.Owner, k.Pool))).cbor(), true},
		{"owner shelley stake registration", RoleOwner, conway,
			baseBody().with(4, certs(stakeReg(k.Owner))).cbor(), true},
		{"fee consolidation", RoleFee, conway, baseBody().cbor(), true},
		{"matching network id", RoleFee, conway, baseBody().with(15, uint64(0)).cbor(), true},
		{"dijkstra pool reg with leios key", RoleCold, dijkstra,
			baseBody().with(4, certs(poolRegFields(k.Pool, leiosKey(), k.Owner))).cbor(), true},

		{"pool reg with second owner", RoleCold, conway,
			baseBody().with(4, certs(poolReg(k.Pool, k.Owner, foreign))).cbor(), false},
		{"pool reg with no owner", RoleCold, conway,
			baseBody().with(4, certs(poolReg(k.Pool))).cbor(), false},
		{"pool reg with foreign operator", RoleCold, conway,
			baseBody().with(4, certs(poolReg(foreign, k.Owner))).cbor(), false},
		{"retirement of foreign pool", RoleCold, conway,
			baseBody().with(4, certs(retire(foreign))).cbor(), false},
		{"foreign stake registration beside pool reg", RoleCold, conway,
			baseBody().with(4, certs(poolReg(k.Pool, k.Owner), registration(foreign))).cbor(), false},
		{"owner delegation to foreign pool", RoleOwner, conway,
			baseBody().with(4, certs(delegation(k.Owner, foreign))).cbor(), false},
		{"vote by foreign pool", RoleCold, conway,
			baseBody().with(19, votes(4, foreign)).cbor(), false},
		{"drep vote", RoleCold, conway,
			baseBody().with(19, votes(2, k.Pool)).cbor(), false},
		{"withdrawal", RoleFee, conway, baseBody().with(5, map[string]uint64{}).cbor(), false},
		{"mint", RoleFee, conway, baseBody().with(9, map[string]uint64{}).cbor(), false},
		{"proposal procedure", RoleFee, conway, baseBody().with(20, []any{}).cbor(), false},
		{"donation", RoleFee, conway, baseBody().with(22, uint64(1)).cbor(), false},
		{"no fee key", RoleFee, dijkstra, baseBody().without(2).cbor(), false},
		{"key 23", RoleFee, dijkstra, baseBody().with(23, []any{}).cbor(), false},
		{"unknown key 99", RoleFee, conway, baseBody().with(99, uint64(1)).cbor(), false},
		{"duplicate map key", RoleFee, conway, duplicateFee(), false},
		{"indefinite body map", RoleFee, conway, indefiniteBody(), false},
		{"trailing bytes", RoleFee, conway, append(baseBody().cbor(), 0x00), false},
		{"fee above cap", RoleFee, conway, baseBody().with(2, uint64(profile.DefaultMaxFee+1)).cbor(), false},
		{"shelley stake registration under dijkstra", RoleOwner, dijkstra,
			baseBody().with(4, certs(stakeReg(k.Owner))).cbor(), false},
		{"mainnet output on testnet profile", RoleFee, conway,
			baseBody().with(1, []any{output(enterprise(1, k.Fee))}).cbor(), false},
		{"mainnet network id on testnet profile", RoleFee, conway,
			baseBody().with(15, uint64(1)).cbor(), false},
		{"fee output with stake part", RoleFee, conway,
			baseBody().with(1, []any{output(base(0, k.Fee, foreign))}).cbor(), false},
		{"cold with only owner certs", RoleCold, conway,
			baseBody().with(4, certs(regDeleg(k.Owner, k.Pool))).cbor(), false},
		{"owner with only retirement", RoleOwner, conway,
			baseBody().with(4, certs(retire(k.Pool))).cbor(), false},
		{"babbage era", RoleFee, uint(ledger.TxTypeBabbage), baseBody().cbor(), false},
	}

	for _, r := range []Role{RoleCold, RoleOwner, RoleFee} {
		cases = append(cases, tc{"foreign output", r, conway,
			baseBody().
				with(1, []any{output(enterprise(0, k.Fee)), output(enterprise(0, foreign))}).
				with(4, certs(poolReg(k.Pool, k.Owner))).cbor(), false})
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := Evaluate(testProfile, k, c.role, c.era, c.body)

			if c.allow && err != nil {
				t.Fatalf("denied: %v", err)
			}

			if err != nil {
				t.Log(err)
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

	body := baseBody().with(1, []any{output(enterprise(1, testKeys.Fee))}).cbor()

	if _, err := Evaluate(p, testKeys, RoleFee, uint(ledger.TxTypeConway), body); err != nil {
		t.Fatalf("mainnet fee output denied: %v", err)
	}

	if _, err := Evaluate(p, testKeys, RoleFee, uint(ledger.TxTypeConway), baseBody().cbor()); err == nil {
		t.Fatal("testnet output allowed on mainnet profile")
	}
}

func TestEvaluateProfileFeeCap(t *testing.T) {
	p := testProfile
	p.MaxFee = 100_000

	if _, err := Evaluate(p, testKeys, RoleFee, uint(ledger.TxTypeConway), baseBody().cbor()); err == nil {
		t.Fatal("fee 200000 allowed under a 100000 cap")
	}
}
