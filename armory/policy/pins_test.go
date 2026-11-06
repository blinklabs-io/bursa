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
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/armory/profile"
	"github.com/blinklabs-io/gouroboros/ledger"
	"github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"
)

// pinnedVRF is the VRF key hash the fixture registration names.
var pinnedVRF = [32]byte{}

func pinnedMeta() *[32]byte {
	h := [32]byte{0x44}
	return &h
}

const metaURL = "https://example.test/p.json"

func hostRelay(host string, port uint32) common.PoolRelay {
	return common.PoolRelay{
		Type:     common.PoolRelayTypeSingleHostName,
		Port:     &port,
		Hostname: &host,
	}
}

// mustDigest is RelaysDigest for fixtures that always encode.
func mustDigest(
	relays []common.PoolRelay,
	url *string,
) [profile.RelaysDigestSize]byte {
	d, err := RelaysDigest(relays, url)
	if err != nil {
		panic(err)
	}

	return d
}

// testPins accept the fixture registration, which has pledge 500_000_000,
// cost 170_000_000, margin 1/100, the relay relay.example:3001 and no
// metadata.
func testPins() *profile.Pins {
	return &profile.Pins{
		VRFKeyHash: pinnedVRF,
		PinRelays:  true,
		PledgeMin:  500_000_000, PledgeMax: 600_000_000,
		CostMax:      170_000_000,
		MarginMaxNum: 1, MarginMaxDen: 100,
		RelaysDigest: mustDigest(
			[]common.PoolRelay{hostRelay("relay.example", 3001)},
			nil,
		),
	}
}

func metadata(h [32]byte) []any { return []any{metaURL, h[:]} }

// relayCBOR is a single-host-name relay as a registration carries it.
func relayCBOR(
	host string,
	port uint64,
) []any {
	return []any{uint64(1), port, host}
}

// regWith returns the fixture registration with field i replaced.
func regWith(i int, v any) []any {
	c := append([]any(nil), poolReg(testKeys.Pool, testKeys.Owner)...)
	c[i] = v

	return c
}

// Certificate array positions: type, operator, vrf, pledge, cost, margin,
// reward, owners, relays, metadata.
const (
	fVRF, fPledge, fCost, fMargin, fRelays, fMeta = 2, 3, 4, 5, 8, 9
)

func margin(
	n, d uint64,
) cbor.Tag {
	return cbor.Tag{Number: 30, Content: []uint64{n, d}}
}

func TestEvaluatePoolPins(t *testing.T) {
	t.Parallel()

	conway := uint(ledger.TxTypeConway)
	otherVRF := bytes.Repeat([]byte{0x77}, 32)

	url := metaURL
	withMeta := testPins()
	withMeta.MetadataHash = pinnedMeta()
	withMeta.RelaysDigest = mustDigest(
		[]common.PoolRelay{hostRelay("relay.example", 3001)},
		&url,
	)

	twoRelays := testPins()
	twoRelays.RelaysDigest = mustDigest(
		[]common.PoolRelay{
			hostRelay("a.example", 1),
			hostRelay("b.example", 2),
		},
		nil,
	)

	// relays and metadata unpinned: only the VRF key and the bounds hold
	free := testPins()
	free.PinRelays, free.RelaysDigest = false, [profile.RelaysDigestSize]byte{}

	type tc struct {
		name  string
		pins  *profile.Pins
		cert  []any
		allow bool
		// refusal is a substring that names the rule that refused it
		refusal string
	}

	cases := []tc{
		{
			"pinned registration matches",
			testPins(),
			regWith(fPledge, uint64(500_000_000)),
			true,
			"",
		},
		{
			"other VRF key",
			testPins(),
			regWith(fVRF, otherVRF),
			false,
			"VRF key hash",
		},
		{
			"metadata when none pinned",
			testPins(),
			regWith(fMeta, metadata([32]byte{0x44})),
			false,
			"metadata",
		},
		{
			"metadata pinned and present",
			withMeta,
			regWith(fMeta, metadata(*pinnedMeta())),
			true,
			"",
		},
		{
			"metadata pinned and absent",
			withMeta,
			poolReg(testKeys.Pool, testKeys.Owner),
			false,
			"metadata",
		},
		{
			"other metadata hash",
			withMeta,
			regWith(fMeta, metadata([32]byte{0x45})),
			false,
			"metadata",
		},
		{
			"pledge below minimum",
			testPins(),
			regWith(fPledge, uint64(499_999_999)),
			false,
			"pledge",
		},
		{
			"pledge at maximum",
			testPins(),
			regWith(fPledge, uint64(600_000_000)),
			true,
			"",
		},
		{
			"pledge above maximum",
			testPins(),
			regWith(fPledge, uint64(600_000_001)),
			false,
			"pledge",
		},
		{
			"cost at maximum",
			testPins(),
			regWith(fCost, uint64(170_000_000)),
			true,
			"",
		},
		{
			"cost above maximum",
			testPins(),
			regWith(fCost, uint64(170_000_001)),
			false,
			"cost",
		},
		{
			"margin at maximum",
			testPins(),
			regWith(fMargin, margin(2, 200)),
			true,
			"",
		},
		{
			"margin above maximum",
			testPins(),
			regWith(fMargin, margin(2, 199)),
			false,
			"margin",
		},
		{"no pins", nil, regWith(fVRF, otherVRF), true, ""},
		{
			"other relay host",
			testPins(),
			regWith(fRelays, []any{relayCBOR("evil.example", 3001)}),
			false,
			"relays",
		},
		{
			"other relay port",
			testPins(),
			regWith(fRelays, []any{relayCBOR("relay.example", 3002)}),
			false,
			"relays",
		},
		{
			"relay added",
			testPins(),
			regWith(
				fRelays,
				[]any{
					relayCBOR("relay.example", 3001),
					relayCBOR("evil.example", 1),
				},
			),
			false,
			"relays",
		},
		{
			"relays removed",
			testPins(),
			regWith(fRelays, []any{}),
			false,
			"relays",
		},
		{
			"pinned relays in order",
			twoRelays,
			regWith(
				fRelays,
				[]any{relayCBOR("a.example", 1), relayCBOR("b.example", 2)},
			),
			true,
			"",
		},
		{
			"pinned relays reordered",
			twoRelays,
			regWith(
				fRelays,
				[]any{relayCBOR("b.example", 2), relayCBOR("a.example", 1)},
			),
			false,
			"relays",
		},
		{
			"other metadata URL",
			withMeta,
			regWith(
				fMeta,
				[]any{"https://evil.example/p.json", pinnedMeta()[:]},
			),
			false,
			"metadata URL",
		},
		{
			"unpinned relays changed",
			free,
			regWith(fRelays, []any{relayCBOR("new.example", 6000)}),
			true,
			"",
		},
		{"unpinned relays removed", free, regWith(fRelays, []any{}), true, ""},
		{
			"unpinned metadata added",
			free,
			regWith(fMeta, metadata([32]byte{0x44})),
			true,
			"",
		},
		{
			"unpinned relays, other VRF key",
			free,
			regWith(fVRF, otherVRF),
			false,
			"VRF key hash",
		},
		{
			"unpinned relays, pledge above maximum",
			free,
			regWith(fPledge, uint64(600_000_001)),
			false,
			"pledge",
		},
		{
			"unpinned relays, cost above maximum",
			free,
			regWith(fCost, uint64(170_000_001)),
			false,
			"cost",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			k := testKeys
			k.Pins = c.pins
			body := baseBody().with(4, certs(c.cert)).cbor()

			d, err := Evaluate(testProfile, k, RoleCold, conway, body)

			switch {
			case c.allow && err != nil:
				t.Fatalf("refused: %v", err)
			case !c.allow && err == nil:
				t.Fatalf("signed: %s", d.Summary)
			case !c.allow && !strings.Contains(err.Error(), c.refusal):
				t.Fatalf(
					"refused by another rule: %v (want %q)",
					err,
					c.refusal,
				)
			}
		})
	}
}

// TestEvaluatePinsOnlyGuardRegistrations: pins bind pool registrations, not
// the other certificates a pinned profile signs.
func TestEvaluatePinsOnlyGuardRegistrations(t *testing.T) {
	t.Parallel()

	k := testKeys
	k.Pins = testPins()
	k.Pins.PledgeMin = 1

	if _, err := Evaluate(testProfile, k, RoleCold, uint(ledger.TxTypeConway),
		baseBody().with(4, certs(retire(k.Pool))).cbor()); err != nil {
		t.Fatalf("retirement refused under pins: %v", err)
	}
}

func TestEvaluateSummaryShowsPinnedFields(t *testing.T) {
	t.Parallel()

	vrf := bytes.Repeat([]byte{0xab, 0xcd}, 16)
	one := baseBody().with(4, certs(func() []any {
		c := regWith(fVRF, vrf)
		c[fMeta] = metadata([32]byte{0x44, 0x55})

		return c
	}())).cbor()

	d, err := Evaluate(
		testProfile,
		testKeys,
		RoleCold,
		uint(ledger.TxTypeConway),
		one,
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{" vrf=abcdabcd ", " meta=4455"} {
		if !strings.Contains(d.Summary+" ", want) {
			t.Errorf("summary %q lacks %q", d.Summary, want)
		}
	}

	none, err := Evaluate(
		testProfile,
		testKeys,
		RoleCold,
		uint(ledger.TxTypeConway),
		baseBody().with(4, certs(poolReg(testKeys.Pool, testKeys.Owner))).
			cbor(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(none.Summary, " meta=none") {
		t.Errorf("summary %q lacks meta=none", none.Summary)
	}
}

// TestEvaluateMetadataHashLength: the ledger stores a pool metadata hash as
// an unbounded byte string, so a registration can carry a short or long one.
// It must be summarized without a panic, and under pins only the exact
// pinned 32 bytes match.
func TestEvaluateMetadataHashLength(t *testing.T) {
	t.Parallel()

	conway := uint(ledger.TxTypeConway)
	pinned := pinnedMeta()

	withMeta := testPins()
	withMeta.MetadataHash = pinned

	meta := func(h []byte) []any { return []any{"https://example.test/p.json", h} }

	for _, c := range []struct {
		name  string
		pins  *profile.Pins
		hash  []byte
		allow bool
		want  string
	}{
		{"empty hash, no pins", nil, []byte{}, true, " meta="},
		{"short hash, no pins", nil, []byte{0x44, 0x55}, true, " meta=4455"},
		{"short pinned prefix", withMeta, pinned[:31], false, "metadata"},
		{"long hash with pinned prefix", withMeta, append(append([]byte(nil), pinned[:]...), 0), false, "metadata"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			k := testKeys
			k.Pins = c.pins
			body := baseBody().with(4, certs(regWith(fMeta, meta(c.hash)))).
				cbor()

			d, err := Evaluate(testProfile, k, RoleCold, conway, body)

			switch {
			case c.allow && err != nil:
				t.Fatalf("refused: %v", err)
			case c.allow && !strings.HasSuffix(d.Summary, c.want):
				t.Fatalf("summary %q does not end in %q", d.Summary, c.want)
			case !c.allow && err == nil:
				t.Fatalf("signed: %s", d.Summary)
			case !c.allow && !strings.Contains(err.Error(), c.want):
				t.Fatalf("refused by another rule: %v (want %q)", err, c.want)
			}
		})
	}
}

// TestRelaysDigest pins the digest encoding: blake2b-160 of the CBOR array
// [relays, url], with no relays and a nil list alike, and address relays
// encoded the same whether built from parsed text or decoded from a
// registration.
func TestRelaysDigest(t *testing.T) {
	t.Parallel()

	url := metaURL
	enc, _ := cbor.Marshal([]any{[]any{relayCBOR("relay.example", 3001)}, url})
	want, _ := blake2b.New(profile.RelaysDigestSize, nil)
	want.Write(enc)

	if got := mustDigest([]common.PoolRelay{hostRelay("relay.example", 3001)}, &url); !bytes.Equal(
		got[:],
		want.Sum(nil),
	) {
		t.Errorf("digest %x, want %x", got, want.Sum(nil))
	}

	if mustDigest(nil, nil) != mustDigest([]common.PoolRelay{}, nil) {
		t.Error("a nil relay list and an empty one differ")
	}

	if mustDigest(nil, nil) == mustDigest(nil, new(string)) {
		t.Error("no metadata and an empty metadata URL collide")
	}

	// an address relay decoded from a registration matches one built from text
	reg := regWith(
		fRelays,
		[]any{
			[]any{
				uint64(0),
				uint64(3001),
				[]byte{1, 2, 3, 4},
				net.ParseIP("2001:db8::1").To16(),
			},
		},
	)

	var cert common.PoolRegistrationCertificate
	if err := cert.UnmarshalCBOR(encode(reg)); err != nil {
		t.Fatal(err)
	}

	port := uint32(3001)
	v4, v6 := net.ParseIP("1.2.3.4"), net.ParseIP("2001:db8::1")
	built := common.PoolRelay{
		Type: common.PoolRelayTypeSingleHostAddress,
		Port: &port,
		Ipv4: &v4,
		Ipv6: &v6,
	}

	if mustDigest(
		cert.Relays,
		nil,
	) != mustDigest(
		[]common.PoolRelay{built},
		nil,
	) {
		t.Error("decoded and built address relays digest differently")
	}
}
