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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/blinklabs-io/bursa/armory/device"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"
)

const (
	coldID  uint32 = 0x20e50011
	profile        = "otg@preview"
)

// fakeChip is a minimal software SE050 (device's own fake is in its tests).
type fakeChip struct {
	keys map[uint32]ed25519.PrivateKey
	bins map[uint32][]byte
}

func (c *fakeChip) Exists(id uint32) (bool, error) {
	_, k := c.keys[id]
	_, b := c.bins[id]

	return k || b, nil
}

func (c *fakeChip) GenerateEd25519(id uint32, _ bool) error {
	_, priv, _ := ed25519.GenerateKey(nil)
	c.keys[id] = priv

	return nil
}

func (c *fakeChip) ImportEd25519(id uint32, seed []byte, _ bool) error {
	c.keys[id] = ed25519.NewKeyFromSeed(seed)
	return nil
}

func (c *fakeChip) PublicKeyEd25519(id uint32) (ed25519.PublicKey, error) {
	k, ok := c.keys[id]
	if !ok {
		return nil, errors.New("no key")
	}

	return k.Public().(ed25519.PublicKey), nil
}

func (c *fakeChip) SignEd25519(id uint32, msg []byte) ([]byte, error) {
	k, ok := c.keys[id]
	if !ok {
		return nil, errors.New("no key")
	}

	return ed25519.Sign(k, msg), nil
}

func (c *fakeChip) WriteBinary(id uint32, data []byte) error {
	c.bins[id] = bytes.Clone(data)
	return nil
}

func (c *fakeChip) ReadBinary(id uint32) ([]byte, error) {
	b, ok := c.bins[id]
	if !ok {
		return nil, errors.New("no object")
	}

	return bytes.Clone(b), nil
}

var testReward = "e0" + strings.Repeat("ee", 28)

type rig struct {
	s        *session
	identity ed25519.PublicKey
	pool     ed25519.PublicKey
	owner    ed25519.PublicKey
	srv      *httptest.Server
}

func devicePost(t *testing.T, srv *httptest.Server, path string, req, resp any) {
	t.Helper()

	b, _ := json.Marshal(req)

	res, err := http.Post(srv.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}

	defer res.Body.Close()

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(res.Body)

	if res.StatusCode != http.StatusOK {
		t.Fatalf("POST %s: %s %s", path, res.Status, buf.String())
	}

	if err := json.Unmarshal(buf.Bytes(), resp); err != nil {
		t.Fatal(err)
	}
}

// newRig serves a real device.Service on a fake chip, provisioned through its
// own endpoints: identity, cold key import and profile (chain counter 3).
func newRig(t *testing.T) *rig {
	t.Helper()

	svc := device.New(&sync.Mutex{}, t.Logf)

	if err := svc.SetChip(&fakeChip{keys: map[uint32]ed25519.PrivateKey{}, bins: map[uint32][]byte{}}); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(svc.Handler())
	t.Cleanup(srv.Close)

	var id device.IdentityResponse

	devicePost(t, srv, "/provision/identity", struct{}{}, &id)

	var cold device.ColdResponse

	devicePost(t, srv, "/provision/cold", device.ColdRequest{
		ColdKeyID: coldID, SigningKey: "5820" + strings.Repeat("42", 32),
	}, &cold)

	chain := uint64(3)

	var prov device.ProvisionResponse

	devicePost(t, srv, "/provision/profile", device.ProvisionRequest{
		Name: profile, Slot: 0, ColdKeyID: coldID, ChainCounter: &chain, RewardAccount: testReward,
	}, &prov)

	pool, _ := hex.DecodeString(cold.PublicKey)

	return &rig{
		s:        &session{c: newClient(srv.URL, ""), identity: id.PublicKey, profile: profile},
		identity: id.PublicKey, pool: pool, owner: prov.OwnerPublicKey, srv: srv,
	}
}

// conwayBody is a testnet body with certificates, as in the device tests.
func conwayBody(certs ...[]any) []byte {
	payer := append([]byte{0x60}, bytes.Repeat([]byte{0xc3}, 28)...)

	b, err := cbor.Marshal(map[uint64]any{
		0: []any{[]any{make([]byte, 32), uint64(0)}},
		1: []any{[]any{payer, uint64(5_000_000)}},
		2: uint64(200_000),
		4: certs,
	})
	if err != nil {
		panic(err)
	}

	return b
}

// tx is [body, witness set, is_valid, auxiliary data], the body spliced in
// raw.
func tx(body []byte) []byte {
	return append(append([]byte{0x84}, body...), 0xa0, 0xf5, 0xf6)
}

func txEnvelope(t *testing.T, dir string, body []byte) string {
	t.Helper()

	p := filepath.Join(dir, "tx.unsigned")

	if err := os.WriteFile(p, marshalEnvelope("Unwitnessed Tx ConwayEra", "Unwitnessed Tx", tx(body)), 0o600); err != nil {
		t.Fatal(err)
	}

	return p
}

func retirement(pool [28]byte) []any { return []any{uint64(4), pool[:], uint64(900)} }

func TestKeys(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	dir := t.TempDir()

	var out bytes.Buffer

	if err := r.s.keys(dir, "preview", &out); err != nil {
		t.Fatal(err)
	}

	pool := hash224(r.pool)
	owner := hash224(r.owner)

	for name, want := range map[string]struct{ typ, desc string }{
		"pool-cold.vkey": {poolVkeyType, poolVkeyDesc},
		"owner.vkey":     {stakeVkeyType, stakeVkeyDesc},
	} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}

		env, raw, err := readEnvelope(b)
		if err != nil || env.Type != want.typ || env.Description != want.desc {
			t.Fatalf("%s: %+v %v", name, env, err)
		}

		pub := r.pool
		if name == "owner.vkey" {
			pub = r.owner
		}

		if !bytes.Equal(raw, append([]byte{0x58, 0x20}, pub...)) {
			t.Fatalf("%s cborHex = %x", name, raw)
		}
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 5 {
		t.Fatalf("output %q", out.String())
	}

	for i, prefix := range []string{
		"pool id hex " + hex.EncodeToString(pool[:]),
		"pool id bech32 pool1",
		"owner key hash " + hex.EncodeToString(owner[:]),
		"owner stake_vk stake_vk1",
		"owner reward address stake_test1",
	} {
		if !strings.HasPrefix(lines[i], prefix) {
			t.Errorf("line %d = %q, want prefix %q", i, lines[i], prefix)
		}
	}

	hrp, data, err := fromBech32(strings.TrimPrefix(lines[1], "pool id bech32 "))
	if err != nil || hrp != "pool" || !bytes.Equal(data, pool[:]) {
		t.Errorf("pool bech32 does not decode to the pool id: %s %x %v", hrp, data, err)
	}

	// the reward address the device profile pins is the owner's, which is
	// what `reward-hex` must hand to /provision/profile
	rh, err := rewardHex(strings.TrimPrefix(lines[4], "owner reward address "))
	if err != nil || rh != "e0"+hex.EncodeToString(owner[:]) {
		t.Errorf("reward hex = %s, %v", rh, err)
	}
}

func TestKeysRejectsWrongIdentity(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	other, _, _ := ed25519.GenerateKey(nil)
	r.s.identity = other

	dir := t.TempDir()

	err := r.s.keys(dir, "preview", &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "attestation") {
		t.Fatalf("err = %v, want an attestation failure", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "pool-cold.vkey")); err == nil {
		t.Fatal("key file written for an unattested inventory")
	}
}

func TestVerifyInventoryRefusals(t *testing.T) {
	t.Parallel()

	_, priv, _ := ed25519.GenerateKey(nil)
	id := priv.Public().(ed25519.PublicKey)
	nonce := bytes.Repeat([]byte{1}, 32)
	k1, k2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)

	signed := func(version string, keys []device.KeyInfo, n []byte) device.Inventory {
		return device.Inventory{Version: version, Keys: keys, Attestation: ed25519.Sign(priv, device.InventoryBinding(n, keys))}
	}
	both := []device.KeyInfo{{Role: "pool", PublicKey: k1}, {Role: "stake", PublicKey: k2}}

	if _, err := verifyInventory(id, nonce, signed(device.Protocol, both, nonce)); err != nil {
		t.Fatalf("valid inventory refused: %v", err)
	}

	for name, inv := range map[string]device.Inventory{
		"version":      signed("other/1", both, nonce),
		"nonce":        signed(device.Protocol, both, []byte("another nonce")),
		"missing role": signed(device.Protocol, both[:1], nonce),
		"duplicate":    signed(device.Protocol, append([]device.KeyInfo{both[0]}, both...), nonce),
		"short key":    signed(device.Protocol, []device.KeyInfo{{Role: "pool", PublicKey: k1[:5]}, both[1]}, nonce),
	} {
		if _, err := verifyInventory(id, nonce, inv); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWitness(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	dir := t.TempDir()
	body := conwayBody(retirement(hash224(r.pool)))
	txFile := txEnvelope(t, dir, body)
	out := filepath.Join(dir, "pool.witness")

	if err := r.s.witness("pool", txFile, out); err != nil {
		t.Fatal(err)
	}

	b, _ := os.ReadFile(out)

	env, raw, err := readEnvelope(b)
	if err != nil || env.Type != "TxWitness ConwayEra" || env.Description != "Detached vkey witness" {
		t.Fatalf("envelope %+v %v", env, err)
	}

	var wit []cbor.RawMessage

	if err = cbor.Unmarshal(raw, &wit); err != nil || len(wit) != 2 {
		t.Fatalf("witness %x: %v", raw, err)
	}

	var vkey, sig []byte

	_ = cbor.Unmarshal(wit[0], &vkey)
	_ = cbor.Unmarshal(wit[1], &sig)

	hash := blake2b.Sum256(body)

	if !bytes.Equal(vkey, r.pool) || !ed25519.Verify(vkey, hash[:], sig) {
		t.Fatal("witness is not the pool key's signature over blake2b-256(body)")
	}

	// the owner key is selected by role
	ownerBody := conwayBody([]any{uint64(11), []any{uint64(0), func() []byte { h := hash224(r.owner); return h[:] }()},
		func() []byte { h := hash224(r.pool); return h[:] }(), uint64(2_000_000)})

	if err = r.s.witness("stake", txEnvelope(t, dir, ownerBody), filepath.Join(dir, "owner.witness")); err != nil {
		t.Fatal(err)
	}
}

func TestWitnessRefusal(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "pool.witness")

	// a retirement of another pool is refused by the device policy
	err := r.s.witness("pool", txEnvelope(t, dir, conwayBody(retirement([28]byte{1}))), out)
	if err == nil || !strings.Contains(err.Error(), "device refused") {
		t.Fatalf("err = %v, want a device refusal", err)
	}

	if _, err := os.Stat(out); err == nil {
		t.Fatal("witness written for a refused request")
	}
}

func TestTxBodyIsExactRawBytes(t *testing.T) {
	t.Parallel()

	// a body whose map keys are in descending order and whose integers are
	// not shortest-form: a decode and re-encode would change both
	body := []byte{0xa2, 0x02, 0x19, 0x00, 0x05, 0x01, 0x80}

	got, err := txBody(tx(body))
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("body = %x, %v; want %x", got, err, body)
	}

	for name, raw := range map[string][]byte{
		"not an array":  {0xa0},
		"short array":   {0x82, 0xa0, 0xa0},
		"indefinite":    {0x9f, 0xff},
		"truncated tx":  {0x84, 0xa0},
		"empty":         {},
		"array of five": {0x85, 0xa0, 0xa0, 0xf5, 0xf6, 0x00},
	} {
		if _, err := txBody(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestReadTxRefusesOtherTypes(t *testing.T) {
	t.Parallel()

	for _, typ := range []string{"TxWitness ConwayEra", "Unwitnessed Tx BabbageEra", ""} {
		if _, err := readTx(marshalEnvelope(typ, "", tx(nil))); err == nil {
			t.Errorf("type %q accepted", typ)
		}
	}

	if _, err := readTx(marshalEnvelope("Tx ConwayEra", "", []byte{0x84})); err != nil {
		t.Errorf("signed Conway envelope refused: %v", err)
	}
}

func TestCheckTxBodyRefusals(t *testing.T) {
	t.Parallel()

	_, priv, _ := ed25519.GenerateKey(nil)
	pub := priv.Public().(ed25519.PublicKey)
	body := []byte{0xa0}
	nonce := bytes.Repeat([]byte{9}, 32)
	req := txBodyRequest(profile, "pool", pub, nonce, body)

	hash := blake2b.Sum256(body)
	good := func() device.SignResponse {
		sig := ed25519.Sign(priv, hash[:])

		return device.SignResponse{
			Version: device.Protocol, Nonce: nonce, Signature: sig,
			BindingSignature: ed25519.Sign(priv, device.ResponseBinding(req, sig)),
		}
	}

	if _, err := checkTxBody(req, good(), pub); err != nil {
		t.Fatalf("valid response refused: %v", err)
	}

	for name, mutate := range map[string]func(*device.SignResponse){
		"version":   func(r *device.SignResponse) { r.Version = "x" },
		"nonce":     func(r *device.SignResponse) { r.Nonce = []byte("other") },
		"error":     func(r *device.SignResponse) { r.Error = "no" },
		"signature": func(r *device.SignResponse) { r.Signature = ed25519.Sign(priv, []byte("other")) },
		"binding": func(r *device.SignResponse) {
			r.BindingSignature = bytes.Clone(r.BindingSignature)
			r.BindingSignature[0] ^= 1
		},
		"missing binding": func(r *device.SignResponse) { r.BindingSignature = nil },
	} {
		resp := good()
		mutate(&resp)

		if _, err := checkTxBody(req, resp, pub); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOpCert(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	dir := t.TempDir()
	kes := bytes.Repeat([]byte{0x5a}, 32)
	kesFile := filepath.Join(dir, "kes.vkey")

	if err := os.WriteFile(kesFile, marshalEnvelope("KesVerificationKey_ed25519_kes_2^6", "", vkeyCBOR(kes)), 0o600); err != nil {
		t.Fatal(err)
	}

	cert := filepath.Join(dir, "node.cert")

	var out bytes.Buffer

	// the profile floor is 3, so the chain counter 3 gives issue 4
	if err := r.s.opcert(kesFile, 7, "3", cert, &out); err != nil {
		t.Fatal(err)
	}

	if out.String() != "issue counter 4\n" {
		t.Fatalf("stdout = %q", out.String())
	}

	b, _ := os.ReadFile(cert)

	env, raw, err := readEnvelope(b)
	if err != nil || env.Type != "NodeOperationalCertificate" || env.Description != "Operational Certificate" {
		t.Fatalf("envelope %+v %v", env, err)
	}

	var oc struct {
		_    struct{} `cbor:",toarray"`
		Body struct {
			_      struct{} `cbor:",toarray"`
			KES    []byte
			Issue  uint64
			Period uint64
			Sig    []byte
		}
		Cold []byte
	}

	if err = cbor.Unmarshal(raw, &oc); err != nil {
		t.Fatal(err)
	}

	signable := binary.BigEndian.AppendUint64(bytes.Clone(kes), 4)
	signable = binary.BigEndian.AppendUint64(signable, 7)

	if !bytes.Equal(oc.Body.KES, kes) || oc.Body.Issue != 4 || oc.Body.Period != 7 ||
		!bytes.Equal(oc.Cold, r.pool) || !ed25519.Verify(r.pool, signable, oc.Body.Sig) {
		t.Fatalf("certificate %+v", oc)
	}

	// "none" is chain counter 0, which the profile floor of 3 refuses
	err = r.s.opcert(kesFile, 7, "none", cert, &out)
	if err == nil || !strings.Contains(err.Error(), "device refused") {
		t.Fatalf("err = %v, want a refusal below the floor", err)
	}
}

func TestCheckOpCertIssueCounter(t *testing.T) {
	t.Parallel()

	_, priv, _ := ed25519.GenerateKey(nil)
	pub := priv.Public().(ed25519.PublicKey)
	kes := bytes.Repeat([]byte{1}, 32)
	nonce := bytes.Repeat([]byte{9}, 32)
	req := opCertRequest(profile, pub, nonce, kes, 5, 11)

	resp := func(issue *uint64, signed uint64) device.SignResponse {
		sig := ed25519.Sign(priv, opCertPayload(kes, signed, 11))

		return device.SignResponse{
			Version: device.Protocol, Nonce: nonce, Signature: sig, IssueCounter: issue,
			BindingSignature: ed25519.Sign(priv, device.ResponseBinding(req, sig)),
		}
	}
	u := func(v uint64) *uint64 { return &v }

	if _, issue, err := checkOpCert(req, resp(u(6), 6), pub, 5, 11); err != nil || issue != 6 {
		t.Fatalf("valid response: %d %v", issue, err)
	}

	for name, r := range map[string]device.SignResponse{
		"no counter":     resp(nil, 6),
		"same counter":   resp(u(5), 5),
		"skipped":        resp(u(7), 7),
		"signed another": resp(u(6), 7),
	} {
		if _, _, err := checkOpCert(req, r, pub, 5, 11); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// goldenBody is a Conway body retiring pool 0x01 x28, as `bursa tx witness`
// signed it.
var goldenBody, _ = hex.DecodeString("a40081825820000000000000000000000000000000000000000000000000000000000000000000018182581d60c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c31a004c4b40021a00030d4004818304581c01010101010101010101010101010101010101010101010101010101190384")

const goldenWitness = `{
    "type": "TxWitness ConwayEra",
    "description": "Detached vkey witness",
    "cborHex": "8258202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db1258403e9746de473b8943e0431d29f1c6dc9beef5a2276148c336f399bef207521b0e5fc93c0229e58a1c7f7525c3028b66593966fe7ddc6585a84647ffc84c3cd401"
}
`

// goldenOpCert has no trailing newline: bursa writes a fixed template.
const goldenOpCert = `{
    "type": "NodeOperationalCertificate",
    "description": "Operational Certificate",
    "cborHex": "828458205a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a040758407c081765657151e9049bd11ee8653a2b4aa64393ff15d5f06ea501ad66d905850d45a159fe92bdc8b0934e7e685a0a9fbc4b6af577c8ed6089cd74d54242fc0b58202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
}`

// Goldens: bursa v0.x `bursa tx witness` and `bursa cert op-cert --out` run
// on the same inputs (signing key seed 0x42 x32, the body below, KES key
// 0x5a x32), whose code is internal/cli/tx.go:80-105 (RunTxWitness, via
// bursa.WriteCborEnvelope, envelope.go:73) and internal/cli/cli.go:1288-1301
// (op-cert --out template). The tests must reproduce those files byte for
// byte.
func TestWitnessMatchesBursaFormat(t *testing.T) {
	t.Parallel()

	seed := bytes.Repeat([]byte{0x42}, 32)
	key := ed25519.NewKeyFromSeed(seed)
	pub := key.Public().(ed25519.PublicKey)
	hash := blake2b.Sum256(goldenBody)
	sig := ed25519.Sign(key, hash[:])

	wit, err := witnessCBOR(pub, sig)
	if err != nil {
		t.Fatal(err)
	}

	if got := string(marshalEnvelope(witnessType, witnessDesc, wit)); got != goldenWitness {
		t.Fatalf("witness file differs from bursa tx witness:\n%s\nwant\n%s", got, goldenWitness)
	}
}

func TestOpCertMatchesBursaFormat(t *testing.T) {
	t.Parallel()

	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, 32))
	pub := key.Public().(ed25519.PublicKey)
	kes := bytes.Repeat([]byte{0x5a}, 32)
	sig := ed25519.Sign(key, opCertPayload(kes, 4, 7))

	raw, err := opCertCBOR(kes, 4, 7, sig, pub)
	if err != nil {
		t.Fatal(err)
	}

	if got := string(marshalOpCertEnvelope(raw)); got != goldenOpCert {
		t.Fatalf("op cert file differs from bursa cert op-cert:\n%s\nwant\n%s", got, goldenOpCert)
	}
}

// Goldens: `bursa address build --payment-key addr_vk1zyg3... --stake-key
// stake_vk1yg3z... --network preview|mainnet [--type reward]`, with the
// payment key 0x11 x32 and the stake key 0x22 x32 (internal/cli address
// build, address code in the bursa module).
func TestAddressMatchesBursa(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	write := func(name, typ string, b byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, marshalEnvelope(typ, "", vkeyCBOR(bytes.Repeat([]byte{b}, 32))), 0o600); err != nil {
			t.Fatal(err)
		}

		return p
	}
	payment, stake := write("payment.vkey", paymentVkeyType, 0x11), write("stake.vkey", stakeVkeyType, 0x22)

	for _, c := range []struct{ typ, network, want string }{
		{"base", "preview", "addr_test1qzx0qqs06evy77cnpk6u5q3fc50exjpp5t4s0swl2ykc4j33xvvd6k63kqmky78w3u4d8rxlj3ndfqlxpscjg2ykf7hsj0nzkg"},
		{"base", "mainnet", "addr1qxx0qqs06evy77cnpk6u5q3fc50exjpp5t4s0swl2ykc4j33xvvd6k63kqmky78w3u4d8rxlj3ndfqlxpscjg2ykf7hs3ewz6h"},
		{"reward", "preview", "stake_test1uqcnxxxatdgmqdmz0rhg72kn3n0egek5s0nqcvfy9ztyltc9cpuz4"},
	} {
		var out bytes.Buffer

		if err := address(payment, stake, c.typ, c.network, &out); err != nil {
			t.Fatal(err)
		}

		if out.String() != c.want+"\n" {
			t.Errorf("%s %s = %q, want %q", c.typ, c.network, out.String(), c.want)
		}
	}

	// a reward address needs no payment key, a base address does
	if err := address("", stake, "reward", "preview", &bytes.Buffer{}); err != nil {
		t.Errorf("reward without payment key: %v", err)
	}

	if err := address("", stake, "base", "preview", &bytes.Buffer{}); err == nil {
		t.Error("base address without payment key")
	}

	if err := address(stake, stake, "base", "preview", &bytes.Buffer{}); err == nil {
		t.Error("stake key accepted as payment key")
	}
}

func TestRewardHex(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer

	if err := run([]string{"reward-hex", "stake_test1uqcnxxxatdgmqdmz0rhg72kn3n0egek5s0nqcvfy9ztyltc9cpuz4"}, &out); err != nil {
		t.Fatal(err)
	}

	h := hash224(bytes.Repeat([]byte{0x22}, 32))

	if want := "e0" + hex.EncodeToString(h[:]) + "\n"; out.String() != want {
		t.Fatalf("stdout = %q, want %q", out.String(), want)
	}

	// a base address and a bad checksum are not reward addresses
	for _, a := range []string{
		"addr_test1qzx0qqs06evy77cnpk6u5q3fc50exjpp5t4s0swl2ykc4j33xvvd6k63kqmky78w3u4d8rxlj3ndfqlxpscjg2ykf7hsj0nzkg",
		"stake_test1uqcnxxxatdgmqdmz0rhg72kn3n0egek5s0nqcvfy9ztyltc9cpuz5",
		"pool1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygszssxcu",
	} {
		if err := run([]string{"reward-hex", a}, &bytes.Buffer{}); err == nil {
			t.Errorf("%s accepted", a)
		}
	}
}

func TestRunRequiresPinnedIdentity(t *testing.T) {
	t.Parallel()

	if err := run([]string{"-profile", "p", "keys", "-out-dir", t.TempDir()}, &bytes.Buffer{}); err == nil {
		t.Fatal("keys ran without -identity")
	}
}

func TestKeysCreatesOutDir(t *testing.T) {
	t.Parallel()

	r := newRig(t)
	dir := filepath.Join(t.TempDir(), "device")

	if err := r.s.keys(dir, "preview", io.Discard); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(dir, "owner.vkey")); err != nil {
		t.Fatal(err)
	}
}
