package multisig

import (
	"context"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	apollo "github.com/blinklabs-io/apollo/v2"
	"github.com/blinklabs-io/apollo/v2/backend"
	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/bip32"
	"github.com/blinklabs-io/bursa/ui/internal/keystore"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/shelley"
	"github.com/blinklabs-io/plutigo/data"
	utxorpc "github.com/utxorpc/go-codegen/utxorpc/v1alpha/cardano"
)

// Two distinct 24-word "abandon" test vectors so we can derive two independent
// multi-sig participant identities.
const mnemonicA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

const mnemonicB = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"

// multiSigKeyHash derives a mnemonic's CIP-1854 multi-sig payment vkey + key-hash.
func multiSigKeyHash(t *testing.T, mnemonic string) (vkeyHex, keyHashHex string, skey bip32.XPrv) {
	t.Helper()
	root, err := bursa.GetRootKeyFromMnemonic(mnemonic, "")
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	acct, err := bursa.GetMultiSigAccountKey(root, 0)
	if err != nil {
		t.Fatalf("multisig account key: %v", err)
	}
	pay, err := bursa.GetMultiSigPaymentKey(acct, 0)
	if err != nil {
		t.Fatalf("multisig payment key: %v", err)
	}
	vkey := pay.Public().PublicKey()
	kh := lcommon.Blake2b224Hash(vkey)
	return hex.EncodeToString(vkey), hex.EncodeToString(kh.Bytes()), pay
}

// --- fakeChain (mirrors the spend package's test harness) ------------------

type fakeChain struct {
	utxos      map[string][]lcommon.Utxo
	pp         backend.ProtocolParameters
	submitHash lcommon.Blake2b256
	submitCbor []byte
	submitMu   sync.Mutex
}

func newFakeChain() *fakeChain {
	var h lcommon.Blake2b256
	b, _ := hex.DecodeString("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	copy(h[:], b)
	return &fakeChain{
		utxos: map[string][]lcommon.Utxo{},
		pp: backend.ProtocolParameters{
			MinFeeConstant:    155381,
			MinFeeCoefficient: 44,
			MaxTxSize:         16384,
			CoinsPerUtxoByte:  "4310",
			KeyDeposits:       "2000000",
			PoolDeposits:      "500000000",
		},
		submitHash: h,
	}
}

func (fc *fakeChain) addUTxO(addr, txHashHex string, outIdx uint32, lovelace uint64) {
	var txID lcommon.Blake2b256
	b, _ := hex.DecodeString(txHashHex)
	copy(txID[:], b)
	input := shelley.ShelleyTransactionInput{TxId: txID, OutputIndex: outIdx}
	a, _ := lcommon.NewAddress(addr)
	fc.utxos[addr] = append(fc.utxos[addr], lcommon.Utxo{
		Id:     input,
		Output: &fakeOutput{address: a, lovelace: lovelace},
	})
}

type fakeOutput struct {
	address  lcommon.Address
	lovelace uint64
}

func (o *fakeOutput) Address() lcommon.Address { return o.address }
func (o *fakeOutput) Amount() *big.Int         { return new(big.Int).SetUint64(o.lovelace) }
func (o *fakeOutput) Assets() *lcommon.MultiAsset[lcommon.MultiAssetTypeOutput] {
	return nil
}
func (o *fakeOutput) Datum() *lcommon.Datum               { return nil }
func (o *fakeOutput) DatumHash() *lcommon.Blake2b256      { return nil }
func (o *fakeOutput) Cbor() []byte                        { return nil }
func (o *fakeOutput) Utxorpc() (*utxorpc.TxOutput, error) { return nil, nil }
func (o *fakeOutput) ScriptRef() lcommon.Script           { return nil }
func (o *fakeOutput) ToPlutusData() data.PlutusData       { return nil }
func (o *fakeOutput) String() string                      { return o.address.String() }

func (fc *fakeChain) ProtocolParams(_ context.Context) (backend.ProtocolParameters, error) {
	return fc.pp, nil
}
func (fc *fakeChain) GenesisParams(_ context.Context) (backend.GenesisParameters, error) {
	return backend.GenesisParameters{ActiveSlotsCoefficient: 0.05, EpochLength: 432000, SlotLength: 1, NetworkMagic: 1}, nil
}
func (fc *fakeChain) NetworkId() uint8                               { return 0 }
func (fc *fakeChain) CurrentEpoch(_ context.Context) (uint64, error) { return 500, nil }
func (fc *fakeChain) MaxTxFee(_ context.Context) (uint64, error) {
	return backend.ComputeMaxTxFee(fc.pp)
}
func (fc *fakeChain) Tip(_ context.Context) (uint64, error) { return 10_000_000, nil }
func (fc *fakeChain) Utxos(_ context.Context, address lcommon.Address) ([]lcommon.Utxo, error) {
	return fc.utxos[address.String()], nil
}
func (fc *fakeChain) SubmitTx(_ context.Context, tx []byte) (lcommon.Blake2b256, error) {
	fc.submitMu.Lock()
	fc.submitCbor = append(fc.submitCbor[:0], tx...)
	fc.submitMu.Unlock()
	return fc.submitHash, nil
}
func (fc *fakeChain) EvaluateTx(_ context.Context, _ []byte, _ []lcommon.Utxo) (map[lcommon.RedeemerKey]lcommon.ExUnits, error) {
	return nil, nil
}
func (fc *fakeChain) UtxoByRef(_ context.Context, txHash lcommon.Blake2b256, index uint32) (*lcommon.Utxo, error) {
	for _, utxos := range fc.utxos {
		for _, u := range utxos {
			if u.Id.Id() == txHash && u.Id.Index() == index {
				cp := u
				return &cp, nil
			}
		}
	}
	return nil, nil
}
func (fc *fakeChain) ScriptCbor(_ context.Context, _ lcommon.Blake2b224) ([]byte, error) {
	return nil, nil
}

// --- fake keystore ---------------------------------------------------------

// fakeKeystore implements the multisig.Keystore interface in memory, returning
// the configured mnemonic for the right password — avoiding scrypt's cost in
// tests. A wrong password yields keystore.ErrDecryptFailed, matching the real
// keystore so the ErrWrongPassword mapping is exercised.
type fakeKeystore struct {
	mnemonic string
	password string
}

func (k *fakeKeystore) Exists() bool { return k.mnemonic != "" }
func (k *fakeKeystore) Unlock(password string) ([]byte, error) {
	if password != k.password {
		return nil, keystore.ErrDecryptFailed
	}
	return []byte(k.mnemonic), nil
}

func newTestKeystore(_ *testing.T, mnemonic string) *fakeKeystore {
	return &fakeKeystore{mnemonic: mnemonic, password: "test-password-123"}
}

// --- tests -----------------------------------------------------------------

func TestComposeScriptThresholdAndAddress(t *testing.T) {
	_, khA, _ := multiSigKeyHash(t, mnemonicA)
	_, khB, _ := multiSigKeyHash(t, mnemonicB)

	pol := Policy{
		Threshold:    2,
		Participants: []Participant{{KeyHashHex: khA}, {KeyHashHex: khB}},
	}
	script, err := composeScript(pol)
	if err != nil {
		t.Fatalf("composeScript: %v", err)
	}
	if id, err := bursa.GetScriptType(script); err != nil || id != 3 {
		t.Fatalf("expected NofK (type 3), got type %d err %v", id, err)
	}
	addr, err := scriptAddress(script, "preview")
	if err != nil {
		t.Fatalf("scriptAddress: %v", err)
	}
	// The address payment credential must equal the canonical native-script hash
	// (NativeScript.Hash) — the ledger derives the same on spend.
	parsed, err := lcommon.NewAddress(addr)
	if err != nil {
		t.Fatalf("parse addr: %v", err)
	}
	if got := hex.EncodeToString(parsed.PaymentKeyHash().Bytes()); got != hex.EncodeToString(script.Hash().Bytes()) {
		t.Fatalf("address credential %s != script hash %s", got, script.Hash().String())
	}
}

func TestComposeScriptTimelock(t *testing.T) {
	_, khA, _ := multiSigKeyHash(t, mnemonicA)
	before := uint64(1000)
	after := uint64(9_000_000)
	pol := Policy{
		Threshold:     1,
		Participants:  []Participant{{KeyHashHex: khA}},
		InvalidBefore: &before,
		InvalidAfter:  &after,
	}
	script, err := composeScript(pol)
	if err != nil {
		t.Fatalf("composeScript timelock: %v", err)
	}
	// A time-locked policy wraps the threshold in an "all" (type 1).
	if id, err := bursa.GetScriptType(script); err != nil || id != 1 {
		t.Fatalf("expected All (type 1) for timelocked, got type %d err %v", id, err)
	}
}

func TestComposeScriptRejectsBadThreshold(t *testing.T) {
	_, khA, _ := multiSigKeyHash(t, mnemonicA)
	_, err := composeScript(Policy{Threshold: 2, Participants: []Participant{{KeyHashHex: khA}}})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest, got %v", err)
	}
}

func TestCreateListGetDelete(t *testing.T) {
	fc := newFakeChain()
	svc := NewService(fc, nil, filepath.Join(t.TempDir(), "multisig.json"))
	_, khA, _ := multiSigKeyHash(t, mnemonicA)
	_, khB, _ := multiSigKeyHash(t, mnemonicB)

	acct, err := svc.Create(CreateRequest{
		Label:   "treasury",
		Network: "preview",
		Policy:  Policy{Threshold: 2, Participants: []Participant{{KeyHashHex: khA}, {KeyHashHex: khB}}},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if acct.ScriptAddress == "" || acct.ScriptCBOR == "" || acct.ID == "" {
		t.Fatalf("incomplete account: %+v", acct)
	}

	// Persisted: a fresh service reading the same file sees it.
	svc2 := NewService(fc, nil, svc.store.path)
	list, err := svc2.List()
	if err != nil || len(list) != 1 || list[0].ID != acct.ID {
		t.Fatalf("List after reload: %v, %+v", err, list)
	}

	got, err := svc2.Get(acct.ID)
	if err != nil || got.ScriptAddress != acct.ScriptAddress {
		t.Fatalf("Get: %v %+v", err, got)
	}

	if err := svc2.Delete(acct.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := svc2.Get(acct.ID); !errors.Is(err, ErrUnknownAccount) {
		t.Fatalf("expected ErrUnknownAccount after delete, got %v", err)
	}
}

func TestStoreAddRollsBackOnPersistFailure(t *testing.T) {
	s := newStore(filepath.Join(t.TempDir(), "missing", "multisig.json"))
	s.loaded = true
	s.accounts = []Account{{ID: "existing", Label: "existing"}}

	if err := s.add(Account{ID: "new", Label: "new"}); err == nil {
		t.Fatal("add succeeded with unwritable store path, want error")
	}
	if len(s.accounts) != 1 || s.accounts[0].ID != "existing" {
		t.Fatalf("accounts after failed add = %+v, want original existing account", s.accounts)
	}
}

func TestStoreRemoveRollsBackOnPersistFailure(t *testing.T) {
	s := newStore(filepath.Join(t.TempDir(), "missing", "multisig.json"))
	s.loaded = true
	s.accounts = []Account{
		{ID: "a", Label: "a"},
		{ID: "b", Label: "b"},
		{ID: "c", Label: "c"},
	}

	if err := s.remove("b"); err == nil {
		t.Fatal("remove succeeded with unwritable store path, want error")
	}
	if len(s.accounts) != 3 || s.accounts[0].ID != "a" || s.accounts[1].ID != "b" || s.accounts[2].ID != "c" {
		t.Fatalf("accounts after failed remove = %+v, want original a,b,c", s.accounts)
	}
}

func TestMyKeyMatchesParticipantDerivation(t *testing.T) {
	fc := newFakeChain()
	ks := newTestKeystore(t, mnemonicA)
	svc := NewService(fc, ks, filepath.Join(t.TempDir(), "multisig.json"))

	mk, err := svc.MyKey("test-password-123")
	if err != nil {
		t.Fatalf("MyKey: %v", err)
	}
	_, wantKH, _ := multiSigKeyHash(t, mnemonicA)
	if mk.KeyHashHex != wantKH {
		t.Fatalf("MyKey hash %s != derived %s", mk.KeyHashHex, wantKH)
	}
}

func TestMyKeyWrongPassword(t *testing.T) {
	fc := newFakeChain()
	ks := newTestKeystore(t, mnemonicA)
	svc := NewService(fc, ks, filepath.Join(t.TempDir(), "multisig.json"))
	if _, err := svc.MyKey("wrong-password-xx"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("expected ErrWrongPassword, got %v", err)
	}
}

// TestSpendFlow is the end-to-end multi-party test: create a 2-of-2 account, fund
// the script address, build an unsigned spend, have BOTH participants co-sign with
// their CIP-1854 keys, and submit. It asserts the threshold is enforced and that
// submission only succeeds once both witnesses are collected.
func TestSpendFlow(t *testing.T) {
	fc := newFakeChain()
	ksA := newTestKeystore(t, mnemonicA)
	ksB := newTestKeystore(t, mnemonicB)
	_, khA, _ := multiSigKeyHash(t, mnemonicA)
	_, khB, _ := multiSigKeyHash(t, mnemonicB)

	// Participant A's service creates the account (its store).
	svcA := NewService(fc, ksA, filepath.Join(t.TempDir(), "a.json"))
	acct, err := svcA.Create(CreateRequest{
		Label:   "joint",
		Network: "preview",
		Policy:  Policy{Threshold: 2, Participants: []Participant{{KeyHashHex: khA}, {KeyHashHex: khB}}},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Fund the script address with 10 ADA.
	fc.addUTxO(acct.ScriptAddress, "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", 0, 10_000_000)

	// Balance reflects the funded UTxO.
	bal, err := svcA.Balance(context.Background(), acct.ID)
	if err != nil || bal != "10000000" {
		t.Fatalf("Balance = %q err %v, want 10000000", bal, err)
	}

	// Build a spend to a third-party address (reuse khA's own ordinary receive is
	// fine; we just need a valid bech32 — derive a plain payment address).
	recv := externalAddr(t)
	built, err := svcA.Build(context.Background(), acct.ID, BuildRequest{To: recv, Lovelace: "3000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if built.Threshold != 2 || len(built.RequiredSigners) != 2 {
		t.Fatalf("unexpected build metadata: %+v", built)
	}

	// Both participants co-sign (each on their own keyed instance).
	witA, err := svcA.Sign(built.UnsignedTxCBOR, "test-password-123")
	if err != nil {
		t.Fatalf("Sign A: %v", err)
	}
	svcB := NewService(fc, ksB, filepath.Join(t.TempDir(), "b.json"))
	witB, err := svcB.Sign(built.UnsignedTxCBOR, "test-password-123")
	if err != nil {
		t.Fatalf("Sign B: %v", err)
	}

	// Submitting with only one witness must fail the threshold check.
	if _, err := svcA.Submit(context.Background(), acct.ID, built.UnsignedTxCBOR, []string{witA.WitnessCBOR}); !errors.Is(err, ErrInvalidWitness) {
		t.Fatalf("expected ErrInvalidWitness with 1/2 sigs, got %v", err)
	}

	// With both witnesses, submission succeeds.
	res, err := svcA.Submit(context.Background(), acct.ID, built.UnsignedTxCBOR, []string{witA.WitnessCBOR, witB.WitnessCBOR})
	if err != nil {
		t.Fatalf("Submit 2/2: %v", err)
	}
	if res.TxHash == "" {
		t.Fatal("expected non-empty tx hash")
	}

	// The submitted tx must carry the native script and exactly the two vkey
	// witnesses (so the ledger can validate the 2-of-2 against the script).
	assertSubmittedWitnesses(t, fc, acct, khA, khB)
}

// externalAddr derives a plain CIP-1852 payment address (mnemonicB) as a spend
// recipient distinct from the script address.
func externalAddr(t *testing.T) string {
	t.Helper()
	root, _ := bursa.GetRootKeyFromMnemonic(mnemonicB, "")
	acct, _ := bursa.GetAccountKey(root, 0)
	pay, _ := bursa.GetPaymentKey(acct, 0)
	stake, _ := bursa.GetStakeKey(acct, 0)
	addr, err := lcommon.NewAddressFromParts(
		lcommon.AddressTypeKeyKey, lcommon.AddressNetworkTestnet,
		pay.Public().PublicKey().Hash(), stake.Public().PublicKey().Hash(),
	)
	if err != nil {
		t.Fatalf("external addr: %v", err)
	}
	return addr.String()
}

// assertSubmittedWitnesses decodes the broadcast tx CBOR and checks the witness
// set carries the native script and both participant vkey witnesses.
func assertSubmittedWitnesses(t *testing.T, fc *fakeChain, acct Account, khA, khB string) {
	t.Helper()
	fc.submitMu.Lock()
	raw := append([]byte(nil), fc.submitCbor...)
	fc.submitMu.Unlock()
	if len(raw) == 0 {
		t.Fatal("no tx was submitted")
	}
	loaded, err := apollo.New(fc).LoadTxCbor(hex.EncodeToString(raw))
	if err != nil {
		t.Fatalf("reload submitted tx: %v", err)
	}
	tx := loaded.GetTx()
	if tx == nil {
		t.Fatal("submitted tx has no body")
	}
	ws := tx.WitnessSet
	if len(ws.WsNativeScripts.Items()) == 0 {
		t.Error("submitted tx is missing the native script")
	}
	have := map[string]bool{}
	for _, vw := range ws.VkeyWitnesses.Items() {
		have[hex.EncodeToString(lcommon.Blake2b224Hash(vw.Vkey).Bytes())] = true
	}
	if !have[khA] || !have[khB] {
		t.Errorf("submitted tx missing a participant witness: have %v want %s,%s", have, khA, khB)
	}
}

func TestBuildTimelockValidityInterval(t *testing.T) {
	fc := newFakeChain()
	svc := NewService(fc, nil, filepath.Join(t.TempDir(), "multisig.json"))
	_, khA, _ := multiSigKeyHash(t, mnemonicA)
	before := uint64(1234)
	after := uint64(5678)

	acct, err := svc.Create(CreateRequest{
		Label:   "timelocked",
		Network: "preview",
		Policy: Policy{
			Threshold:     1,
			Participants:  []Participant{{KeyHashHex: khA}},
			InvalidBefore: &before,
			InvalidAfter:  &after,
		},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	fc.addUTxO(acct.ScriptAddress, "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", 0, 10_000_000)

	built, err := svc.Build(context.Background(), acct.ID, BuildRequest{To: externalAddr(t), Lovelace: "3000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	loaded, err := apollo.New(fc).LoadTxCbor(built.UnsignedTxCBOR)
	if err != nil {
		t.Fatalf("reload unsigned tx: %v", err)
	}
	tx := loaded.GetTx()
	if tx == nil {
		t.Fatal("unsigned tx has no body")
	}
	if got := tx.Body.ValidityIntervalStart(); got != before {
		t.Fatalf("validity start = %d, want %d", got, before)
	}
	if got := tx.Body.TTL(); got != after {
		t.Fatalf("ttl = %d, want %d", got, after)
	}

	tooLarge := uint64(math.MaxInt64) + 1
	for _, tc := range []struct {
		name          string
		invalidBefore *uint64
		invalidAfter  *uint64
		want          string
	}{
		{name: "invalid before", invalidBefore: &tooLarge, want: "invalid_before slot out of range"},
		{name: "invalid after", invalidAfter: &tooLarge, want: "invalid_after slot out of range"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acct, err := svc.Create(CreateRequest{
				Label:   tc.name,
				Network: "preview",
				Policy: Policy{
					Threshold:     1,
					Participants:  []Participant{{KeyHashHex: khA}},
					InvalidBefore: tc.invalidBefore,
					InvalidAfter:  tc.invalidAfter,
				},
			})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			fc.addUTxO(acct.ScriptAddress, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 0, 10_000_000)
			_, err = svc.Build(context.Background(), acct.ID, BuildRequest{To: externalAddr(t), Lovelace: "3000000"})
			if !errors.Is(err, ErrInvalidRequest) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Build error = %v, want ErrInvalidRequest containing %q", err, tc.want)
			}
		})
	}
}

func TestBuildNoUTxOs(t *testing.T) {
	fc := newFakeChain()
	svc := NewService(fc, nil, filepath.Join(t.TempDir(), "multisig.json"))
	_, khA, _ := multiSigKeyHash(t, mnemonicA)
	acct, err := svc.Create(CreateRequest{
		Label:   "empty",
		Network: "preview",
		Policy:  Policy{Threshold: 1, Participants: []Participant{{KeyHashHex: khA}}},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.Build(context.Background(), acct.ID, BuildRequest{To: externalAddr(t), Lovelace: "1000000"}); !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("expected ErrInsufficientFunds with no UTxOs, got %v", err)
	}
}
