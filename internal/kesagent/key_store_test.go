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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
	"github.com/blinklabs-io/gouroboros/kes"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// memKeyStore is a KeyStore in memory with the PostgreSQL store's semantics,
// for tests that run without a database. One instance shared by several
// agents stands in for one database.
type memKeyStore struct {
	mu   sync.Mutex
	recs map[string]SealedKey
}

var _ KeyStore = (*memKeyStore)(nil)

func newMemKeyStore() *memKeyStore {
	return &memKeyStore{recs: make(map[string]SealedKey)}
}

func memKey(pool, network, state string) string {
	return pool + "|" + network + "|" + state
}

func cloneSealedKey(r SealedKey) SealedKey {
	r.KESVKey = bytes.Clone(r.KESVKey)
	r.Sealed = bytes.Clone(r.Sealed)
	r.OpCert = bytes.Clone(r.OpCert)
	return r
}

func (m *memKeyStore) PutStaged(
	_ context.Context,
	pool, network string,
	rec SealedKey,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec = cloneSealedKey(rec)
	rec.OpCert, rec.Generation = nil, 0
	m.recs[memKey(pool, network, "staged")] = rec
	return nil
}

func (m *memKeyStore) get(pool, network, state string) (SealedKey, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.recs[memKey(pool, network, state)]
	return cloneSealedKey(r), ok
}

func (m *memKeyStore) Staged(
	_ context.Context,
	pool, network string,
) (SealedKey, bool, error) {
	r, ok := m.get(pool, network, "staged")
	return r, ok, nil
}

func (m *memKeyStore) Installed(
	_ context.Context,
	pool, network string,
) (SealedKey, bool, error) {
	r, ok := m.get(pool, network, "installed")
	return r, ok, nil
}

func (m *memKeyStore) Install(
	_ context.Context,
	pool, network string,
	kesVKey, opcert []byte,
) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	staged, ok := m.recs[memKey(pool, network, "staged")]
	installed, haveInstalled := m.recs[memKey(pool, network, "installed")]
	if !ok {
		return alreadyInstalled(installed, haveInstalled, kesVKey, opcert)
	}
	if !bytes.Equal(staged.KESVKey, kesVKey) {
		return 0, ErrOpCertKESVK
	}
	rec := cloneSealedKey(staged)
	rec.OpCert = bytes.Clone(opcert)
	rec.Generation = installed.Generation + 1
	m.recs[memKey(pool, network, "installed")] = rec
	delete(m.recs, memKey(pool, network, "staged"))
	return rec.Generation, nil
}

// replica is what one agent replica opens: a guard store and a key store.
// Mem replicas share one instance of each; PostgreSQL replicas each open
// their own connection pool onto one database.
type replica struct {
	guard SharedGuardStore
	keys  KeyStore
}

func memReplicas() (replica, replica) {
	r := replica{guard: watermark.NewMemWatermark(), keys: newMemKeyStore()}
	return r, r
}

// testPGReplica opens a PostgreSQL replica, or skips the test when
// BURSA_TEST_POSTGRES_DSN is unset.
func testPGReplica(t *testing.T) replica {
	t.Helper()
	dsn := os.Getenv(pgDSNEnv)
	if dsn == "" {
		t.Skipf("%s not set; skipping PostgreSQL runtime tests", pgDSNEnv)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	wm, err := watermark.NewPostgresWatermark(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresWatermark: %v", err)
	}
	t.Cleanup(wm.Close)
	ks, err := NewPostgresKeyStore(ctx, wm.Pool())
	if err != nil {
		t.Fatalf("NewPostgresKeyStore: %v", err)
	}
	return replica{guard: wm, keys: ks}
}

func pgReplicas(t *testing.T) (replica, replica) {
	t.Helper()
	return testPGReplica(t), testPGReplica(t)
}

// testSealer returns a sealer with a fresh age identity that seals to itself.
func testSealer(t *testing.T) *KeySealer {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}
	path := filepath.Join(t.TempDir(), "age-identity.txt")
	if err := os.WriteFile(path, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	s, err := NewKeySealer([]string{id.Recipient().String()}, path)
	if err != nil {
		t.Fatalf("NewKeySealer: %v", err)
	}
	return s
}

// sharedKeyAgent builds a sign-mode agent at KES period 5 over r, sharing
// keys sealed with sealer.
func sharedKeyAgent(
	t *testing.T,
	cold coldKeyPair,
	r replica,
	sealer *KeySealer,
) *Agent {
	t.Helper()
	cfg := Config{
		Mode:              ModeSign,
		Depth:             kes.CardanoKesDepth,
		SystemStart:       epoch,
		SlotLength:        time.Second,
		SlotsPerKESPeriod: 10,
		MaxKESEvolutions:  62,
		ColdVKey:          cold.pub,
		EvolveInterval:    time.Hour,
		Version:           "test",
		SharedGuard:       r.guard,
		KeyStore:          r.keys,
		KeySealer:         sealer,
	}
	a, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a.now = func() time.Time { return atPeriod(5) }
	t.Cleanup(a.Close)
	return a
}

// sharedSpec is the header spec for a key certified at period 3.
func sharedSpec(
	t *testing.T,
	cold coldKeyPair,
	vkey, opcert []byte,
	issue, slot uint64,
) headerSpec {
	t.Helper()
	return headerSpec{
		slot:      slot,
		issuer:    cold.pub,
		hotVkey:   vkey,
		sequence:  issue,
		kesPeriod: 3,
		coldSig:   opCertColdSig(t, opcert),
	}
}

// signAndVerify signs spec's header body at period 5 with a and checks the
// signature against the opcert's KES key.
func signAndVerify(t *testing.T, name string, a *Agent, spec headerSpec) {
	t.Helper()
	body := spec.encode(t)
	sig, err := a.SignHeader(5, body)
	if err != nil {
		t.Fatalf("%s SignHeader slot %d: %v", name, spec.slot, err)
	}
	if !kes.VerifySignedKES(spec.hotVkey, 5-3, body, sig) {
		t.Fatalf("%s signature for slot %d does not verify", name, spec.slot)
	}
}

func syncKeys(t *testing.T, name string, a *Agent) {
	t.Helper()
	if err := a.SyncKeys(context.Background()); err != nil {
		t.Fatalf("%s SyncKeys: %v", name, err)
	}
}

// checkAgentsShareKey: a key staged on one replica is installed on the other,
// and each signs with it after loading it.
func checkAgentsShareKey(t *testing.T, ra, rb replica) {
	t.Helper()
	cold := newColdKey(t)
	sealer := testSealer(t)
	a := sharedKeyAgent(t, cold, ra, sealer)
	b := sharedKeyAgent(t, cold, rb, sealer)
	syncKeys(t, "A", a)
	syncKeys(t, "B", b)
	if _, err := b.SignHeader(5, []byte{0}); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("B before any install: want ErrNoActiveKey, got %v", err)
	}

	vkey, err := a.GenStagedKey()
	if err != nil {
		t.Fatalf("A GenStagedKey: %v", err)
	}
	opcert := makeOpCert(t, vkey, 7, 3, cold)
	if _, err := b.InstallKey(opcert); err != nil {
		t.Fatalf("B InstallKey of the key A staged: %v", err)
	}
	signAndVerify(t, "B", b, sharedSpec(t, cold, vkey, opcert, 7, 52))

	syncKeys(t, "A", a)
	info := a.Info()
	if !info.HasActiveKey || !bytes.Equal(info.ActiveKESVKey, vkey) ||
		!bytes.Equal(info.ActiveOpCert, opcert) {
		t.Fatalf("A after sync: active key %x opcert %x, want %x", info.ActiveKESVKey, info.ActiveOpCert, vkey)
	}
	signAndVerify(t, "A", a, sharedSpec(t, cold, vkey, opcert, 7, 53))
	// The guard is shared too: B cannot sign another header for slot 53.
	other := sharedSpec(t, cold, vkey, opcert, 7, 53)
	other.blockNumber = 2
	if _, err := b.SignHeader(5, other.encode(t)); !errors.Is(err, ErrSlotEquivocation) {
		t.Fatalf("B second header for slot 53: want ErrSlotEquivocation, got %v", err)
	}

	// A newer install reaches the other replica on its next sync.
	vkey2, err := b.GenStagedKey()
	if err != nil {
		t.Fatalf("B GenStagedKey: %v", err)
	}
	opcert2 := makeOpCert(t, vkey2, 8, 3, cold)
	if _, err := a.InstallKey(opcert2); err != nil {
		t.Fatalf("A InstallKey of the key B staged: %v", err)
	}
	syncKeys(t, "B", b)
	signAndVerify(t, "B", b, sharedSpec(t, cold, vkey2, opcert2, 8, 54))
}

func TestAgentsShareKeyMem(t *testing.T) {
	t.Parallel()
	ra, rb := memReplicas()
	checkAgentsShareKey(t, ra, rb)
}

func TestPostgresKeyAgentsShareKey(t *testing.T) {
	t.Parallel()
	ra, rb := pgReplicas(t)
	checkAgentsShareKey(t, ra, rb)
}

// checkConcurrentInstall: two replicas install different opcerts for one
// staged key at the same moment. Exactly one install wins, the store holds
// it, and both replicas end up with it.
func checkConcurrentInstall(t *testing.T, ra, rb replica) {
	t.Helper()
	cold := newColdKey(t)
	sealer := testSealer(t)
	a := sharedKeyAgent(t, cold, ra, sealer)
	b := sharedKeyAgent(t, cold, rb, sealer)
	const rounds = 10
	for round := range uint64(rounds) {
		vkey, err := a.GenStagedKey()
		if err != nil {
			t.Fatalf("round %d GenStagedKey: %v", round, err)
		}
		opcerts := [2][]byte{
			makeOpCert(t, vkey, 2*round, 3, cold),
			makeOpCert(t, vkey, 2*round+1, 3, cold),
		}
		agents := [2]*Agent{a, b}
		var errs [2]error
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, errs[i] = agents[i].InstallKey(opcerts[i])
			}()
		}
		close(start)
		wg.Wait()
		winner := -1
		for i, err := range errs {
			switch {
			case err == nil:
				if winner != -1 {
					t.Fatalf("round %d: both installs succeeded", round)
				}
				winner = i
			case errors.Is(err, ErrKeyAlreadyInstalled),
				errors.Is(err, ErrNoStagedKey):
			default:
				t.Fatalf("round %d install %d: %v", round, i, err)
			}
		}
		if winner == -1 {
			t.Fatalf("round %d: no install succeeded: %v", round, errs)
		}
		rec, ok, err := ra.keys.Installed(
			context.Background(),
			sole(t, a).keyPool,
			sole(t, a).keyNetwork,
		)
		if err != nil || !ok {
			t.Fatalf("round %d Installed: %v %v", round, ok, err)
		}
		if !bytes.Equal(rec.OpCert, opcerts[winner]) {
			t.Fatalf("round %d: stored opcert is not the winner's", round)
		}
		for i, ag := range agents {
			syncKeys(t, fmt.Sprintf("replica %d", i), ag)
			if got := ag.Info().ActiveOpCert; !bytes.Equal(got, opcerts[winner]) {
				t.Fatalf("round %d replica %d holds a different opcert", round, i)
			}
		}
	}

	// The same opcert installed from both replicas at once is one install.
	vkey, err := b.GenStagedKey()
	if err != nil {
		t.Fatalf("GenStagedKey: %v", err)
	}
	opcert := makeOpCert(t, vkey, 2*rounds, 3, cold)
	var errs [2]error
	var wg sync.WaitGroup
	for i, ag := range []*Agent{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = ag.InstallKey(opcert)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("same opcert from replica %d: %v", i, err)
		}
	}
	if sole(t, a).seenGen != sole(t, b).seenGen {
		t.Fatalf("same opcert installed as generations %d and %d", sole(t, a).seenGen, sole(t, b).seenGen)
	}
}

func TestConcurrentInstallMem(t *testing.T) {
	t.Parallel()
	ra, rb := memReplicas()
	checkConcurrentInstall(t, ra, rb)
}

func TestPostgresKeyConcurrentInstall(t *testing.T) {
	t.Parallel()
	ra, rb := pgReplicas(t)
	checkConcurrentInstall(t, ra, rb)
}

// checkWrongIdentity: a replica whose age identity the key was not sealed to
// cannot load it and refuses signs, naming why.
func checkWrongIdentity(t *testing.T, ra, rb replica) {
	t.Helper()
	cold := newColdKey(t)
	a := sharedKeyAgent(t, cold, ra, testSealer(t))
	b := sharedKeyAgent(t, cold, rb, testSealer(t))
	vkey, err := a.GenStagedKey()
	if err != nil {
		t.Fatalf("GenStagedKey: %v", err)
	}
	opcert := makeOpCert(t, vkey, 7, 3, cold)
	if _, err := b.InstallKey(opcert); err == nil {
		t.Fatal("B installed a key it cannot unseal")
	}
	if _, err := a.InstallKey(opcert); err != nil {
		t.Fatalf("A InstallKey: %v", err)
	}
	var noMatch *age.NoIdentityMatchError
	err = b.SyncKeys(context.Background())
	if !errors.As(err, &noMatch) {
		t.Fatalf("B SyncKeys: want an age.NoIdentityMatchError, got %v", err)
	}
	spec := sharedSpec(t, cold, vkey, opcert, 7, 52)
	_, err = b.SignHeader(5, spec.encode(t))
	if !errors.Is(err, ErrNoActiveKey) || !errors.As(err, &noMatch) ||
		!strings.Contains(err.Error(), "could not be loaded") {
		t.Fatalf("B SignHeader: want ErrNoActiveKey naming the unseal failure, got %v", err)
	}
	signAndVerify(t, "A", a, spec)
}

func TestWrongIdentityRefusesMem(t *testing.T) {
	t.Parallel()
	ra, rb := memReplicas()
	checkWrongIdentity(t, ra, rb)
}

func TestPostgresKeyWrongIdentityRefuses(t *testing.T) {
	t.Parallel()
	ra, rb := pgReplicas(t)
	checkWrongIdentity(t, ra, rb)
}

// checkRestartReloads: an agent started again over the same store signs with
// the installed key once it has synced.
func checkRestartReloads(t *testing.T, r replica, reopen func() replica) {
	t.Helper()
	cold := newColdKey(t)
	sealer := testSealer(t)
	a := sharedKeyAgent(t, cold, r, sealer)
	vkey, err := a.GenStagedKey()
	if err != nil {
		t.Fatalf("GenStagedKey: %v", err)
	}
	opcert := makeOpCert(t, vkey, 7, 3, cold)
	if _, err := a.InstallKey(opcert); err != nil {
		t.Fatalf("InstallKey: %v", err)
	}
	signAndVerify(t, "first run", a, sharedSpec(t, cold, vkey, opcert, 7, 52))
	a.Close()

	again := sharedKeyAgent(t, cold, reopen(), sealer)
	spec := sharedSpec(t, cold, vkey, opcert, 7, 53)
	if _, err := again.SignHeader(5, spec.encode(t)); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("restarted agent before sync: want ErrNoActiveKey, got %v", err)
	}
	syncKeys(t, "restarted agent", again)
	signAndVerify(t, "restarted agent", again, spec)
}

func TestRestartReloadsKeyMem(t *testing.T) {
	t.Parallel()
	r, _ := memReplicas()
	checkRestartReloads(t, r, func() replica { return r })
}

func TestPostgresKeyRestartReloads(t *testing.T) {
	t.Parallel()
	r := testPGReplica(t)
	checkRestartReloads(t, r, func() replica { return testPGReplica(t) })
}

// TestDropKeyIsLocal: drop-key wipes this replica's copy and the poll does
// not bring it back; the next install does.
func TestDropKeyIsLocal(t *testing.T) {
	t.Parallel()
	ra, rb := memReplicas()
	cold := newColdKey(t)
	sealer := testSealer(t)
	a := sharedKeyAgent(t, cold, ra, sealer)
	b := sharedKeyAgent(t, cold, rb, sealer)
	vkey, err := a.GenStagedKey()
	if err != nil {
		t.Fatal(err)
	}
	opcert := makeOpCert(t, vkey, 7, 3, cold)
	if _, err := a.InstallKey(opcert); err != nil {
		t.Fatal(err)
	}
	syncKeys(t, "B", b)
	if err := a.DropKey("active"); err != nil {
		t.Fatal(err)
	}
	syncKeys(t, "A", a)
	if a.Info().HasActiveKey {
		t.Fatal("a sync reloaded the key A dropped")
	}
	signAndVerify(t, "B", b, sharedSpec(t, cold, vkey, opcert, 7, 52))
	vkey2, err := b.GenStagedKey()
	if err != nil {
		t.Fatal(err)
	}
	opcert2 := makeOpCert(t, vkey2, 8, 3, cold)
	if _, err := b.InstallKey(opcert2); err != nil {
		t.Fatal(err)
	}
	syncKeys(t, "A", a)
	signAndVerify(t, "A", a, sharedSpec(t, cold, vkey2, opcert2, 8, 53))
}

// TestLoadRefusesUncertifiedRecord: a record marked installed whose opcert
// the cold key did not sign is not loaded, whoever wrote it.
func TestLoadRefusesUncertifiedRecord(t *testing.T) {
	t.Parallel()
	ra, _ := memReplicas()
	cold := newColdKey(t)
	sealer := testSealer(t)
	a := sharedKeyAgent(t, cold, ra, sealer)
	vkey, err := a.GenStagedKey()
	if err != nil {
		t.Fatal(err)
	}
	p := sole(t, a)
	forged := makeOpCert(t, vkey, 7, 3, newColdKey(t))
	if _, err := ra.keys.Install(
		context.Background(), p.keyPool, p.keyNetwork, vkey, forged,
	); err != nil {
		t.Fatalf("store Install: %v", err)
	}
	if err := a.SyncKeys(context.Background()); !errors.Is(err, ErrOpCertColdVK) {
		t.Fatalf("SyncKeys of a forged record: want ErrOpCertColdVK, got %v", err)
	}
	if a.Info().HasActiveKey {
		t.Fatal("forged record was loaded")
	}
}

func TestSealerRefusesMismatchedRecord(t *testing.T) {
	t.Parallel()
	s := testSealer(t)
	sk, vkey, err := kes.KeyGen(kes.CardanoKesDepth, bytes.Repeat([]byte{7}, kes.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.seal(sk.Depth, 0, vkey, sk.Data)
	if err != nil {
		t.Fatal(err)
	}
	rec := SealedKey{KESVKey: vkey, Depth: sk.Depth, Sealed: sealed}
	buf, err := s.unseal(rec)
	if err != nil {
		t.Fatalf("unseal: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), sk.Data) {
		t.Fatal("unsealed key differs")
	}
	_ = buf.Close()

	_, other, err := kes.KeyGen(kes.CardanoKesDepth, bytes.Repeat([]byte{8}, kes.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	swapped := rec
	swapped.KESVKey = other
	if _, err := s.unseal(swapped); err == nil {
		t.Fatal("unsealed a key presented under another verification key")
	}
	moved := rec
	moved.SealedPeriod = 1
	if _, err := s.unseal(moved); err == nil {
		t.Fatal("unsealed a key presented at another period")
	}
	var noMatch *age.NoIdentityMatchError
	if _, err := testSealer(t).unseal(rec); !errors.As(err, &noMatch) {
		t.Fatalf("other identity: want age.NoIdentityMatchError, got %v", err)
	}
}

func TestNewKeySealerRequiresBoth(t *testing.T) {
	t.Parallel()
	if _, err := NewKeySealer(nil, "x"); err == nil {
		t.Fatal("no recipients accepted")
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewKeySealer([]string{id.Recipient().String()}, ""); err == nil {
		t.Fatal("no identity file accepted")
	}
	if _, err := NewKeySealer([]string{"not-a-recipient"}, "x"); err == nil {
		t.Fatal("bad recipient accepted")
	}
}

func TestStageRefusesKeyOwnIdentityCannotOpen(t *testing.T) {
	t.Parallel()
	ra, _ := memReplicas()
	own, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	elsewhere, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id.txt")
	if err := os.WriteFile(path, []byte(own.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewKeySealer([]string{elsewhere.Recipient().String()}, path)
	if err != nil {
		t.Fatal(err)
	}
	a := sharedKeyAgent(t, newColdKey(t), ra, s)
	if _, err := a.GenStagedKey(); err == nil ||
		!strings.Contains(err.Error(), "age_recipients") {
		t.Fatalf("GenStagedKey sealing past its own identity: got %v", err)
	}
}

func TestNewKeyStoreConfigRules(t *testing.T) {
	t.Parallel()
	base := Config{
		Mode:              ModeSign,
		SystemStart:       epoch,
		SlotLength:        time.Second,
		SlotsPerKESPeriod: 10,
		ColdVKey:          newColdKey(t).pub,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	noGuard := base
	noGuard.GuardPath = filepath.Join(t.TempDir(), "guard.json")
	noGuard.KeyStore = newMemKeyStore()
	noGuard.KeySealer = testSealer(t)
	if _, err := New(noGuard, logger, nil); err == nil ||
		!strings.Contains(err.Error(), "requires the shared guard") {
		t.Fatalf("key store without shared guard: got %v", err)
	}
	noSealer := base
	noSealer.SharedGuard = watermark.NewMemWatermark()
	noSealer.KeyStore = newMemKeyStore()
	if _, err := New(noSealer, logger, nil); err == nil ||
		!strings.Contains(err.Error(), "set together") {
		t.Fatalf("key store without sealer: got %v", err)
	}
}

// TestNoKeyStoreKeepsKeyLocal: with the shared guard but no key store, a
// key installed on one agent is not available to another, as before.
func TestNoKeyStoreKeepsKeyLocal(t *testing.T) {
	t.Parallel()
	store := watermark.NewMemWatermark()
	cold := newColdKey(t)
	a, _ := sharedHeaderAgent(t, cold, store, 7)
	if err := a.SyncKeys(context.Background()); err != nil {
		t.Fatalf("SyncKeys without a key store: %v", err)
	}
	cfg := Config{
		Mode:              ModeSign,
		Depth:             kes.CardanoKesDepth,
		SystemStart:       epoch,
		SlotLength:        time.Second,
		SlotsPerKESPeriod: 10,
		ColdVKey:          cold.pub,
		SharedGuard:       store,
	}
	b, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	if err := b.SyncKeys(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b.Info().HasActiveKey {
		t.Fatal("agent without a key store has a key it never installed")
	}
}

// TestPostgresKeyStoreConcurrentSchemaCreation opens the key store from
// several replicas at once on a schema without its table.
func TestPostgresKeyStoreConcurrentSchemaCreation(t *testing.T) {
	dsn := os.Getenv(pgDSNEnv)
	if dsn == "" {
		t.Skipf("%s not set; skipping PostgreSQL runtime tests", pgDSNEnv)
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open admin pool: %v", err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("bursa_ks_race_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	defer func() {
		if _, err := admin.Exec(
			context.Background(),
			"DROP SCHEMA "+quoted+" CASCADE",
		); err != nil {
			t.Errorf("drop schema: %v", err)
		}
	}()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	const replicas = 8
	start := make(chan struct{})
	errs := make([]error, replicas)
	var wg sync.WaitGroup
	for i := range replicas {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pool, err := pgxpool.NewWithConfig(ctx, cfg)
			if err != nil {
				errs[i] = err
				return
			}
			defer pool.Close()
			<-start
			_, errs[i] = NewPostgresKeyStore(ctx, pool)
		}()
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("replica %d: NewPostgresKeyStore: %v", i, err)
		}
	}
	var tables int
	if err := admin.QueryRow(ctx,
		`SELECT count(*) FROM information_schema.tables
		 WHERE table_schema = $1 AND table_name = 'kes_agent_key'`,
		schema,
	).Scan(&tables); err != nil {
		t.Fatalf("count tables: %v", err)
	}
	if tables != 1 {
		t.Fatalf("kes_agent_key tables in fresh schema = %d, want 1", tables)
	}
}

// TestWrongIdentityRefusesMultiProfile: in a multi-profile replica the sign
// refusal for a profile whose key failed to load still names why, rather
// than reporting that no profile matched.
func TestWrongIdentityRefusesMultiProfile(t *testing.T) {
	t.Parallel()
	r, _ := memReplicas()
	coldX, coldY := newColdKey(t), newColdKey(t)
	multi := func(sealer *KeySealer) *Agent {
		x := profileOn(t, networkA, "pool-x", coldX)
		y := profileOn(t, networkA, "pool-y", coldY)
		x.GuardPath, y.GuardPath = "", ""
		a, err := New(Config{
			Mode:           ModeSign,
			EvolveInterval: time.Hour,
			Version:        "test",
			Profiles:       []ProfileConfig{x, y},
			SharedGuard:    r.guard,
			KeyStore:       r.keys,
			KeySealer:      sealer,
		}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		a.now = func() time.Time { return testClock }
		t.Cleanup(a.Close)
		return a
	}
	a := multi(testSealer(t))
	b := multi(testSealer(t))
	px := install(t, a, "pool-x", coldX, 3, 52, 5)
	mustSign(t, a, px, px.header.encode(t))

	var noMatch *age.NoIdentityMatchError
	if err := b.SyncKeys(context.Background()); !errors.As(err, &noMatch) {
		t.Fatalf("B SyncKeys: want an age.NoIdentityMatchError, got %v", err)
	}
	px.header.slot = 53
	_, err := b.SignHeader(5, px.header.encode(t))
	if !errors.Is(err, ErrNoActiveKey) || !errors.As(err, &noMatch) {
		t.Fatalf("B SignHeader for pool-x: want ErrNoActiveKey naming the unseal failure, got %v", err)
	}
}

// TestNewKeySealerRefusesASharedIdentityFile checks that an age identity file
// group or other users can read is refused, as other secret key files are.
func TestNewKeySealerRefusesASharedIdentityFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file mode bits are not enforced on windows")
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "age-identity.txt")
	if err := os.WriteFile(path, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewKeySealer([]string{id.Recipient().String()}, path); err == nil {
		t.Fatal("NewKeySealer accepted an identity file readable by others")
	}
}

// TestInstallOfAnInstalledKeyClearsStaged checks that an install answered by
// the record another replica already installed drops this replica's staged
// key, as an install of the staged record does.
func TestInstallOfAnInstalledKeyClearsStaged(t *testing.T) {
	ra, rb := memReplicas()
	cold := newColdKey(t)
	sealer := testSealer(t)
	a := sharedKeyAgent(t, cold, ra, sealer)
	b := sharedKeyAgent(t, cold, rb, sealer)
	vkey, err := a.GenStagedKey()
	if err != nil {
		t.Fatalf("A GenStagedKey: %v", err)
	}
	opcert := makeOpCert(t, vkey, 7, 3, cold)
	if _, err := b.InstallKey(opcert); err != nil {
		t.Fatalf("B InstallKey: %v", err)
	}
	if _, err := a.InstallKey(opcert); err != nil {
		t.Fatalf("A InstallKey of the installed opcert: %v", err)
	}
	p := sole(t, a)
	p.mu.Lock()
	staged := p.staged
	p.mu.Unlock()
	if staged != nil {
		t.Fatal("A kept its staged key after the install")
	}
}
