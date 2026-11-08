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
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/gouroboros/kes"
)

// The two test networks. Network A is the testAgent schedule (10 slots per
// KES period from epoch), at KES period 5 under testClock. Network B starts
// 20s later with 20 slots per period, so testClock is its KES period 1.
var (
	testClock = atPeriod(5)
	networkA  = ProfileConfig{
		SystemStart:       epoch,
		SlotLength:        time.Second,
		SlotsPerKESPeriod: 10,
	}
	networkB = ProfileConfig{
		SystemStart:       epoch.Add(20 * time.Second),
		SlotLength:        time.Second,
		SlotsPerKESPeriod: 20,
	}
)

// installedProfile is a test profile with an installed key and the header
// spec and KES period that match it.
type installedProfile struct {
	name   string
	vkey   []byte
	header headerSpec
	period uint64
}

func profileOn(
	t *testing.T,
	network ProfileConfig,
	name string,
	cold coldKeyPair,
) ProfileConfig {
	t.Helper()
	pc := network
	pc.Name = name
	pc.ColdVKey = cold.pub
	pc.GuardPath = filepath.Join(t.TempDir(), name+".guard.json")
	return pc
}

func newMultiAgent(t *testing.T, profiles ...ProfileConfig) *Agent {
	t.Helper()
	a, err := New(Config{
		Mode:           ModeSign,
		EvolveInterval: time.Hour,
		Version:        "test",
		Profiles:       profiles,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a.now = func() time.Time { return testClock }
	t.Cleanup(a.Close)
	return a
}

// install stages and installs a key in the named profile through the control
// commands, with an opcert issued at opcertPeriod, and returns a header for
// slot in that profile.
func install(
	t *testing.T,
	a *Agent,
	name string,
	cold coldKeyPair,
	opcertPeriod, slot, period uint64,
) installedProfile {
	t.Helper()
	reply := a.dispatch(Command{Command: CmdGenStagedKey, Profile: name})
	if !reply.Ok {
		t.Fatalf("gen-staged-key %s: %s", name, reply.Error)
	}
	vkey := reply.KESVKey
	opcert := makeOpCert(t, vkey, 1, opcertPeriod, cold)
	reply = a.dispatch(Command{
		Command: CmdInstallKey,
		Profile: name,
		OpCert:  opcert,
	})
	if !reply.Ok {
		t.Fatalf("install-key %s: %s", name, reply.Error)
	}
	if reply.Info == nil || reply.Info.Profile != name {
		t.Fatalf("install-key %s replied with info %+v", name, reply.Info)
	}
	return installedProfile{
		name: name,
		vkey: vkey,
		header: headerSpec{
			slot:      slot,
			issuer:    cold.pub,
			hotVkey:   vkey,
			sequence:  1,
			kesPeriod: opcertPeriod,
			coldSig:   opCertColdSig(t, opcert),
		},
		period: period,
	}
}

func mustSign(t *testing.T, a *Agent, p installedProfile, body []byte) {
	t.Helper()
	sig, err := a.SignHeader(p.period, body)
	if err != nil {
		t.Fatalf("SignHeader for %s: %v", p.name, err)
	}
	if !kes.VerifySignedKES(p.header.hotVkey, p.period-p.header.kesPeriod, body, sig) {
		t.Fatalf("signature for %s does not verify under its KES key", p.name)
	}
}

func TestAgentSignsForEachProfileOnTwoNetworks(t *testing.T) {
	coldA, coldB := newColdKey(t), newColdKey(t)
	a := newMultiAgent(t,
		profileOn(t, networkA, "pool-a", coldA),
		profileOn(t, networkB, "pool-b", coldB),
	)
	pa := install(t, a, "pool-a", coldA, 3, 52, 5)
	pb := install(t, a, "pool-b", coldB, 0, 25, 1)

	mustSign(t, a, pa, pa.header.encode(t))
	mustSign(t, a, pb, pb.header.encode(t))

	stranger := newColdKey(t)
	unknown := pa.header
	unknown.issuer = stranger.pub
	if _, err := a.SignHeader(5, unknown.encode(t)); !errors.Is(err, ErrUnknownProfile) {
		t.Fatalf("header from an unknown pool: err = %v, want ErrUnknownProfile", err)
	}
	crossed := pa.header
	crossed.hotVkey = pb.header.hotVkey
	if _, err := a.SignHeader(5, crossed.encode(t)); !errors.Is(err, ErrUnknownProfile) {
		t.Fatalf("pool A issuer with pool B's KES key: err = %v, want ErrUnknownProfile", err)
	}
}

func TestAgentTellsOneColdKeyOnTwoNetworksApartByKESKey(t *testing.T) {
	cold := newColdKey(t)
	a := newMultiAgent(t,
		profileOn(t, networkA, "mainnet-pool", cold),
		profileOn(t, networkB, "testnet-pool", cold),
	)
	pa := install(t, a, "mainnet-pool", cold, 3, 52, 5)
	pb := install(t, a, "testnet-pool", cold, 0, 25, 1)

	// Slot 25 is below pool A's last signed slot 52; it is signed because the
	// header routes to the other profile, whose slot record is its own.
	mustSign(t, a, pa, pa.header.encode(t))
	mustSign(t, a, pb, pb.header.encode(t))
	slotA, _ := a.byName["mainnet-pool"].guard.LastSignedSlot()
	slotB, _ := a.byName["testnet-pool"].guard.LastSignedSlot()
	if slotA != 52 || slotB != 25 {
		t.Fatalf("last signed slots = %d, %d; want 52, 25", slotA, slotB)
	}
}

func TestAgentRefusalInOneProfileLeavesTheOtherSigning(t *testing.T) {
	coldA, coldB := newColdKey(t), newColdKey(t)
	a := newMultiAgent(t,
		profileOn(t, networkA, "pool-a", coldA),
		profileOn(t, networkB, "pool-b", coldB),
	)
	pa := install(t, a, "pool-a", coldA, 3, 52, 5)
	pb := install(t, a, "pool-b", coldB, 0, 25, 1)

	mustSign(t, a, pa, pa.header.encode(t))
	other := pa.header
	other.blockNumber = 2
	if _, err := a.SignHeader(5, other.encode(t)); !errors.Is(err, ErrSlotEquivocation) {
		t.Fatalf("second header for pool A's slot: err = %v, want ErrSlotEquivocation", err)
	}
	older := pa.header
	older.slot = 51
	if _, err := a.SignHeader(5, older.encode(t)); !errors.Is(err, ErrSlotRollback) {
		t.Fatalf("older slot for pool A: err = %v, want ErrSlotRollback", err)
	}
	mustSign(t, a, pb, pb.header.encode(t))
	next := pb.header
	next.slot = 26
	mustSign(t, a, pb, next.encode(t))
}

func TestSignHeaderForRefusesAHeaderOfAnotherProfile(t *testing.T) {
	coldA, coldB := newColdKey(t), newColdKey(t)
	a := newMultiAgent(t,
		profileOn(t, networkA, "pool-a", coldA),
		profileOn(t, networkB, "pool-b", coldB),
	)
	pa := install(t, a, "pool-a", coldA, 3, 52, 5)
	pb := install(t, a, "pool-b", coldB, 0, 25, 1)

	_, err := a.signHeaderFor(a.byName["pool-a"], pb.period, pb.header.encode(t))
	if !errors.Is(err, ErrProfileMismatch) {
		t.Fatalf("pool B header on a pool A session: err = %v, want ErrProfileMismatch", err)
	}
	if _, set := a.byName["pool-b"].guard.LastSignedSlot(); set {
		t.Fatal("a refused header reached pool B's slot record")
	}
	if _, err := a.signHeaderFor(a.byName["pool-a"], pa.period, pa.header.encode(t)); err != nil {
		t.Fatalf("pool A header on a pool A session: %v", err)
	}
}

func TestSelectProfile(t *testing.T) {
	coldA, coldB := newColdKey(t), newColdKey(t)
	a := newMultiAgent(t,
		profileOn(t, networkA, "pool-a", coldA),
		profileOn(t, networkB, "pool-b", coldB),
	)
	pa := install(t, a, "pool-a", coldA, 3, 52, 5)

	for _, tc := range []struct {
		name    string
		profile string
		kesVKey []byte
		want    string
		wantErr error
	}{
		{name: "by KES key", kesVKey: pa.vkey, want: "pool-a"},
		{name: "by KES key and name", profile: "pool-a", kesVKey: pa.vkey, want: "pool-a"},
		{name: "by name", profile: "pool-b", want: "pool-b"},
		{name: "neither", wantErr: ErrAmbiguousProfile},
		{name: "unknown name", profile: "pool-c", wantErr: ErrUnknownProfile},
		{name: "key not installed", kesVKey: make([]byte, 32), wantErr: ErrUnknownProfile},
		{name: "key and other name", profile: "pool-b", kesVKey: pa.vkey, wantErr: ErrProfileMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := a.selectProfile(tc.profile, tc.kesVKey)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil || p.cfg.Name != tc.want {
				t.Fatalf("selected %v, %v; want %s", p, err, tc.want)
			}
		})
	}
}

func TestControlCommandsTakeAProfile(t *testing.T) {
	coldA, coldB := newColdKey(t), newColdKey(t)
	a := newMultiAgent(t,
		profileOn(t, networkA, "pool-a", coldA),
		profileOn(t, networkB, "pool-b", coldB),
	)
	install(t, a, "pool-a", coldA, 3, 52, 5)

	reply := a.dispatch(Command{Command: CmdGenStagedKey})
	if reply.Ok || !strings.Contains(reply.Error, ErrAmbiguousProfile.Error()) {
		t.Fatalf("gen-staged-key without a profile: %+v", reply)
	}
	reply = a.dispatch(Command{Command: CmdDropKey, Profile: "pool-c"})
	if reply.Ok || !strings.Contains(reply.Error, ErrUnknownProfile.Error()) {
		t.Fatalf("drop-key for an unknown profile: %+v", reply)
	}
	reply = a.dispatch(Command{Command: CmdInfo})
	if !reply.Ok || reply.Info != nil || len(reply.Profiles) != 2 {
		t.Fatalf("info without a profile: %+v", reply)
	}
	if reply.Profiles[0].Profile != "pool-a" || !reply.Profiles[0].HasActiveKey ||
		reply.Profiles[1].Profile != "pool-b" || reply.Profiles[1].HasActiveKey {
		t.Fatalf("info lists %+v", reply.Profiles)
	}
	reply = a.dispatch(Command{Command: CmdInfo, Profile: "pool-b"})
	if !reply.Ok || reply.Info == nil || reply.Info.Profile != "pool-b" {
		t.Fatalf("info for pool-b: %+v", reply)
	}
	reply = a.dispatch(Command{Command: CmdDropKey, Profile: "pool-a"})
	if !reply.Ok || reply.Info.HasActiveKey {
		t.Fatalf("drop-key pool-a: %+v", reply)
	}
}

func TestNewRefusesInvalidProfiles(t *testing.T) {
	cold := newColdKey(t)
	shared := filepath.Join(t.TempDir(), "guard.json")
	a1 := profileOn(t, networkA, "pool-a", cold)
	a2 := profileOn(t, networkB, "pool-b", cold)
	sameGuard := a2
	sameGuard.GuardPath = shared
	sameGuardToo := a1
	sameGuardToo.GuardPath = filepath.Join(filepath.Dir(shared), ".", "guard.json")
	dup := a2
	dup.Name = "pool-a"
	badName := a2
	badName.Name = "pool b"

	for _, tc := range []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "duplicate name",
			cfg:  Config{Mode: ModeSign, Profiles: []ProfileConfig{a1, dup}},
			want: "duplicate profile name",
		},
		{
			name: "shared guard file",
			cfg: Config{
				Mode:     ModeSign,
				Profiles: []ProfileConfig{sameGuardToo, sameGuard},
			},
			want: "share guard file",
		},
		{
			name: "invalid name",
			cfg:  Config{Mode: ModeSign, Profiles: []ProfileConfig{badName}},
			want: "profile name",
		},
		{
			name: "serve-key with two profiles",
			cfg:  Config{Mode: ModeServeKey, Profiles: []ProfileConfig{a1, a2}},
			want: "exactly one profile",
		},
		{
			name: "profiles and single-pool fields",
			cfg: Config{
				Mode:      ModeSign,
				Profiles:  []ProfileConfig{a1},
				GuardPath: shared,
			},
			want: "not both",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg, nil, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// A guard file written by a single-pool agent before profiles existed is the
// default profile's state.
func TestSinglePoolGuardFileIsAdopted(t *testing.T) {
	cold := newColdKey(t)
	guard := filepath.Join(t.TempDir(), "guard.json")
	if err := os.WriteFile(guard, []byte(`{"floor":6,"set":true,"kes_vkey":"00"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{
		Mode:              ModeSign,
		SystemStart:       epoch,
		SlotLength:        time.Second,
		SlotsPerKESPeriod: 10,
		ColdVKey:          cold.pub,
		GuardPath:         guard,
	}, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	if len(a.profiles) != 1 || a.profiles[0].cfg.Name != DefaultProfileName {
		t.Fatalf("profiles = %+v, want one %q", a.profiles, DefaultProfileName)
	}
	if floor, set := a.profiles[0].guard.Floor(); !set || floor != 6 {
		t.Fatalf("floor = %d, %v; want 6 from the existing guard file", floor, set)
	}
	if info := a.Info(); info.Profile != DefaultProfileName {
		t.Fatalf("info profile = %q", info.Profile)
	}
}

func TestServiceSignRequestProfileMustMatchTheHeader(t *testing.T) {
	coldA, coldB := newColdKey(t), newColdKey(t)
	a := newMultiAgent(t,
		profileOn(t, networkA, "pool-a", coldA),
		profileOn(t, networkB, "pool-b", coldB),
	)
	pa := install(t, a, "pool-a", coldA, 3, 52, 5)
	pb := install(t, a, "pool-b", coldB, 0, 25, 1)

	sock := shortSocketPath(t, "multi.sock")
	ln, err := ListenUnix(sock, 0o600)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = a.ServeService(ctx, ln) }()
	conn := dial(t, sock)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var hello Hello
	if err := readFrame(conn, &hello); err != nil {
		t.Fatalf("read hello: %v", err)
	}

	roundTrip := func(req SignRequest) SignResponse {
		t.Helper()
		req.Type = "sign_request"
		if err := writeFrame(conn, req); err != nil {
			t.Fatalf("write sign request: %v", err)
		}
		var resp SignResponse
		if err := readFrame(conn, &resp); err != nil {
			t.Fatalf("read sign response: %v", err)
		}
		return resp
	}

	resp := roundTrip(SignRequest{
		Period:  pb.period,
		Message: pb.header.encode(t),
		Profile: "pool-a",
	})
	if !strings.Contains(resp.Error, ErrProfileMismatch.Error()) {
		t.Fatalf("pool B header named for pool-a: %+v", resp)
	}
	resp = roundTrip(SignRequest{
		Period:  pa.period,
		Message: pa.header.encode(t),
		Profile: "pool-a",
	})
	if resp.Error != "" || len(resp.Signature) == 0 {
		t.Fatalf("pool A header named for pool-a: %+v", resp)
	}
	resp = roundTrip(SignRequest{Period: pb.period, Message: pb.header.encode(t)})
	if resp.Error != "" || len(resp.Signature) == 0 {
		t.Fatalf("pool B header without a profile: %+v", resp)
	}
}

func TestServeAttestedServiceRefusesSeveralProfiles(t *testing.T) {
	coldA, coldB := newColdKey(t), newColdKey(t)
	a := newMultiAgent(t,
		profileOn(t, networkA, "pool-a", coldA),
		profileOn(t, networkB, "pool-b", coldB),
	)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	err = a.ServeAttestedService(context.Background(), ln, AttestedServiceConfig{})
	if !errors.Is(err, ErrAmbiguousProfile) {
		t.Fatalf("ServeAttestedService with two profiles: err = %v, want ErrAmbiguousProfile", err)
	}
}
