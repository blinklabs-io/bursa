package spend

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/chain"
)

// strptr is a helper for the *string fields in test fixtures.
func strptr(s string) *string { return &s }

// validPoolID is a syntactically valid bech32 pool1… id (28 bytes 0x01..0x1c);
// BuildDelegation decodes the pool id, so the build tests must use a real one.
const validPoolID = "pool1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c6vr4kr"

// validDRepID is the matching bech32 drep1… id (legacy CIP-0105, 28 bytes).
const validDRepID = "drep1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3cpvc53e"

// defaultParams is the deposit set used across plan() tests: 2 ₳ key deposit,
// 500 ₳ DRep deposit (matching mainnet/preview Conway values).
var defaultParams = ProtocolParams{KeyDeposit: 2_000_000, DRepDeposit: 500_000_000}

// kinds extracts the cert kinds from a plan result for concise assertions.
func kinds(certs []Cert) []CertKind {
	out := make([]CertKind, len(certs))
	for i, c := range certs {
		out[i] = c.Kind
	}
	return out
}

func equalKinds(a, b []CertKind) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestPlanStateMatrix(t *testing.T) {
	const pool = "pool1abc"
	const otherPool = "pool1xyz"

	cases := []struct {
		name         string
		current      AccountState
		req          DelegationRequest
		withdrawable string
		want         []CertKind
		wantErr      error
	}{
		{
			name:    "fresh wallet, pool only → register + delegate",
			current: AccountState{Registered: false},
			req:     DelegationRequest{PoolID: pool},
			want:    []CertKind{CertStakeRegistration, CertStakeDelegation},
		},
		{
			name:    "fresh wallet, pool + abstain → register + delegate + vote",
			current: AccountState{Registered: false},
			req:     DelegationRequest{PoolID: pool, Vote: &Vote{Type: VoteAbstain}},
			want:    []CertKind{CertStakeRegistration, CertStakeDelegation, CertVoteDelegation},
		},
		{
			name:    "fresh wallet, register self → register + drep-reg + vote",
			current: AccountState{Registered: false},
			req:     DelegationRequest{PoolID: pool, Vote: &Vote{Type: VoteRegisterSelf}},
			want:    []CertKind{CertStakeRegistration, CertStakeDelegation, CertDRepRegistration, CertVoteDelegation},
		},
		{
			name:    "already registered, pool change → delegate only",
			current: AccountState{Registered: true, CurrentPool: strptr(otherPool)},
			req:     DelegationRequest{PoolID: pool},
			want:    []CertKind{CertStakeDelegation},
		},
		{
			name:    "already registered, same pool → no-op",
			current: AccountState{Registered: true, CurrentPool: strptr(pool)},
			req:     DelegationRequest{PoolID: pool},
			wantErr: ErrNoChange,
		},
		{
			name:    "registered, no delegation yet, set pool → delegate only",
			current: AccountState{Registered: true, CurrentPool: nil},
			req:     DelegationRequest{PoolID: pool},
			want:    []CertKind{CertStakeDelegation},
		},
		{
			name:    "registered, abstain vote only → vote only",
			current: AccountState{Registered: true, CurrentPool: strptr(pool)},
			req:     DelegationRequest{Vote: &Vote{Type: VoteAbstain}},
			want:    []CertKind{CertVoteDelegation},
		},
		{
			name:    "registered, no-confidence vote only → vote only",
			current: AccountState{Registered: true},
			req:     DelegationRequest{Vote: &Vote{Type: VoteNoConfidence}},
			want:    []CertKind{CertVoteDelegation},
		},
		{
			name:    "registered, specific drep vote → vote only",
			current: AccountState{Registered: true},
			req:     DelegationRequest{Vote: &Vote{Type: VoteDRep, DRepID: "drep1abc"}},
			want:    []CertKind{CertVoteDelegation},
		},
		{
			name:    "registered, register self → drep-reg + vote",
			current: AccountState{Registered: true, CurrentPool: strptr(pool)},
			req:     DelegationRequest{Vote: &Vote{Type: VoteRegisterSelf}},
			want:    []CertKind{CertDRepRegistration, CertVoteDelegation},
		},
		{
			name:         "registered, withdraw only → withdrawal",
			current:      AccountState{Registered: true, CurrentPool: strptr(pool)},
			req:          DelegationRequest{Withdraw: true},
			withdrawable: "5000000",
			want:         []CertKind{CertWithdrawal},
		},
		{
			name:         "pool change + withdraw → delegate + withdrawal",
			current:      AccountState{Registered: true, CurrentPool: strptr(otherPool)},
			req:          DelegationRequest{PoolID: pool, Withdraw: true},
			withdrawable: "5000000",
			want:         []CertKind{CertStakeDelegation, CertWithdrawal},
		},
		{
			name:         "withdraw with zero rewards → error",
			current:      AccountState{Registered: true, CurrentPool: strptr(pool)},
			req:          DelegationRequest{Withdraw: true},
			withdrawable: "0",
			wantErr:      ErrInvalidRequest,
		},
		{
			name:    "empty request → no-op",
			current: AccountState{Registered: true},
			req:     DelegationRequest{},
			wantErr: ErrNoChange,
		},
		{
			name:    "specific drep without id → error",
			current: AccountState{Registered: true},
			req:     DelegationRequest{Vote: &Vote{Type: VoteDRep}},
			wantErr: ErrInvalidRequest,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			certs, err := plan(tc.current, tc.req, defaultParams, tc.withdrawable)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("plan err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("plan: %v", err)
			}
			if !equalKinds(kinds(certs), tc.want) {
				t.Fatalf("plan kinds = %v, want %v", kinds(certs), tc.want)
			}
		})
	}
}

func TestPlanDepositMath(t *testing.T) {
	// A fresh wallet registering self carries both the key deposit (on the stake
	// registration cert) and the DRep deposit (on the DRep registration cert),
	// each distinctly itemized.
	certs, err := plan(
		AccountState{Registered: false},
		DelegationRequest{PoolID: "pool1abc", Vote: &Vote{Type: VoteRegisterSelf}},
		defaultParams, "0",
	)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	var keyDep, drepDep string
	for _, c := range certs {
		switch c.Kind {
		case CertStakeRegistration:
			keyDep = c.DepositLovelace
		case CertDRepRegistration:
			drepDep = c.DepositLovelace
		}
	}
	if keyDep != "2000000" {
		t.Fatalf("stake registration deposit = %q, want 2000000", keyDep)
	}
	if drepDep != "500000000" {
		t.Fatalf("drep registration deposit = %q, want 500000000", drepDep)
	}
}

func TestPlanWithdrawalAmount(t *testing.T) {
	certs, err := plan(
		AccountState{Registered: true, CurrentPool: strptr("pool1abc")},
		DelegationRequest{Withdraw: true},
		defaultParams, "7500000",
	)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(certs) != 1 || certs[0].Kind != CertWithdrawal {
		t.Fatalf("unexpected certs: %+v", certs)
	}
	if certs[0].AmountLovelace != "7500000" {
		t.Fatalf("withdrawal amount = %q, want 7500000", certs[0].AmountLovelace)
	}
}

// fakeQuerier implements chainQuerier for BuildDelegation tests.
type fakeQuerier struct {
	account    chain.AccountInfo
	accountErr error
	pool       chain.PoolInfo
	poolErr    error
	drep       chain.DRepInfo
	drepErr    error
	params     chain.ProtocolParams
	paramsErr  error
	poolCalled bool
	drepCalled bool
	wantPoolID string
	wantDRepID string
}

func (f *fakeQuerier) Account(_ context.Context, _ string) (chain.AccountInfo, error) {
	return f.account, f.accountErr
}

func (f *fakeQuerier) Pool(_ context.Context, id string) (chain.PoolInfo, error) {
	f.poolCalled = true
	f.wantPoolID = id
	return f.pool, f.poolErr
}

func (f *fakeQuerier) DRep(_ context.Context, id string) (chain.DRepInfo, error) {
	f.drepCalled = true
	f.wantDRepID = id
	return f.drep, f.drepErr
}

func (f *fakeQuerier) ProtocolParams(_ context.Context) (chain.ProtocolParams, error) {
	return f.params, f.paramsErr
}

func newFakeQuerier() *fakeQuerier {
	dd := "500000000"
	return &fakeQuerier{
		account: chain.AccountInfo{Active: false, WithdrawableAmount: "0"},
		pool:    chain.PoolInfo{PoolID: "pool1abc"},
		drep:    chain.DRepInfo{DRepID: "drep1abc", Registered: true},
		params:  chain.ProtocolParams{KeyDeposit: "2000000", PoolDeposit: "500000000", DRepDeposit: &dd},
	}
}

func TestBuildDelegationNoWallet(t *testing.T) {
	fc := newFakeChain(5_000_000, mustDeriveTestAccount(t).ReceiveAddresses[0])
	s := NewService(fc, nil, nil)
	s.SetChainQuerier(newFakeQuerier())
	_, err := s.BuildDelegation(context.Background(), DelegationRequest{PoolID: "pool1abc"})
	if !errors.Is(err, ErrNoWallet) {
		t.Fatalf("BuildDelegation without wallet = %v, want ErrNoWallet", err)
	}
}

func TestBuildDelegationPoolNotFound(t *testing.T) {
	acct := mustDeriveTestAccount(t)
	fc := newFakeChain(5_000_000, acct.ReceiveAddresses[0])
	s := NewService(fc, nil, acct)
	q := newFakeQuerier()
	q.poolErr = chain.ErrNotFound
	s.SetChainQuerier(q)

	_, err := s.BuildDelegation(context.Background(), DelegationRequest{PoolID: "pool1missing"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("BuildDelegation unknown pool = %v, want ErrInvalidRequest", err)
	}
	if !strings.Contains(err.Error(), "not found by your node") {
		t.Fatalf("error should mention node not-found: %v", err)
	}
}

func TestBuildDelegationDRepNotFound(t *testing.T) {
	acct := mustDeriveTestAccount(t)
	fc := newFakeChain(5_000_000, acct.ReceiveAddresses[0])
	s := NewService(fc, nil, acct)
	q := newFakeQuerier()
	q.account = chain.AccountInfo{Active: true, WithdrawableAmount: "0"}
	q.drepErr = chain.ErrNotFound
	s.SetChainQuerier(q)

	_, err := s.BuildDelegation(context.Background(), DelegationRequest{Vote: &Vote{Type: VoteDRep, DRepID: "drep1missing"}})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("BuildDelegation unknown drep = %v, want ErrInvalidRequest", err)
	}
}

func TestBuildDelegationNoChange(t *testing.T) {
	acct := mustDeriveTestAccount(t)
	fc := newFakeChain(5_000_000, acct.ReceiveAddresses[0])
	s := NewService(fc, nil, acct)
	q := newFakeQuerier()
	// Already delegated to the requested pool → no certs.
	q.account = chain.AccountInfo{Active: true, PoolID: strptr("pool1abc"), WithdrawableAmount: "0"}
	s.SetChainQuerier(q)

	_, err := s.BuildDelegation(context.Background(), DelegationRequest{PoolID: "pool1abc"})
	if !errors.Is(err, ErrNoChange) {
		t.Fatalf("BuildDelegation no change = %v, want ErrNoChange", err)
	}
}

// TestBuildDelegationFreshWalletPreview drives the full build of a fresh wallet
// registering + delegating to a pool, asserting the itemized preview surfaces
// the stake deposit and a non-zero fee, and that the pool was verified.
func TestBuildDelegationFreshWalletPreview(t *testing.T) {
	acct := mustDeriveTestAccount(t)
	fc := newFakeChain(10_000_000, acct.ReceiveAddresses[0])
	s := NewService(fc, nil, acct)
	q := newFakeQuerier()
	s.SetChainQuerier(q)

	pv, err := s.BuildDelegation(context.Background(), DelegationRequest{PoolID: validPoolID})
	if err != nil {
		t.Fatalf("BuildDelegation: %v", err)
	}
	if !q.poolCalled || q.wantPoolID != validPoolID {
		t.Fatalf("pool not verified: called=%v id=%q", q.poolCalled, q.wantPoolID)
	}
	if pv.PendingID == "" {
		t.Fatal("expected non-empty pending id")
	}
	if len(pv.Certs) != 2 || pv.Certs[0].Kind != CertStakeRegistration || pv.Certs[1].Kind != CertStakeDelegation {
		t.Fatalf("unexpected certs: %+v", pv.Certs)
	}
	if pv.Deposit != "2000000" {
		t.Fatalf("deposit = %q, want 2000000", pv.Deposit)
	}
	if pv.Fee == "" || pv.Fee == "0" {
		t.Fatalf("expected non-zero fee, got %q", pv.Fee)
	}
}

// TestBuildDelegationConfirmSignsAndSubmits proves a delegation tx flows through
// the SAME Confirm (sign+submit) path the Send flow uses, unchanged.
func TestBuildDelegationConfirmSignsAndSubmits(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	fc := newFakeChain(10_000_000, acct.ReceiveAddresses[0])
	ks := fakeKeystore{mnemonic: testMnemonic}
	s := NewService(fc, ks, acct)
	q := newFakeQuerier()
	s.SetChainQuerier(q)

	ctx := context.Background()
	pv, err := s.BuildDelegation(ctx, DelegationRequest{PoolID: validPoolID, Vote: &Vote{Type: VoteAbstain}})
	if err != nil {
		t.Fatalf("BuildDelegation: %v", err)
	}
	if len(pv.Certs) != 3 {
		t.Fatalf("expected 3 certs (register, delegate, vote), got %+v", pv.Certs)
	}

	res, err := s.Confirm(ctx, pv.PendingID, "pw")
	if err != nil {
		t.Fatalf("Confirm delegation: %v", err)
	}
	if res.TxHash == "" {
		t.Fatal("expected non-empty tx hash")
	}
	if fc.submitCalls != 1 {
		t.Fatalf("SubmitTx calls = %d, want 1", fc.submitCalls)
	}
}

// TestBuildDelegationRegisterSelfPreview drives a self-DRep registration,
// asserting the DRep deposit is itemized distinctly from the stake deposit.
func TestBuildDelegationRegisterSelfPreview(t *testing.T) {
	acct := mustDeriveConfirmAccount(t)
	if len(acct.DRepKeyHash) == 0 {
		t.Fatal("derived account is missing its DRep key hash")
	}
	fc := newFakeChain(600_000_000, acct.ReceiveAddresses[0])
	s := NewService(fc, nil, acct)
	q := newFakeQuerier()
	q.account = chain.AccountInfo{Active: true, PoolID: strptr("pool1abc"), WithdrawableAmount: "0"}
	s.SetChainQuerier(q)

	pv, err := s.BuildDelegation(context.Background(), DelegationRequest{
		Vote: &Vote{Type: VoteRegisterSelf, Anchor: &Anchor{
			URL:  "https://example.com/drep.jsonld",
			Hash: strings.Repeat("ab", 32),
		}},
	})
	if err != nil {
		t.Fatalf("BuildDelegation register self: %v", err)
	}
	var keyDep, drepDep string
	for _, c := range pv.Certs {
		switch c.Kind {
		case CertStakeRegistration:
			keyDep = c.DepositLovelace
		case CertDRepRegistration:
			drepDep = c.DepositLovelace
		}
	}
	if keyDep != "" {
		t.Fatalf("already-registered wallet should not re-register stake (deposit %q)", keyDep)
	}
	if drepDep != "500000000" {
		t.Fatalf("drep deposit = %q, want 500000000", drepDep)
	}
	if pv.Deposit != "500000000" {
		t.Fatalf("total deposit = %q, want 500000000", pv.Deposit)
	}
}

func TestDecodeDRepID(t *testing.T) {
	// A valid legacy CIP-0105 (28-byte) drep1 id decodes to a key-hash credential.
	typ, hash, err := decodeDRepID(validDRepID)
	if err != nil {
		t.Fatalf("decodeDRepID(%q): %v", validDRepID, err)
	}
	if typ != 0 { // DrepTypeAddrKeyHash
		t.Fatalf("type = %d, want 0 (key hash)", typ)
	}
	if len(hash) != 28 {
		t.Fatalf("hash len = %d, want 28", len(hash))
	}
	if _, _, err := decodeDRepID("notbech32"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid bech32 should error, got %v", err)
	}
	if _, _, err := decodeDRepID(validPoolID); err == nil {
		t.Fatal("a non-drep prefix should error")
	}
}
