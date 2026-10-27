package spend

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/ledger/conway"

	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

func testHash28(b byte) lcommon.Blake2b224 {
	var h lcommon.Blake2b224
	copy(h[:], bytesRepeat(b, 28))
	return h
}

func testHex28(b byte) string {
	return strings.Repeat(hex.EncodeToString([]byte{b}), 28)
}

func testKeyCred(b byte) lcommon.Credential {
	return lcommon.Credential{CredType: lcommon.CredentialTypeAddrKeyHash, Credential: testHash28(b)}
}

func testScriptCred(b byte) lcommon.Credential {
	return lcommon.Credential{CredType: lcommon.CredentialTypeScriptHash, Credential: testHash28(b)}
}

// decodeWithCertificate re-encodes the send fixture with certs as its only
// certificate and returns the JSON DecodeTx reports for it, so each case
// crosses the wire decode and the JSON field names the web preview reads.
func decodeWithCertificate(t *testing.T, cert lcommon.CertificateWrapper) string {
	t.Helper()
	svc, _, unsignedCbor := buildUnsignedSendFixture(t)
	txBytes, err := hex.DecodeString(unsignedCbor)
	if err != nil {
		t.Fatalf("decode unsigned cbor: %v", err)
	}
	var outer []cbor.RawMessage
	if _, err := cbor.Decode(txBytes, &outer); err != nil {
		t.Fatalf("decode tx as CBOR array: %v", err)
	}
	body, err := conway.NewConwayTransactionBodyFromCbor(outer[0])
	if err != nil {
		t.Fatalf("decode tx body: %v", err)
	}
	body.TxCertificates = []lcommon.CertificateWrapper{cert}
	body.SetCbor(nil)
	newBody, err := cbor.Encode(body)
	if err != nil {
		t.Fatalf("encode tx body: %v", err)
	}
	outer[0] = cbor.RawMessage(newBody)
	newTx, err := cbor.Encode(outer)
	if err != nil {
		t.Fatalf("encode tx: %v", err)
	}
	got, err := svc.DecodeTx(context.Background(), hex.EncodeToString(newTx))
	if err != nil {
		t.Fatalf("DecodeTx: %v", err)
	}
	if len(got.Certificates) != 1 {
		t.Fatalf("got %d certificates, want 1: %+v", len(got.Certificates), got.Certificates)
	}
	out, err := json.Marshal(got.Certificates[0])
	if err != nil {
		t.Fatalf("marshal certificate summary: %v", err)
	}
	return string(out)
}

func TestDecodeTx_CertificateDetails(t *testing.T) {
	poolReg := &lcommon.PoolRegistrationCertificate{
		CertType:   uint(lcommon.CertificateTypePoolRegistration),
		Operator:   testHash28(0x33),
		Pledge:     1,
		Cost:       340_000_000,
		Margin:     cbor.Rat{Rat: big.NewRat(1, 100)},
		PoolOwners: []lcommon.AddrKeyHash{testHash28(0x55), testHash28(0x66)},
		Relays:     []lcommon.PoolRelay{},
	}
	if err := poolReg.SetRewardAccountCredential(testScriptCred(0x44), lcommon.AddressNetworkTestnet); err != nil {
		t.Fatalf("SetRewardAccountCredential: %v", err)
	}

	stake := `"stake_credential":{"type":"key_hash","hash":"` + testHex28(0x11) + `"}`
	pool := `"pool_id":"` + testHex28(0x33) + `"`
	drepKey := `"drep":{"type":"key_hash","hash":"` + testHex28(0x77) + `"}`
	drepCred := `"drep_credential":{"type":"script_hash","hash":"` + testHex28(0x88) + `"}`
	cold := `"committee_cold_credential":{"type":"key_hash","hash":"` + testHex28(0x99) + `"}`

	cases := []struct {
		name string
		cert lcommon.Certificate
		typ  lcommon.CertificateType
		want string
	}{
		{
			name: "legacy stake registration marks the protocol deposit",
			typ:  lcommon.CertificateTypeStakeRegistration,
			cert: &lcommon.StakeRegistrationCertificate{
				CertType: uint(lcommon.CertificateTypeStakeRegistration), StakeCredential: testKeyCred(0x11),
			},
			want: `{"kind":"stake_registration",` + stake + `,"deposit_implicit":true}`,
		},
		{
			name: "legacy stake deregistration marks the protocol refund",
			typ:  lcommon.CertificateTypeStakeDeregistration,
			cert: &lcommon.StakeDeregistrationCertificate{
				CertType: uint(lcommon.CertificateTypeStakeDeregistration), StakeCredential: testScriptCred(0x22),
			},
			want: `{"kind":"stake_deregistration","stake_credential":{"type":"script_hash","hash":"` + testHex28(0x22) + `"},"refund_implicit":true}`,
		},
		{
			name: "stake delegation",
			typ:  lcommon.CertificateTypeStakeDelegation,
			cert: func() lcommon.Certificate {
				cred := testKeyCred(0x11)
				return &lcommon.StakeDelegationCertificate{
					CertType: uint(lcommon.CertificateTypeStakeDelegation), StakeCredential: &cred,
					PoolKeyHash: lcommon.PoolKeyHash(testHash28(0x33)),
				}
			}(),
			want: `{"kind":"stake_delegation",` + stake + `,` + pool + `}`,
		},
		{
			name: "pool registration names reward account and owners",
			typ:  lcommon.CertificateTypePoolRegistration,
			cert: poolReg,
			want: `{"kind":"pool_registration",` + pool +
				`,"reward_account":{"type":"script_hash","hash":"` + testHex28(0x44) + `"}` +
				`,"pool_owners":["` + testHex28(0x55) + `","` + testHex28(0x66) + `"]}`,
		},
		{
			name: "pool retirement names the epoch",
			typ:  lcommon.CertificateTypePoolRetirement,
			cert: &lcommon.PoolRetirementCertificate{
				CertType: uint(lcommon.CertificateTypePoolRetirement), PoolKeyHash: lcommon.PoolKeyHash(testHash28(0x33)), Epoch: 300,
			},
			want: `{"kind":"pool_retirement",` + pool + `,"retirement_epoch":300}`,
		},
		{
			name: "conway registration deposit",
			typ:  lcommon.CertificateTypeRegistration,
			cert: &lcommon.RegistrationCertificate{
				CertType: uint(lcommon.CertificateTypeRegistration), StakeCredential: testKeyCred(0x11), Amount: 2_000_000,
			},
			want: `{"kind":"registration",` + stake + `,"deposit_lovelace":"2000000"}`,
		},
		{
			name: "conway deregistration refund",
			typ:  lcommon.CertificateTypeDeregistration,
			cert: &lcommon.DeregistrationCertificate{
				CertType: uint(lcommon.CertificateTypeDeregistration), StakeCredential: testKeyCred(0x11), Amount: 2_000_000,
			},
			want: `{"kind":"deregistration",` + stake + `,"refund_lovelace":"2000000"}`,
		},
		{
			name: "vote delegation",
			typ:  lcommon.CertificateTypeVoteDelegation,
			cert: &lcommon.VoteDelegationCertificate{
				CertType: uint(lcommon.CertificateTypeVoteDelegation), StakeCredential: testKeyCred(0x11),
				Drep: lcommon.Drep{Type: lcommon.DrepTypeAddrKeyHash, Credential: bytesRepeat(0x77, 28)},
			},
			want: `{"kind":"vote_delegation",` + stake + `,` + drepKey + `}`,
		},
		{
			name: "stake and vote delegation to abstain",
			typ:  lcommon.CertificateTypeStakeVoteDelegation,
			cert: &lcommon.StakeVoteDelegationCertificate{
				CertType: uint(lcommon.CertificateTypeStakeVoteDelegation), StakeCredential: testKeyCred(0x11),
				PoolKeyHash: lcommon.PoolKeyHash(testHash28(0x33)), Drep: lcommon.Drep{Type: lcommon.DrepTypeAbstain},
			},
			want: `{"kind":"stake_vote_delegation",` + stake + `,` + pool + `,"drep":{"type":"abstain"}}`,
		},
		{
			name: "stake registration and delegation",
			typ:  lcommon.CertificateTypeStakeRegistrationDelegation,
			cert: &lcommon.StakeRegistrationDelegationCertificate{
				CertType: uint(lcommon.CertificateTypeStakeRegistrationDelegation), StakeCredential: testKeyCred(0x11),
				PoolKeyHash: lcommon.PoolKeyHash(testHash28(0x33)), Amount: 2_000_000,
			},
			want: `{"kind":"stake_registration_delegation",` + stake + `,` + pool + `,"deposit_lovelace":"2000000"}`,
		},
		{
			name: "vote registration and delegation to no confidence",
			typ:  lcommon.CertificateTypeVoteRegistrationDelegation,
			cert: &lcommon.VoteRegistrationDelegationCertificate{
				CertType: uint(lcommon.CertificateTypeVoteRegistrationDelegation), StakeCredential: testKeyCred(0x11),
				Drep: lcommon.Drep{Type: lcommon.DrepTypeNoConfidence}, Amount: 2_000_000,
			},
			want: `{"kind":"vote_registration_delegation",` + stake + `,"drep":{"type":"no_confidence"},"deposit_lovelace":"2000000"}`,
		},
		{
			name: "stake and vote registration and delegation",
			typ:  lcommon.CertificateTypeStakeVoteRegistrationDelegation,
			cert: &lcommon.StakeVoteRegistrationDelegationCertificate{
				CertType: uint(lcommon.CertificateTypeStakeVoteRegistrationDelegation), StakeCredential: testKeyCred(0x11),
				PoolKeyHash: lcommon.PoolKeyHash(testHash28(0x33)),
				Drep:        lcommon.Drep{Type: lcommon.DrepTypeScriptHash, Credential: bytesRepeat(0x77, 28)},
				Amount:      2_000_000,
			},
			want: `{"kind":"stake_vote_registration_delegation",` + stake + `,` + pool +
				`,"drep":{"type":"script_hash","hash":"` + testHex28(0x77) + `"},"deposit_lovelace":"2000000"}`,
		},
		{
			name: "committee hot key authorization",
			typ:  lcommon.CertificateTypeAuthCommitteeHot,
			cert: &lcommon.AuthCommitteeHotCertificate{
				CertType: uint(lcommon.CertificateTypeAuthCommitteeHot), ColdCredential: testKeyCred(0x99), HotCredential: testScriptCred(0xaa),
			},
			want: `{"kind":"auth_committee_hot",` + cold + `,"committee_hot_credential":{"type":"script_hash","hash":"` + testHex28(0xaa) + `"}}`,
		},
		{
			name: "committee cold key resignation",
			typ:  lcommon.CertificateTypeResignCommitteeCold,
			cert: &lcommon.ResignCommitteeColdCertificate{
				CertType: uint(lcommon.CertificateTypeResignCommitteeCold), ColdCredential: testKeyCred(0x99),
			},
			want: `{"kind":"resign_committee_cold",` + cold + `}`,
		},
		{
			name: "DRep registration deposit",
			typ:  lcommon.CertificateTypeRegistrationDrep,
			cert: &lcommon.RegistrationDrepCertificate{
				CertType: uint(lcommon.CertificateTypeRegistrationDrep), DrepCredential: testScriptCred(0x88), Amount: 500_000_000,
			},
			want: `{"kind":"registration_drep",` + drepCred + `,"deposit_lovelace":"500000000"}`,
		},
		{
			name: "DRep deregistration refund",
			typ:  lcommon.CertificateTypeDeregistrationDrep,
			cert: &lcommon.DeregistrationDrepCertificate{
				CertType: uint(lcommon.CertificateTypeDeregistrationDrep), DrepCredential: testScriptCred(0x88), Amount: 500_000_000,
			},
			want: `{"kind":"deregistration_drep",` + drepCred + `,"refund_lovelace":"500000000"}`,
		},
		{
			name: "DRep update",
			typ:  lcommon.CertificateTypeUpdateDrep,
			cert: &lcommon.UpdateDrepCertificate{
				CertType: uint(lcommon.CertificateTypeUpdateDrep), DrepCredential: testScriptCred(0x88),
			},
			want: `{"kind":"update_drep",` + drepCred + `}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decodeWithCertificate(t, lcommon.CertificateWrapper{Type: uint(tc.typ), Certificate: tc.cert})
			if got != tc.want {
				t.Errorf("certificate summary\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}
