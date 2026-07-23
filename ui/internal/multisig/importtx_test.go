package multisig

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"testing"

	apollo "github.com/blinklabs-io/apollo/v2"
	"github.com/blinklabs-io/bursa"
	gcbor "github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/conway"
)

func TestPolicyFromScript_RoundTrip(t *testing.T) {
	kh := func(b byte) string { return hex.EncodeToString(bytesRepeat(b, 28)) }
	in := Policy{
		Threshold: 2,
		Participants: []Participant{
			{KeyHashHex: kh(1)}, {KeyHashHex: kh(2)}, {KeyHashHex: kh(3)},
		},
	}
	script, err := composeScript(in)
	if err != nil {
		t.Fatalf("composeScript: %v", err)
	}
	got, err := PolicyFromScript(script)
	if err != nil {
		t.Fatalf("PolicyFromScript: %v", err)
	}
	if got.Threshold != 2 || len(got.Participants) != 3 {
		t.Fatalf("got %d-of-%d, want 2-of-3", got.Threshold, len(got.Participants))
	}
	for i, part := range got.Participants {
		if part.KeyHashHex != in.Participants[i].KeyHashHex {
			t.Errorf("participant %d key hash = %s, want %s", i, part.KeyHashHex, in.Participants[i].KeyHashHex)
		}
	}
}

func TestPolicyFromScript_TimeLocked(t *testing.T) {
	before, after := uint64(100), uint64(200)
	kh := func(b byte) string { return hex.EncodeToString(bytesRepeat(b, 28)) }
	in := Policy{
		Threshold: 1, Participants: []Participant{{KeyHashHex: kh(1)}},
		InvalidBefore: &before, InvalidAfter: &after,
	}
	script, err := composeScript(in)
	if err != nil {
		t.Fatalf("composeScript: %v", err)
	}
	got, err := PolicyFromScript(script)
	if err != nil {
		t.Fatalf("PolicyFromScript: %v", err)
	}
	if got.InvalidBefore == nil || *got.InvalidBefore != before {
		t.Errorf("invalid_before = %v, want %d", got.InvalidBefore, before)
	}
	if got.InvalidAfter == nil || *got.InvalidAfter != after {
		t.Errorf("invalid_after = %v, want %d", got.InvalidAfter, after)
	}
	if got.Threshold != 1 || len(got.Participants) != 1 {
		t.Fatalf("got %d-of-%d, want 1-of-1", got.Threshold, len(got.Participants))
	}
}

// TestPolicyFromScript_UnsupportedShape covers a script shape composeScript
// never emits (a bare pubkey script, with no threshold clause at all): it
// must be rejected as ErrInvalidTx, not silently accepted or panicked on.
func TestPolicyFromScript_UnsupportedShape(t *testing.T) {
	kh := bytesRepeat(1, 28)
	script, err := bursa.NewScriptSig(kh)
	if err != nil {
		t.Fatalf("NewScriptSig: %v", err)
	}
	_, err = PolicyFromScript(script)
	if !errors.Is(err, ErrInvalidTx) {
		t.Fatalf("PolicyFromScript() error = %v, want ErrInvalidTx", err)
	}
}

// TestPolicyFromScript_RejectsMultipleThresholdClauses covers a non-canonical
// `all` script the node validates in full but composeScript never emits: two
// N-of-K threshold clauses. Silently keeping only the last would let cosigning
// report readiness against one clause while the node still enforces both, so
// PolicyFromScript must reject it.
func TestPolicyFromScript_RejectsMultipleThresholdClauses(t *testing.T) {
	first, err := bursa.NewMultiSigScript(1, bytesRepeat(1, 28))
	if err != nil {
		t.Fatalf("NewMultiSigScript(first): %v", err)
	}
	second, err := bursa.NewMultiSigScript(1, bytesRepeat(2, 28))
	if err != nil {
		t.Fatalf("NewMultiSigScript(second): %v", err)
	}
	all, err := bursa.NewScriptAll(first, second)
	if err != nil {
		t.Fatalf("NewScriptAll: %v", err)
	}
	if _, err := PolicyFromScript(all); !errors.Is(err, ErrInvalidTx) {
		t.Fatalf("PolicyFromScript(two threshold clauses) error = %v, want ErrInvalidTx", err)
	}
}

func bytesRepeat(b byte, n int) []byte {
	s := make([]byte, n)
	for i := range s {
		s[i] = b
	}
	return s
}

// --- InspectTx / FindByScriptHash ------------------------------------------

// TestInspectTx_EmbeddedScript builds a real 2-of-3 multisig account, funds
// its script address, and Build()s an unsigned spend (which attaches the
// native script to the witness set per Build's contract). InspectTx must
// recover the embedded script's policy and report zero signatures collected
// so far, plus pick up the saved account's label via FindByScriptHash.
func TestInspectTx_EmbeddedScript(t *testing.T) {
	fc := newFakeChain()
	svc := NewService(fc, nil, filepath.Join(t.TempDir(), "multisig.json"))
	_, khA, _ := multiSigKeyHash(t, mnemonicA)
	_, khB, _ := multiSigKeyHash(t, mnemonicB)
	khC := hex.EncodeToString(bytesRepeat(3, 28))

	acct, err := svc.Create(CreateRequest{
		Label:   "treasury",
		Network: "preview",
		Policy: Policy{
			Threshold: 2,
			Participants: []Participant{
				{KeyHashHex: khA}, {KeyHashHex: khB}, {KeyHashHex: khC},
			},
		},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	fc.addUTxO(acct.ScriptAddress, strings.Repeat("11", 32), 0, 10_000_000)

	built, err := svc.Build(context.Background(), acct.ID, BuildRequest{To: externalAddr(t), Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	info, err := svc.InspectTx(built.UnsignedTxCBOR)
	if err != nil {
		t.Fatalf("InspectTx: %v", err)
	}
	if !info.IsMultiSig {
		t.Fatal("expected IsMultiSig")
	}
	if info.Threshold != 2 || len(info.Participants) != 3 {
		t.Errorf("got %d-of-%d, want 2-of-3", info.Threshold, len(info.Participants))
	}
	if info.SignedCount != 0 {
		t.Errorf("signed_count = %d, want 0", info.SignedCount)
	}
	if !info.ScriptEmbedded {
		t.Error("Build attaches the script, so ScriptEmbedded should be true")
	}
	if info.Label != acct.Label {
		t.Errorf("label = %q, want %q (recovered via FindByScriptHash)", info.Label, acct.Label)
	}
	if info.ScriptHash == "" {
		t.Error("expected a non-empty script hash")
	}
	for _, p := range info.Participants {
		if p.Signed {
			t.Errorf("participant %s reported signed on an unsigned tx", p.KeyHash)
		}
	}
}

// TestInspectTx_MintOnlyIsNotMultiSig covers the classification bug: an
// ordinary vkey-signed payment that also mints a token/NFT under a
// native-script policy carries that policy script in its witness set (the
// ledger requires it there to authorize the mint) but has no script-locked
// spend at all. InspectTx must NOT classify this as a multisig spend — doing
// so would route it to the cosign/submit path, where it fails because the
// wallet isn't a "participant" of the mint policy.
func TestInspectTx_MintOnlyIsNotMultiSig(t *testing.T) {
	fc := newFakeChain()
	svc := NewService(fc, nil, filepath.Join(t.TempDir(), "multisig.json"))

	// A bare pubkey native script used purely as a minting policy (not a
	// multisig N-of-M threshold script, and not saved as an account here).
	mintScript, err := bursa.NewScriptSig(bytesRepeat(9, 28))
	if err != nil {
		t.Fatalf("NewScriptSig: %v", err)
	}
	policyIDHex := hex.EncodeToString(mintScript.Hash().Bytes())

	txHex := mintOnlyTxHex(t, fc, mintScript, policyIDHex)

	info, err := svc.InspectTx(txHex)
	if err != nil {
		t.Fatalf("InspectTx: %v", err)
	}
	if info.IsMultiSig {
		t.Errorf("mint-only native script must not be classified multisig: %+v", info)
	}
	if info.ScriptEmbedded {
		t.Error("mint-only tx must not report ScriptEmbedded (routed to the vkey path)")
	}
}

// TestInspectTx_MultiSigSpendPlusMint covers the mixed case: a real multisig
// spend script alongside an unrelated mint policy script in the same witness
// set. The spend script must still be selected (it doesn't match any mint
// policy ID) and the tx must still classify as multisig.
func TestInspectTx_MultiSigSpendPlusMint(t *testing.T) {
	fc := newFakeChain()
	svc := NewService(fc, nil, filepath.Join(t.TempDir(), "multisig.json"))
	_, khA, _ := multiSigKeyHash(t, mnemonicA)
	_, khB, _ := multiSigKeyHash(t, mnemonicB)

	acct, err := svc.Create(CreateRequest{
		Label:   "treasury",
		Network: "preview",
		Policy: Policy{
			Threshold:    2,
			Participants: []Participant{{KeyHashHex: khA}, {KeyHashHex: khB}},
		},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	fc.addUTxO(acct.ScriptAddress, strings.Repeat("77", 32), 0, 10_000_000)

	built, err := svc.Build(context.Background(), acct.ID, BuildRequest{To: externalAddr(t), Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Attach an unrelated mint policy script (different hash) on top of the
	// already-built multisig spend tx.
	mintScript, err := bursa.NewScriptSig(bytesRepeat(8, 28))
	if err != nil {
		t.Fatalf("NewScriptSig: %v", err)
	}
	policyIDHex := hex.EncodeToString(mintScript.Hash().Bytes())
	txHex := addMintToTx(t, built.UnsignedTxCBOR, mintScript, policyIDHex)

	info, err := svc.InspectTx(txHex)
	if err != nil {
		t.Fatalf("InspectTx: %v", err)
	}
	if !info.IsMultiSig {
		t.Fatalf("multisig spend script must still classify as multisig even with an unrelated mint policy attached: %+v", info)
	}
	if info.Threshold != 2 || len(info.Participants) != 2 {
		t.Errorf("got %d-of-%d, want 2-of-2", info.Threshold, len(info.Participants))
	}
}

// TestInspectTx_ScriptWithdrawalIsUnsupported covers the classification bug for
// stake-purpose native scripts: a reward-account withdrawal governed by a
// native script carries that script in the witness set, but it is there to
// authorize a stake action, NOT a payment spend. InspectTx must NOT treat it as
// a payment-multisig spend — doing so routes it to CosignImported, which
// derives the role-0 PAYMENT multisig key and so produces the wrong key for the
// legitimate owner (whose participation is via the stake/DRep key). It must be
// reported as a recognizable-but-unsupported multisig (embedded script,
// threshold 0, no participants) so CosignImported/SubmitImported refuse it.
func TestInspectTx_ScriptWithdrawalIsUnsupported(t *testing.T) {
	fc := newFakeChain()
	svc := NewService(fc, nil, filepath.Join(t.TempDir(), "multisig.json"))

	stakeScript, err := composeScript(Policy{
		Threshold:    1,
		Participants: []Participant{{KeyHashHex: hex.EncodeToString(bytesRepeat(5, 28))}},
	})
	if err != nil {
		t.Fatalf("composeScript: %v", err)
	}
	txHex := injectScriptWithdrawal(t, fc, stakeScript)

	info, err := svc.InspectTx(txHex)
	if err != nil {
		t.Fatalf("InspectTx: %v", err)
	}
	if !info.IsMultiSig || !info.ScriptEmbedded {
		t.Fatalf("stake-script withdrawal should classify as an embedded multisig: %+v", info)
	}
	if info.Threshold != 0 || len(info.Participants) != 0 {
		t.Fatalf("stake-script withdrawal must NOT be treated as a payment-multisig spend (want threshold 0, no participants): %+v", info)
	}
}

// TestInspectTx_VotingProcedureScriptIsUnsupported covers the governance-vote
// arm of the stake-purpose classifier: a DRep-script vote carries its native
// script in the witness set to authorize the vote, NOT a payment spend.
// InspectTx must NOT treat it as a payment-multisig spend (which would route it
// to CosignImported and derive the wrong role-0 payment key); it must report a
// recognizable-but-unsupported multisig (embedded script, threshold 0, no
// participants).
func TestInspectTx_VotingProcedureScriptIsUnsupported(t *testing.T) {
	fc := newFakeChain()
	svc := NewService(fc, nil, filepath.Join(t.TempDir(), "multisig.json"))

	voteScript, err := composeScript(Policy{
		Threshold:    1,
		Participants: []Participant{{KeyHashHex: hex.EncodeToString(bytesRepeat(6, 28))}},
	})
	if err != nil {
		t.Fatalf("composeScript: %v", err)
	}
	txHex := injectScriptVote(t, fc, voteScript)

	info, err := svc.InspectTx(txHex)
	if err != nil {
		t.Fatalf("InspectTx: %v", err)
	}
	if !info.IsMultiSig || !info.ScriptEmbedded {
		t.Fatalf("governance-vote script should classify as an embedded multisig: %+v", info)
	}
	if info.Threshold != 0 || len(info.Participants) != 0 {
		t.Fatalf("governance-vote script must NOT be treated as a payment-multisig spend (want threshold 0, no participants): %+v", info)
	}
}

// TestInspectTx_StakeScriptAlsoMintIsUnsupported covers the mint-vs-stake
// precedence bug: a script that is both a stake/gov credential (here, a script-
// credentialed withdrawal) AND reused as a mint policy must let the stake
// purpose dominate. It must be classified as an unsupported stake/gov multisig
// (threshold 0), NOT routed to the vkey path just because its hash also matches
// a mint policy — the stake/gov witness would otherwise be left unsatisfied.
func TestInspectTx_StakeScriptAlsoMintIsUnsupported(t *testing.T) {
	fc := newFakeChain()
	svc := NewService(fc, nil, filepath.Join(t.TempDir(), "multisig.json"))

	script, err := composeScript(Policy{
		Threshold:    1,
		Participants: []Participant{{KeyHashHex: hex.EncodeToString(bytesRepeat(9, 28))}},
	})
	if err != nil {
		t.Fatalf("composeScript: %v", err)
	}
	txHex := injectScriptWithdrawalAndMint(t, fc, script)

	info, err := svc.InspectTx(txHex)
	if err != nil {
		t.Fatalf("InspectTx: %v", err)
	}
	if !info.IsMultiSig || !info.ScriptEmbedded {
		t.Fatalf("stake script reused as a mint policy should classify as an embedded multisig: %+v", info)
	}
	if info.Threshold != 0 || len(info.Participants) != 0 {
		t.Fatalf("stake-script-also-mint must NOT be routed to the vkey path (want threshold 0, no participants): %+v", info)
	}
}

// TestStakeScriptCredentialHashes_Certificate exercises the certificate branch
// of the stake-purpose detector directly: a stake-deregistration certificate
// bearing a script credential must be collected (so InspectTx excludes that
// script from payment-spend candidates), while the same certificate with an
// addr-key-hash credential must not be.
func TestStakeScriptCredentialHashes_Certificate(t *testing.T) {
	scriptHashHex := hex.EncodeToString(bytesRepeat(7, 28))
	var credHash lcommon.Blake2b224
	copy(credHash[:], bytesRepeat(7, 28))

	scriptCred := func(credType uint) *conway.ConwayTransaction {
		tx := &conway.ConwayTransaction{}
		tx.Body.TxCertificates = []lcommon.CertificateWrapper{{
			Type: uint(lcommon.CertificateTypeStakeDeregistration),
			Certificate: &lcommon.StakeDeregistrationCertificate{
				StakeCredential: lcommon.Credential{CredType: credType, Credential: credHash},
			},
		}}
		return tx
	}

	if got := stakeScriptCredentialHashes(scriptCred(lcommon.CredentialTypeScriptHash)); !got[scriptHashHex] {
		t.Fatalf("stake-deregistration script credential %s not collected: %v", scriptHashHex, got)
	}
	if got := stakeScriptCredentialHashes(scriptCred(lcommon.CredentialTypeAddrKeyHash)); len(got) != 0 {
		t.Fatalf("addr-key-hash credential must not be collected as a stake script: %v", got)
	}
}

// TestStakeScriptCredentialHashes_VotingProcedure exercises the governance-vote
// branch of the stake-purpose detector directly: DRep-script and committee-hot-
// script voters authorize their vote via a native script and must be collected
// (so InspectTx excludes those scripts from payment-spend candidates), while
// key-hash voters (DRep-key, committee-hot-key, stake-pool) carry no script and
// must not be collected.
func TestStakeScriptCredentialHashes_VotingProcedure(t *testing.T) {
	voterHash := func(fill byte) [28]byte {
		var h [28]byte
		copy(h[:], bytesRepeat(fill, 28))
		return h
	}
	tx := &conway.ConwayTransaction{}
	drepScript := voterHash(0xd1)
	ccHotScript := voterHash(0xc2)
	drepKey := voterHash(0xd3)
	ccHotKey := voterHash(0xc4)
	poolKey := voterHash(0x5e)
	tx.Body.TxVotingProcedures = lcommon.VotingProcedures{
		{Type: lcommon.VoterTypeDRepScriptHash, Hash: drepScript}:                       {},
		{Type: lcommon.VoterTypeConstitutionalCommitteeHotScriptHash, Hash: ccHotScript}: {},
		{Type: lcommon.VoterTypeDRepKeyHash, Hash: drepKey}:                              {},
		{Type: lcommon.VoterTypeConstitutionalCommitteeHotKeyHash, Hash: ccHotKey}:       {},
		{Type: lcommon.VoterTypeStakingPoolKeyHash, Hash: poolKey}:                       {},
	}

	got := stakeScriptCredentialHashes(tx)
	if !got[hex.EncodeToString(drepScript[:])] {
		t.Errorf("DRep-script voter hash not collected: %v", got)
	}
	if !got[hex.EncodeToString(ccHotScript[:])] {
		t.Errorf("committee-hot-script voter hash not collected: %v", got)
	}
	for _, kh := range [][28]byte{drepKey, ccHotKey, poolKey} {
		if got[hex.EncodeToString(kh[:])] {
			t.Errorf("key-hash voter %x must not be collected as a stake script: %v", kh, got)
		}
	}
	if len(got) != 2 {
		t.Errorf("want exactly the 2 script voters, got %d: %v", len(got), got)
	}
}

// injectScriptWithdrawal decodes an ordinary unsigned tx and rewrites it to
// carry a reward-account withdrawal keyed by ns's script hash, plus ns in the
// witness set — the shape a script-credentialed (stake-purpose) withdrawal
// takes. See mintOnlyTxHex for why this is done at the gouroboros struct level.
func injectScriptWithdrawal(t *testing.T, fc *fakeChain, ns *bursa.NativeScript) string {
	t.Helper()
	tx := decodeConwayTx(t, ordinaryUnsignedTxHex(t, fc))

	// Reward account (stake address) with a script staking credential: a header
	// byte of AddressTypeNoneScript on the testnet network, then the 28-byte
	// script hash.
	scriptHash := ns.Hash()
	raw := append(
		[]byte{byte(lcommon.AddressTypeNoneScript<<4 | lcommon.AddressNetworkTestnet)},
		scriptHash.Bytes()...,
	)
	addr, err := lcommon.NewAddressFromBytes(raw)
	if err != nil {
		t.Fatalf("reward addr: %v", err)
	}
	tx.Body.TxWithdrawals = map[*lcommon.Address]uint64{&addr: 1_000_000}
	tx.WitnessSet.WsNativeScripts = gcbor.NewSetType([]lcommon.NativeScript{*ns}, true)

	tx.SetCbor(nil)
	tx.Body.SetCbor(nil)
	tx.WitnessSet.SetCbor(nil)
	return encodeConwayTx(t, &tx)
}

// injectScriptVote decodes an ordinary unsigned tx and rewrites it to carry a
// governance voting procedure cast by a DRep-script voter keyed by ns's script
// hash, plus ns in the witness set — the shape a vote-by-native-script tx takes.
// See mintOnlyTxHex for why this is done at the gouroboros struct level.
func injectScriptVote(t *testing.T, fc *fakeChain, ns *bursa.NativeScript) string {
	t.Helper()
	tx := decodeConwayTx(t, ordinaryUnsignedTxHex(t, fc))

	var voterHash [28]byte
	copy(voterHash[:], ns.Hash().Bytes())
	voter := &lcommon.Voter{Type: lcommon.VoterTypeDRepScriptHash, Hash: voterHash}
	govAction := &lcommon.GovActionId{GovActionIdx: 0}
	tx.Body.TxVotingProcedures = lcommon.VotingProcedures{
		voter: {govAction: lcommon.VotingProcedure{Vote: 1}},
	}
	tx.WitnessSet.WsNativeScripts = gcbor.NewSetType([]lcommon.NativeScript{*ns}, true)

	tx.SetCbor(nil)
	tx.Body.SetCbor(nil)
	tx.WitnessSet.SetCbor(nil)
	return encodeConwayTx(t, &tx)
}

// injectScriptWithdrawalAndMint builds a script-credentialed withdrawal tx (as
// injectScriptWithdrawal) and additionally mints one unit under the SAME script
// hash as a mint policy — a stake/gov script reused as a mint policy. InspectTx
// must let the stake purpose dominate the mint purpose and classify it as an
// unsupported stake/gov multisig, not route it to the vkey path.
func injectScriptWithdrawalAndMint(t *testing.T, fc *fakeChain, ns *bursa.NativeScript) string {
	t.Helper()
	tx := decodeConwayTx(t, injectScriptWithdrawal(t, fc, ns))
	injectMint(t, &tx, hex.EncodeToString(ns.Hash().Bytes()), []lcommon.NativeScript{*ns})
	return encodeConwayTx(t, &tx)
}

// mintOnlyTxHex builds an ordinary vkey-signed payment tx (via
// ordinaryUnsignedTxHex — no script-locked input at all) and then injects a
// mint of one unit under mintScript's policy ID plus mintScript itself into
// the witness set, directly at the decoded-struct level. This is the shape
// the ledger requires to authorize a native-script mint, and exactly what
// used to be misclassified as a multisig spend.
//
// Apollo's Mint/AttachScript builder methods only feed a fresh Complete()/
// CompleteContext() build — they don't retroactively mutate a tx already
// loaded via LoadTxCbor (GetTxCbor just re-serializes whatever is in the
// loaded struct) — so post-hoc injection has to happen at the gouroboros
// struct level, decoding then re-encoding the CBOR directly.
func mintOnlyTxHex(t *testing.T, fc *fakeChain, mintScript *bursa.NativeScript, policyIDHex string) string {
	t.Helper()
	tx := decodeConwayTx(t, ordinaryUnsignedTxHex(t, fc))
	injectMint(t, &tx, policyIDHex, []lcommon.NativeScript{*mintScript})
	return encodeConwayTx(t, &tx)
}

// addMintToTx decodes an already-built unsigned tx CBOR and injects an
// additional mint under mintScript's policy plus mintScript itself into the
// witness set (ahead of whatever native scripts the tx already carries), so
// the result carries both the original spend script and the new mint policy
// script. See mintOnlyTxHex for why this happens at the struct level rather
// than through Apollo's builder methods.
func addMintToTx(t *testing.T, unsignedTxCBOR string, mintScript *bursa.NativeScript, policyIDHex string) string {
	t.Helper()
	tx := decodeConwayTx(t, unsignedTxCBOR)
	scripts := append([]lcommon.NativeScript{*mintScript}, tx.WitnessSet.NativeScripts()...)
	injectMint(t, &tx, policyIDHex, scripts)
	return encodeConwayTx(t, &tx)
}

// decodeConwayTx hex-decodes and CBOR-decodes a Conway transaction.
func decodeConwayTx(t *testing.T, txHex string) conway.ConwayTransaction {
	t.Helper()
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		t.Fatalf("decode tx hex: %v", err)
	}
	var tx conway.ConwayTransaction
	if _, err := gcbor.Decode(txBytes, &tx); err != nil {
		t.Fatalf("decode tx: %v", err)
	}
	return tx
}

// injectMint sets tx.Body.TxMint to mint one unit under policyIDHex and
// replaces the witness set's native scripts with scripts, clearing the CBOR
// caches so re-encoding reflects the change.
func injectMint(t *testing.T, tx *conway.ConwayTransaction, policyIDHex string, scripts []lcommon.NativeScript) {
	t.Helper()
	policyBytes, err := hex.DecodeString(policyIDHex)
	if err != nil {
		t.Fatalf("decode policy id: %v", err)
	}
	var policyID lcommon.Blake2b224
	copy(policyID[:], policyBytes)
	mintData := map[lcommon.Blake2b224]map[gcbor.ByteString]lcommon.MultiAssetTypeMint{
		policyID: {gcbor.NewByteString([]byte("token")): big.NewInt(1)},
	}
	mint := lcommon.NewMultiAsset[lcommon.MultiAssetTypeMint](mintData)
	tx.Body.TxMint = &mint
	tx.WitnessSet.WsNativeScripts = gcbor.NewSetType(scripts, true)

	tx.SetCbor(nil)
	tx.Body.SetCbor(nil)
	tx.WitnessSet.SetCbor(nil)
}

// encodeConwayTx CBOR-encodes a Conway transaction back to hex.
func encodeConwayTx(t *testing.T, tx *conway.ConwayTransaction) string {
	t.Helper()
	out, err := gcbor.Encode(tx)
	if err != nil {
		t.Fatalf("re-encode tx: %v", err)
	}
	return hex.EncodeToString(out)
}

// TestInspectTx_NotMultiSig feeds InspectTx an ordinary (no native script)
// unsigned tx CBOR and asserts it is not classified as multisig.
func TestInspectTx_NotMultiSig(t *testing.T) {
	fc := newFakeChain()
	svc := NewService(fc, nil, filepath.Join(t.TempDir(), "multisig.json"))

	info, err := svc.InspectTx(ordinaryUnsignedTxHex(t, fc))
	if err != nil {
		t.Fatalf("InspectTx: %v", err)
	}
	if info.IsMultiSig {
		t.Error("ordinary tx must not be classified multisig")
	}
	if info.ScriptEmbedded {
		t.Error("ordinary tx must not report an embedded script")
	}
}

// TestInspectTx_MalformedHex covers the ErrInvalidTx wrapping requirement for
// hex that doesn't even decode.
func TestInspectTx_MalformedHex(t *testing.T) {
	fc := newFakeChain()
	svc := NewService(fc, nil, filepath.Join(t.TempDir(), "multisig.json"))
	if _, err := svc.InspectTx("not-hex-at-all"); !errors.Is(err, ErrInvalidTx) {
		t.Fatalf("InspectTx(bad hex) error = %v, want ErrInvalidTx", err)
	}
}

// TestFindByScriptHash_SkipsDecodeErrors saves one account with a corrupt
// ScriptCBOR (so decodeScript fails) and one valid account, and asserts the
// search still finds the valid one rather than aborting on the bad record.
func TestFindByScriptHash_SkipsDecodeErrors(t *testing.T) {
	fc := newFakeChain()
	svc := NewService(fc, nil, filepath.Join(t.TempDir(), "multisig.json"))
	_, khA, _ := multiSigKeyHash(t, mnemonicA)

	acct, err := svc.Create(CreateRequest{
		Label:   "good",
		Network: "preview",
		Policy:  Policy{Threshold: 1, Participants: []Participant{{KeyHashHex: khA}}},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	script, err := decodeScript(acct.ScriptCBOR)
	if err != nil {
		t.Fatalf("decodeScript: %v", err)
	}
	wantHash := hex.EncodeToString(script.Hash().Bytes())

	// Inject a second, corrupt account directly into the store (bypassing
	// Create, which would validate the script).
	corrupt := Account{ID: "corrupt", Label: "corrupt", Network: "preview", ScriptCBOR: "zz-not-hex"}
	if err := svc.store.add(corrupt); err != nil {
		t.Fatalf("add corrupt account: %v", err)
	}

	got, ok, err := svc.FindByScriptHash(wantHash)
	if err != nil {
		t.Fatalf("FindByScriptHash: %v", err)
	}
	if !ok || got.ID != acct.ID {
		t.Fatalf("FindByScriptHash = %+v, %v, want %s, true", got, ok, acct.ID)
	}

	if _, ok, err := svc.FindByScriptHash(strings.Repeat("ab", 28)); err != nil || ok {
		t.Fatalf("FindByScriptHash(unknown) = %v, %v, want false, nil", ok, err)
	}
}

// --- CosignImported ----------------------------------------------------------

// TestCosignImported_AddsAndMerges builds a 1-of-1 account whose sole
// participant is this wallet's own CIP-1854 key, funds it, builds a spend, and
// cosigns the resulting pasted (unsigned) tx CBOR. The first cosign must
// attach the wallet's witness (Added=true, SignedCount=1); re-cosigning the
// returned CBOR must not attach a duplicate (Added=false, idempotent).
func TestCosignImported_AddsAndMerges(t *testing.T) {
	fc := newFakeChain()
	ks := newTestKeystore(t, mnemonicA)
	svc := NewService(fc, ks, filepath.Join(t.TempDir(), "multisig.json"))

	mk, err := svc.MyKey("test-password-123")
	if err != nil {
		t.Fatalf("MyKey: %v", err)
	}
	acct, err := svc.Create(CreateRequest{
		Label:   "solo",
		Network: "preview",
		Policy:  Policy{Threshold: 1, Participants: []Participant{{KeyHashHex: mk.KeyHashHex}}},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	fc.addUTxO(acct.ScriptAddress, strings.Repeat("22", 32), 0, 10_000_000)

	built, err := svc.Build(context.Background(), acct.ID, BuildRequest{To: externalAddr(t), Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	res, err := svc.CosignImported(built.UnsignedTxCBOR, "test-password-123")
	if err != nil {
		t.Fatalf("CosignImported: %v", err)
	}
	if !res.Added || res.SignedCount != 1 || res.Threshold != 1 {
		t.Fatalf("CosignImported = %+v, want Added=true SignedCount=1 Threshold=1", res)
	}
	if res.TxCBOR == "" {
		t.Fatal("expected non-empty tx_cbor")
	}

	// Re-cosigning the returned (already-signed) CBOR is idempotent: no
	// duplicate witness gets added.
	res2, err := svc.CosignImported(res.TxCBOR, "test-password-123")
	if err != nil {
		t.Fatalf("CosignImported (2nd): %v", err)
	}
	if res2.Added {
		t.Error("second cosign should not add a duplicate witness")
	}
	if res2.SignedCount != 1 {
		t.Errorf("SignedCount after re-cosign = %d, want 1", res2.SignedCount)
	}
}

// TestCosignImported_NotAParticipant builds an account whose sole participant
// is a foreign key-hash the wallet does not own, and asserts CosignImported
// refuses with ErrInvalidRequest rather than silently signing a script it
// isn't party to.
func TestCosignImported_NotAParticipant(t *testing.T) {
	fc := newFakeChain()
	ks := newTestKeystore(t, mnemonicA)
	svc := NewService(fc, ks, filepath.Join(t.TempDir(), "multisig.json"))

	acct, err := svc.Create(CreateRequest{
		Label:   "foreign",
		Network: "preview",
		Policy:  Policy{Threshold: 1, Participants: []Participant{{KeyHashHex: strings.Repeat("ab", 28)}}},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	fc.addUTxO(acct.ScriptAddress, strings.Repeat("33", 32), 0, 10_000_000)

	built, err := svc.Build(context.Background(), acct.ID, BuildRequest{To: externalAddr(t), Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if _, err := svc.CosignImported(built.UnsignedTxCBOR, "test-password-123"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("CosignImported error = %v, want ErrInvalidRequest", err)
	}
}

// TestCosignImported_PreservesOtherCosigner is the real multi-party regression
// for CosignImported's headline guarantee ("preserves existing co-signer
// witnesses"): unlike TestCosignImported_AddsAndMerges (a 1-of-1 policy where
// there is no other co-signer to preserve), this builds a genuine 2-of-2
// policy across two independent keystores/wallets (mirrors TestSpendFlow's
// svcA/svcB setup) and cosigns in two hops through the pasted-CBOR flow:
// svcA attaches its witness first, then svcB imports svcA's *result* CBOR and
// attaches its own. The final tx must carry BOTH participants' witnesses —
// proving svcB's merge didn't clobber svcA's — which InspectTx confirms via
// SignedCount and each participant's Signed flag.
func TestCosignImported_PreservesOtherCosigner(t *testing.T) {
	fc := newFakeChain()
	ksA := newTestKeystore(t, mnemonicA)
	ksB := newTestKeystore(t, mnemonicB)

	// Two independent wallets (separate keystores + separate on-disk stores),
	// sharing only the fake chain.
	svcA := NewService(fc, ksA, filepath.Join(t.TempDir(), "a.json"))
	svcB := NewService(fc, ksB, filepath.Join(t.TempDir(), "b.json"))

	mkA, err := svcA.MyKey("test-password-123")
	if err != nil {
		t.Fatalf("MyKey A: %v", err)
	}
	mkB, err := svcB.MyKey("test-password-123")
	if err != nil {
		t.Fatalf("MyKey B: %v", err)
	}

	// svcA creates the joint 2-of-2 account (its own store only — CosignImported
	// recovers the policy from the tx's embedded script, so svcB never needs
	// this account saved in its own store).
	acct, err := svcA.Create(CreateRequest{
		Label:   "joint",
		Network: "preview",
		Policy: Policy{
			Threshold:    2,
			Participants: []Participant{{KeyHashHex: mkA.KeyHashHex}, {KeyHashHex: mkB.KeyHashHex}},
		},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	fc.addUTxO(acct.ScriptAddress, strings.Repeat("44", 32), 0, 10_000_000)

	built, err := svcA.Build(context.Background(), acct.ID, BuildRequest{To: externalAddr(t), Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Hop 1: svcA cosigns the freshly-built unsigned tx.
	resA, err := svcA.CosignImported(built.UnsignedTxCBOR, "test-password-123")
	if err != nil {
		t.Fatalf("CosignImported A: %v", err)
	}
	if !resA.Added || resA.SignedCount != 1 {
		t.Fatalf("CosignImported A = %+v, want Added=true SignedCount=1", resA)
	}

	// Hop 2: svcB pastes svcA's *result* CBOR (not the original unsigned tx)
	// and cosigns it — the real "pass the CBOR along" workflow.
	resB, err := svcB.CosignImported(resA.TxCBOR, "test-password-123")
	if err != nil {
		t.Fatalf("CosignImported B: %v", err)
	}
	if !resB.Added || resB.SignedCount != 2 {
		t.Fatalf("CosignImported B = %+v, want Added=true SignedCount=2", resB)
	}

	// The final tx must carry BOTH witnesses: svcA's survived svcB's merge.
	info, err := svcA.InspectTx(resB.TxCBOR)
	if err != nil {
		t.Fatalf("InspectTx: %v", err)
	}
	if info.SignedCount != 2 {
		t.Fatalf("SignedCount = %d, want 2", info.SignedCount)
	}
	for _, p := range info.Participants {
		if !p.Signed {
			t.Errorf("participant %s not signed, want both participants signed", p.KeyHash)
		}
	}
}

// --- SubmitImported ----------------------------------------------------------

// TestSubmitImported_BelowThresholdRejected builds a 2-of-2 policy (this
// wallet's own CIP-1854 key plus a foreign key-hash it does not own), funds
// the script address, builds a spend, and cosigns with only this wallet's key
// (1 of 2). SubmitImported must refuse to broadcast a below-threshold tx.
func TestSubmitImported_BelowThresholdRejected(t *testing.T) {
	fc := newFakeChain()
	ks := newTestKeystore(t, mnemonicA)
	svc := NewService(fc, ks, filepath.Join(t.TempDir(), "multisig.json"))

	mk, err := svc.MyKey("test-password-123")
	if err != nil {
		t.Fatalf("MyKey: %v", err)
	}
	acct, err := svc.Create(CreateRequest{
		Label:   "2of2",
		Network: "preview",
		Policy: Policy{Threshold: 2, Participants: []Participant{
			{KeyHashHex: mk.KeyHashHex}, {KeyHashHex: strings.Repeat("cd", 28)},
		}},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	fc.addUTxO(acct.ScriptAddress, strings.Repeat("55", 32), 0, 10_000_000)

	built, err := svc.Build(context.Background(), acct.ID, BuildRequest{To: externalAddr(t), Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	signed, err := svc.CosignImported(built.UnsignedTxCBOR, "test-password-123") // 1 of 2
	if err != nil {
		t.Fatalf("CosignImported: %v", err)
	}
	if _, err := svc.SubmitImported(context.Background(), signed.TxCBOR); !errors.Is(err, ErrInvalidWitness) {
		t.Fatalf("SubmitImported error = %v, want ErrInvalidWitness (below threshold)", err)
	}
}

// TestSubmitImported_ThresholdMetBroadcasts builds a 1-of-1 policy owned
// entirely by this wallet, cosigns it (meeting the threshold), and asserts
// SubmitImported broadcasts successfully and returns a non-empty tx hash.
func TestSubmitImported_ThresholdMetBroadcasts(t *testing.T) {
	fc := newFakeChain()
	ks := newTestKeystore(t, mnemonicA)
	svc := NewService(fc, ks, filepath.Join(t.TempDir(), "multisig.json"))

	mk, err := svc.MyKey("test-password-123")
	if err != nil {
		t.Fatalf("MyKey: %v", err)
	}
	acct, err := svc.Create(CreateRequest{
		Label:   "1of1",
		Network: "preview",
		Policy:  Policy{Threshold: 1, Participants: []Participant{{KeyHashHex: mk.KeyHashHex}}},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	fc.addUTxO(acct.ScriptAddress, strings.Repeat("66", 32), 0, 10_000_000)

	built, err := svc.Build(context.Background(), acct.ID, BuildRequest{To: externalAddr(t), Lovelace: "1000000"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	signed, err := svc.CosignImported(built.UnsignedTxCBOR, "test-password-123")
	if err != nil {
		t.Fatalf("CosignImported: %v", err)
	}
	res, err := svc.SubmitImported(context.Background(), signed.TxCBOR)
	if err != nil {
		t.Fatalf("SubmitImported: %v", err)
	}
	if res.TxHash == "" {
		t.Error("expected a tx hash")
	}
}

// ordinaryUnsignedTxHex builds a plain (non-script) unsigned spend directly
// through apollo — no AttachScript call — so the resulting Conway tx's
// witness set carries zero native scripts. It exercises the same
// build/complete path as Service.Build minus the script attachment, giving a
// realistic (not hand-crafted) "not multisig" fixture.
func ordinaryUnsignedTxHex(t *testing.T, fc *fakeChain) string {
	t.Helper()
	root, err := bursa.GetRootKeyFromMnemonic(mnemonicA, "")
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	acctKey, err := bursa.GetAccountKey(root, 0)
	if err != nil {
		t.Fatalf("account key: %v", err)
	}
	pay, err := bursa.GetPaymentKey(acctKey, 0)
	if err != nil {
		t.Fatalf("payment key: %v", err)
	}
	stake, err := bursa.GetStakeKey(acctKey, 0)
	if err != nil {
		t.Fatalf("stake key: %v", err)
	}
	addr, err := lcommon.NewAddressFromParts(
		lcommon.AddressTypeKeyKey, lcommon.AddressNetworkTestnet,
		pay.Public().PublicKey().Hash(), stake.Public().PublicKey().Hash(),
	)
	if err != nil {
		t.Fatalf("plain addr: %v", err)
	}
	fc.addUTxO(addr.String(), strings.Repeat("cc", 32), 0, 10_000_000)

	a := apollo.New(fc).
		SetWallet(apollo.NewExternalWallet(addr)).
		SetChangeAddress(addr)
	utxos, err := fc.Utxos(context.Background(), addr)
	if err != nil {
		t.Fatalf("utxos: %v", err)
	}
	a = a.AddLoadedUTxOs(utxos...)
	a = a.PayToAddress(addr, 1_000_000)

	a, err = a.CompleteContext(context.Background())
	if err != nil {
		t.Fatalf("complete ordinary tx: %v", err)
	}
	cborBytes, err := a.GetTxCbor()
	if err != nil {
		t.Fatalf("encode ordinary tx: %v", err)
	}
	return hex.EncodeToString(cborBytes)
}
