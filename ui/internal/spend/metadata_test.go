// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package spend

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/wallet"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/ledger"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

func metaUint(n uint64) lcommon.TransactionMetadatum {
	return lcommon.MetaInt{Value: new(big.Int).SetUint64(n)}
}

// metaValue is a label value shaped like a CIP-179 payload: a list holding an
// integer-keyed map whose keys are in ascending order.
func metaValue() lcommon.TransactionMetadatum {
	var pairs []lcommon.MetaPair
	for _, k := range []uint64{0, 1, 2, 10, 300} {
		pairs = append(pairs, lcommon.MetaPair{Key: metaUint(k), Value: metaUint(k + 100)})
	}
	return lcommon.MetaList{Items: []lcommon.TransactionMetadatum{
		metaUint(1), lcommon.MetaList{Items: []lcommon.TransactionMetadatum{lcommon.MetaMap{Pairs: pairs}}},
	}}
}

// accountKeyHashes returns the wallet's payment (address 0), stake and DRep
// key hashes, read from the account independently of the service.
func accountKeyHashes(t *testing.T, acct *wallet.Account) map[SignerKind]string {
	t.Helper()
	return map[SignerKind]string{
		SignerPayment: paymentKeyHashForAddress(t, acct.ReceiveAddresses[0]),
		SignerStake:   stakeKeyHashForAddress(t, acct.ReceiveAddresses[0]),
		SignerDRep:    drepKeyHashForAccount(t, acct),
	}
}

func TestWalletCredential(t *testing.T) {
	t.Parallel()
	acct := mustDeriveConfirmAccount(t)
	s := NewService(nil, nil, acct)
	for kind, want := range accountKeyHashes(t, acct) {
		got, err := s.WalletCredential(kind)
		if err != nil {
			t.Fatalf("WalletCredential(%s): %v", kind, err)
		}
		if hex.EncodeToString(got[:]) != want {
			t.Errorf("WalletCredential(%s) = %x, want %s", kind, got, want)
		}
	}
	if _, err := s.WalletCredential("spo"); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("unknown kind: err = %v, want ErrInvalidRequest", err)
	}
	if _, err := NewService(nil, nil, nil).WalletCredential(SignerStake); !errors.Is(err, ErrNoWallet) {
		t.Errorf("no wallet: err = %v, want ErrNoWallet", err)
	}
}

func TestBuildMetadataCarriesTheValueUnchanged(t *testing.T) {
	t.Parallel()
	acct := mustDeriveConfirmAccount(t)
	s := NewService(newFakeChain(10_000_000, acct.ReceiveAddresses[0]), nil, acct)
	value := metaValue()

	pv, err := s.BuildMetadata(context.Background(), MetadataRequest{Label: 17, Value: value, Signer: SignerPayment})
	if err != nil {
		t.Fatalf("BuildMetadata: %v", err)
	}
	unsigned, err := s.ExportUnsigned(pv.PendingID)
	if err != nil {
		t.Fatalf("ExportUnsigned: %v", err)
	}
	raw, err := hex.DecodeString(unsigned.UnsignedTxCBOR)
	if err != nil {
		t.Fatal(err)
	}
	var parts []cbor.RawMessage
	if _, err := cbor.Decode(raw, &parts); err != nil || len(parts) != 4 {
		t.Fatalf("decode tx: %v (%d parts)", err, len(parts))
	}

	// The auxiliary data is exactly {17: value}: the supplied metadatum, byte for
	// byte, so its integer map keys stay in ascending order.
	want, err := cbor.Encode(lcommon.MetaMap{Pairs: []lcommon.MetaPair{{Key: metaUint(17), Value: value}}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parts[3], want) {
		t.Fatalf("auxiliary data = %x\nwant           %x", []byte(parts[3]), want)
	}

	// The body commits to those exact bytes.
	tx, err := ledger.NewConwayTransactionFromCbor(raw)
	if err != nil {
		t.Fatalf("decode conway tx: %v", err)
	}
	hash := lcommon.Blake2b256Hash(want)
	if tx.Body.TxAuxDataHash == nil || *tx.Body.TxAuxDataHash != hash {
		t.Fatalf("auxiliary data hash = %v, want %x", tx.Body.TxAuxDataHash, hash)
	}
}

func TestBuildMetadataRequiresTheCredentialSigner(t *testing.T) {
	t.Parallel()
	for _, kind := range []SignerKind{SignerPayment, SignerStake, SignerDRep} {
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()
			acct := mustDeriveConfirmAccount(t)
			s := NewService(newFakeChain(10_000_000, acct.ReceiveAddresses[0]), nil, acct)
			pv, err := s.BuildMetadata(context.Background(), MetadataRequest{Label: 17, Value: metaValue(), Signer: kind})
			if err != nil {
				t.Fatalf("BuildMetadata: %v", err)
			}
			hashes := accountKeyHashes(t, acct)
			signers := exportedRequiredSignerSet(t, s, pv.PendingID)
			// The credential's key plus the payment key of the spent input, and
			// no other wallet key.
			want := map[string]bool{hashes[SignerPayment]: true, hashes[kind]: true}
			if len(signers) != len(want) {
				t.Fatalf("required signers = %v, want %v", signers, want)
			}
			for h := range want {
				if !signers[h] {
					t.Fatalf("required signers = %v, missing %s", signers, h)
				}
			}
		})
	}
}

// vkeyHashes lists the key hashes of the vkey witnesses in a submitted tx.
func vkeyHashes(t *testing.T, txCbor []byte) map[string]bool {
	t.Helper()
	tx, err := ledger.NewConwayTransactionFromCbor(txCbor)
	if err != nil {
		t.Fatalf("decode submitted tx: %v", err)
	}
	out := map[string]bool{}
	for _, w := range tx.WitnessSet.VkeyWitnesses.Items() {
		h := lcommon.Blake2b224Hash(w.Vkey)
		out[hex.EncodeToString(h[:])] = true
	}
	return out
}

func TestConfirmMetadataTxSignsWithTheCredentialKey(t *testing.T) {
	t.Parallel()
	for _, kind := range []SignerKind{SignerPayment, SignerStake, SignerDRep} {
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()
			acct := mustDeriveConfirmAccount(t)
			// Funds sit at receive address 1 only, so the credential's payment
			// key (address 0) signs only if Confirm adds it for the credential.
			fc := newFakeChain(10_000_000, acct.ReceiveAddresses[1])
			s := NewService(fc, fakeKeystore{mnemonic: testMnemonic}, acct)
			ctx := context.Background()

			pv, err := s.BuildMetadata(ctx, MetadataRequest{Label: 17, Value: metaValue(), Signer: kind})
			if err != nil {
				t.Fatalf("BuildMetadata: %v", err)
			}
			if _, err := s.Confirm(ctx, pv.PendingID, "pw"); err != nil {
				t.Fatalf("Confirm: %v", err)
			}
			got := vkeyHashes(t, fc.submittedTxCbor())
			hashes := accountKeyHashes(t, acct)
			input := paymentKeyHashForAddress(t, acct.ReceiveAddresses[1])
			for _, want := range []string{hashes[kind], input} {
				if !got[want] {
					t.Errorf("witnesses %v lack key %s", got, want)
				}
			}
			if kind != SignerStake && got[hashes[SignerStake]] || kind != SignerDRep && got[hashes[SignerDRep]] {
				t.Errorf("witnesses %v include a key the credential did not need", got)
			}
		})
	}
}

// Hardware devices are shown only the structured fields of a transaction, so a
// body that commits to auxiliary data they never see cannot be signed there.
func TestBuildMetadataStaysUnsignableOnHardware(t *testing.T) {
	t.Parallel()
	acct := mustDeriveConfirmAccount(t)
	s := NewService(newFakeChain(10_000_000, acct.ReceiveAddresses[0]), nil, acct)
	pv, err := s.BuildMetadata(context.Background(), MetadataRequest{Label: 17, Value: metaValue(), Signer: SignerPayment})
	if err != nil {
		t.Fatalf("BuildMetadata: %v", err)
	}
	req, err := s.HardwareSignRequest(pv.PendingID)
	if err != nil {
		t.Fatalf("HardwareSignRequest: %v", err)
	}
	if !strings.Contains(req.Unsupported, "auxiliary data") {
		t.Fatalf("Unsupported = %q, want an auxiliary data rejection", req.Unsupported)
	}
}

func TestBuildMetadataRejectsBadRequests(t *testing.T) {
	t.Parallel()
	acct := mustDeriveConfirmAccount(t)
	s := NewService(newFakeChain(10_000_000, acct.ReceiveAddresses[0]), nil, acct)
	ctx := context.Background()

	if _, err := s.BuildMetadata(ctx, MetadataRequest{Label: 17, Signer: SignerPayment}); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("nil value: err = %v, want ErrInvalidRequest", err)
	}
	if _, err := s.BuildMetadata(ctx, MetadataRequest{Label: 17, Value: metaValue(), Signer: "spo"}); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("unknown signer: err = %v, want ErrInvalidRequest", err)
	}
	empty := NewService(newFakeChain(10_000_000, acct.ReceiveAddresses[0]), nil, nil)
	if _, err := empty.BuildMetadata(ctx, MetadataRequest{Label: 17, Value: metaValue(), Signer: SignerPayment}); !errors.Is(err, ErrNoWallet) {
		t.Errorf("no wallet: err = %v, want ErrNoWallet", err)
	}
}
