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
	"context"
	"errors"
	"fmt"

	apollo "github.com/Salvionied/apollo/v2"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// SignerKind names which of the wallet's keys a metadata transaction proves
// control of.
type SignerKind string

const (
	SignerPayment SignerKind = "payment" // payment key of the first receive address
	SignerStake   SignerKind = "stake"
	SignerDRep    SignerKind = "drep"
)

// MetadataRequest asks for a payment-less transaction that carries Value under
// metadata Label and lists the Signer key in its required signers, so the
// ledger enforces that the wallet controls that credential.
type MetadataRequest struct {
	Label  uint64
	Value  lcommon.TransactionMetadatum
	Signer SignerKind
}

// WalletCredential returns the key hash of the active wallet's key of the given
// kind: the credential a metadata transaction built for that kind proves.
func (s *Service) WalletCredential(kind SignerKind) ([28]byte, error) {
	_, acct, _ := s.currentBinding()
	if acct == nil {
		return [28]byte{}, ErrNoWallet
	}
	return walletCredential(acct, kind)
}

func walletCredential(acct *wallet.Account, kind SignerKind) ([28]byte, error) {
	if len(acct.ReceiveAddresses) == 0 {
		return [28]byte{}, errors.New("account has no receive addresses")
	}
	addr, err := lcommon.NewAddress(acct.ReceiveAddresses[0])
	if err != nil {
		return [28]byte{}, fmt.Errorf("base address: %w", err)
	}
	// A script credential's hash reads through the same accessors as a key
	// hash, but no wallet key can witness it, so it is refused rather than
	// listed as a required signer the transaction could never satisfy.
	switch kind {
	case SignerPayment:
		switch addr.Type() {
		case lcommon.AddressTypeKeyKey, lcommon.AddressTypeKeyScript, lcommon.AddressTypeKeyPointer, lcommon.AddressTypeKeyNone:
			return addr.PaymentKeyHash(), nil
		}
		return [28]byte{}, fmt.Errorf("%w: wallet payment credential is not a key", ErrInvalidRequest)
	case SignerStake:
		switch addr.Type() {
		case lcommon.AddressTypeKeyKey, lcommon.AddressTypeScriptKey:
			return addr.StakeKeyHash(), nil
		}
		return [28]byte{}, fmt.Errorf("%w: wallet has no stake key", ErrInvalidRequest)
	case SignerDRep:
		drep, err := drepFromHex(acct.DRepKeyHash)
		if err != nil {
			return [28]byte{}, fmt.Errorf("%w: wallet has no DRep key", ErrInvalidRequest)
		}
		return [28]byte(drep.Credential), nil
	}
	return [28]byte{}, fmt.Errorf("%w: unknown signer kind %q", ErrInvalidRequest, kind)
}

// BuildMetadata builds a metadata-only transaction for preview and later
// Confirm. Apollo is handed the metadatum as is, so its encoding (and the
// auxiliary data hash over it) is exactly what the caller built.
//
// The pending transaction is software-signed only: hardware devices are shown
// the structured fields of a body and never the auxiliary data it commits to,
// so HardwareSignRequest keeps rejecting such a body.
func (s *Service) BuildMetadata(ctx context.Context, req MetadataRequest) (Preview, error) {
	walletID, acct, gen := s.currentBinding()
	if acct == nil {
		return Preview{}, ErrNoWallet
	}
	if req.Value == nil {
		return Preview{}, fmt.Errorf("%w: metadata value required", ErrInvalidRequest)
	}
	credential, err := walletCredential(acct, req.Signer)
	if err != nil {
		return Preview{}, err
	}

	a, utxoAddr, err := s.completeWithSigners(ctx, acct, []lcommon.Blake2b224{credential},
		func(next *apollo.Apollo) (*apollo.Apollo, error) {
			return next.SetShelleyMetadata(map[uint64]any{req.Label: req.Value}), nil
		})
	if err != nil {
		return Preview{}, err
	}
	if err := s.guardTxSize(ctx, a, utxoAddr); err != nil {
		return Preview{}, err
	}

	id := s.mkID()
	s.mu.Lock()
	if s.gen != gen || s.walletID != walletID {
		s.mu.Unlock()
		return Preview{}, ErrWalletChanged
	}
	s.sweepExpiredLocked()
	s.pending[id] = &pending{
		tx:       a,
		utxoAddr: utxoAddr,
		created:  s.now(),
		walletID: walletID,
		account:  cloneAccount(acct),
		signer:   req.Signer,
	}
	s.mu.Unlock()
	return toPreview(id, a), nil
}
