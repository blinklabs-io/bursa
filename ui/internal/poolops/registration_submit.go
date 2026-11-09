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

package poolops

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	apollo "github.com/Salvionied/apollo/v2"
	"github.com/Salvionied/apollo/v2/backend"
	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/bip32"
	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// PoolRegistry reports whether a pool is already registered on chain. A new
// registration locks the pool deposit; a re-registration of a registered pool
// is a parameter update and locks none.
type PoolRegistry interface {
	PoolRegistered(
		ctx context.Context,
		poolID string,
	) (registered bool, err error)
}

// RegistrationTxResult is returned after a pool registration or update
// transaction is submitted. Update is true when the pool was already registered,
// so no deposit was locked.
type RegistrationTxResult struct {
	TxHash string `json:"tx_hash"`
	Update bool   `json:"update"`
}

// SetPoolRegistry wires the on-chain pool lookup SubmitRegistration needs to
// decide whether the transaction locks the pool deposit. Pass nil to clear it.
func (s *Service) SetPoolRegistry(r PoolRegistry) {
	s.mu.Lock()
	s.registry = r
	s.mu.Unlock()
}

func (s *Service) poolRegistry() PoolRegistry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.registry
}

// SubmitRegistration builds the registration/update certificate from the active
// wallet's seed-derived cold and VRF keys, places it in a transaction funded
// from the active account, signs it (payment keys, the owner stake key and the
// pool cold key) and submits it. The pool deposit is locked only when the pool
// is not yet registered on chain. Every owner must be the wallet's own stake
// key: an owner the wallet cannot sign for needs the air-gap flow.
func (s *Service) SubmitRegistration(
	ctx context.Context,
	password string,
	p RegistrationParams,
) (RegistrationTxResult, error) {
	walletID, acct := s.currentBinding()
	if acct == nil {
		return RegistrationTxResult{}, ErrNoWallet
	}
	if s.chain == nil {
		return RegistrationTxResult{}, errors.New("no chain context configured")
	}
	registry := s.poolRegistry()
	if registry == nil {
		return RegistrationTxResult{}, errors.New("no pool registry configured")
	}
	if len(acct.ReceiveAddresses) == 0 {
		return RegistrationTxResult{}, errors.New(
			"account has no receive addresses",
		)
	}
	if strings.TrimSpace(p.ColdVKeyHex) != "" {
		return RegistrationTxResult{}, fmt.Errorf(
			"%w: an external cold key cannot be submitted in-app; use the air-gap flow",
			ErrInvalidRequest,
		)
	}
	root, zero, err := s.unlockRoot(walletID, password)
	if err != nil {
		return RegistrationTxResult{}, err
	}
	defer zero()

	built, err := s.buildRegistrationFromRoot(root, p, acct)
	if err != nil {
		return RegistrationTxResult{}, err
	}
	certBytes, err := hex.DecodeString(built.CBORHex)
	if err != nil {
		return RegistrationTxResult{}, fmt.Errorf("decode certificate: %w", err)
	}
	var cert lcommon.PoolRegistrationCertificate
	if _, err := cbor.Decode(certBytes, &cert); err != nil {
		return RegistrationTxResult{}, fmt.Errorf("decode certificate: %w", err)
	}

	// The wallet can witness only its own stake key, so every owner must be it.
	acctKey, err := bursa.GetAccountKey(root, acct.AccountIndex)
	if err != nil {
		return RegistrationTxResult{}, fmt.Errorf("account key: %w", err)
	}
	defer zeroBytes(acctKey)
	stakeKey, err := bursa.GetStakeKey(acctKey, 0)
	if err != nil {
		return RegistrationTxResult{}, fmt.Errorf("stake key: %w", err)
	}
	stakeHash := lcommon.Blake2b224Hash(
		bip32.XPrv(stakeKey).Public().PublicKey(),
	)
	zeroBytes(stakeKey)
	for _, owner := range cert.PoolOwners {
		if lcommon.Blake2b224(owner) != stakeHash {
			return RegistrationTxResult{}, fmt.Errorf(
				"%w: owner %x is not this wallet's stake key; use the air-gap flow",
				ErrInvalidRequest,
				owner[:],
			)
		}
	}

	registered, err := registry.PoolRegistered(ctx, built.PoolID)
	if err != nil {
		return RegistrationTxResult{}, fmt.Errorf(
			"check pool registration: %w",
			err,
		)
	}

	cold, err := deriveCold(root, defaultColdIndex)
	if err != nil {
		return RegistrationTxResult{}, err
	}
	defer cold.zero()

	plan := poolTxPlan{
		addCerts: func(a *apollo.Apollo) (*apollo.Apollo, error) {
			return a.SetCertificates([]lcommon.CertificateWrapper{{
				Type:        uint(lcommon.CertificateTypePoolRegistration),
				Certificate: &cert,
			}}), nil
		},
		stakeSigners: []lcommon.Blake2b224{stakeHash},
	}
	if registered {
		// Apollo charges the pool deposit for every registration certificate;
		// an update locks none, so build it against zero pool deposit.
		plan.chain = noPoolDepositChain{ChainContext: s.chain}
	}
	hash, err := s.submitPoolTx(ctx, root, acct, &cold, plan)
	if err != nil {
		return RegistrationTxResult{}, err
	}
	return RegistrationTxResult{TxHash: hash, Update: registered}, nil
}

// noPoolDepositChain reports a zero pool deposit and otherwise delegates,
// including the context-aware methods, so cancellation and submission behave as
// they do on the wrapped chain.
type noPoolDepositChain struct {
	backend.ChainContext
}

func (c noPoolDepositChain) zeroDeposit(
	pp backend.ProtocolParameters,
	err error,
) (backend.ProtocolParameters, error) {
	pp.PoolDeposits = "0"
	return pp, err
}

func (c noPoolDepositChain) ProtocolParams() (backend.ProtocolParameters, error) {
	return c.zeroDeposit(c.ChainContext.ProtocolParams())
}

func (c noPoolDepositChain) ProtocolParamsContext(
	ctx context.Context,
) (backend.ProtocolParameters, error) {
	return c.zeroDeposit(backend.ProtocolParamsContext(ctx, c.ChainContext))
}

func (c noPoolDepositChain) GenesisParamsContext(
	ctx context.Context,
) (backend.GenesisParameters, error) {
	return backend.GenesisParamsContext(ctx, c.ChainContext)
}

func (c noPoolDepositChain) CurrentEpochContext(
	ctx context.Context,
) (uint64, error) {
	return backend.CurrentEpochContext(ctx, c.ChainContext)
}

func (c noPoolDepositChain) MaxTxFeeContext(
	ctx context.Context,
) (uint64, error) {
	return backend.MaxTxFeeContext(ctx, c.ChainContext)
}

func (c noPoolDepositChain) TipContext(ctx context.Context) (uint64, error) {
	return backend.TipContext(ctx, c.ChainContext)
}

func (c noPoolDepositChain) UtxosContext(
	ctx context.Context,
	address lcommon.Address,
) ([]lcommon.Utxo, error) {
	return backend.UtxosContext(ctx, c.ChainContext, address)
}

func (c noPoolDepositChain) SubmitTxContext(
	ctx context.Context,
	txCbor []byte,
) (lcommon.Blake2b256, error) {
	return backend.SubmitTxContext(ctx, c.ChainContext, txCbor)
}

func (c noPoolDepositChain) EvaluateTxContext(
	ctx context.Context,
	txCbor []byte,
	additionalUtxos []lcommon.Utxo,
) (map[lcommon.RedeemerKey]lcommon.ExUnits, error) {
	return backend.EvaluateTxContext(
		ctx,
		c.ChainContext,
		txCbor,
		additionalUtxos,
	)
}

func (c noPoolDepositChain) UtxoByRefContext(
	ctx context.Context,
	txHash lcommon.Blake2b256,
	index uint32,
) (*lcommon.Utxo, error) {
	return backend.UtxoByRefContext(ctx, c.ChainContext, txHash, index)
}

func (c noPoolDepositChain) ScriptCborContext(
	ctx context.Context,
	scriptHash lcommon.Blake2b224,
) ([]byte, error) {
	return backend.ScriptCborContext(ctx, c.ChainContext, scriptHash)
}

// Capabilities forwards the wrapped chain's capability set.
func (c noPoolDepositChain) Capabilities() backend.CapabilitySet {
	return backend.CapabilitiesOf(c.ChainContext)
}

var (
	_ backend.ContextChainContext = noPoolDepositChain{}
	_ backend.CapabilityReporter  = noPoolDepositChain{}
)
