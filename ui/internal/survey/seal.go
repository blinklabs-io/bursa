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

package survey

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/drand/drand/v2/crypto"
	"github.com/drand/kyber"
	"github.com/drand/tlock"
)

// Sealed responses are timelock-encrypted to the Drand quicknet chain, the only
// chain this package seals to. Its parameters are bundled so sealing never
// touches the network; only unsealing needs the beacon for the reveal round.
const (
	// QuicknetChainHash is the hex chain hash of Drand quicknet.
	QuicknetChainHash = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"

	quicknetPublicKey = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
	quicknetGenesis   = int64(1692803367)
	quicknetPeriod    = 3 * time.Second
)

// ErrBeaconMissing is returned when unsealing needs a beacon that was not
// supplied.
var ErrBeaconMissing = errors.New("survey: drand beacon not available")

func quicknetHash() (h [32]byte) {
	b, _ := hex.DecodeString(QuicknetChainHash) // constant, valid hex
	copy(h[:], b)
	return h
}

// CurrentRound is the quicknet round published at the given time. Round 1 is
// published at genesis.
func CurrentRound(now time.Time) uint64 {
	if now.Unix() < quicknetGenesis {
		return 1
	}
	return uint64(now.Unix()-quicknetGenesis)/uint64(quicknetPeriod/time.Second) + 1 //nolint:gosec // checked non-negative
}

func quicknetScheme() (*crypto.Scheme, kyber.Point, error) {
	scheme, err := crypto.SchemeFromName(crypto.SigsOnG1ID)
	if err != nil {
		return nil, nil, err
	}
	raw, err := hex.DecodeString(quicknetPublicKey)
	if err != nil {
		return nil, nil, err
	}
	pub := scheme.KeyGroup.Point()
	if err := pub.UnmarshalBinary(raw); err != nil {
		return nil, nil, fmt.Errorf("quicknet public key: %w", err)
	}
	return scheme, pub, nil
}

type beacon struct {
	round uint64
	sig   []byte
}

func (b beacon) GetRound() uint64             { return b.round }
func (b beacon) GetSignature() []byte         { return b.sig }
func (b beacon) GetPreviousSignature() []byte { return nil }

// VerifyBeacon checks a quicknet beacon signature for a round.
func VerifyBeacon(round uint64, sig []byte) error {
	scheme, pub, err := quicknetScheme()
	if err != nil {
		return err
	}
	if err := scheme.VerifyBeacon(beacon{round: round, sig: sig}, pub); err != nil {
		return fmt.Errorf("%w: beacon for round %d: %w", ErrInvalid, round, err)
	}
	return nil
}

// quicknetNetwork is the tlock network for quicknet. It holds at most one
// beacon, for the survey's reveal round, and fails any other round's lookup, so
// a response sealed to a different round cannot be opened through it.
type quicknetNetwork struct {
	scheme *crypto.Scheme
	pub    kyber.Point
	round  uint64
	sig    []byte
}

func (n quicknetNetwork) ChainHash() string          { return QuicknetChainHash }
func (n quicknetNetwork) Current(t time.Time) uint64 { return CurrentRound(t) }
func (n quicknetNetwork) PublicKey() kyber.Point     { return n.pub }
func (n quicknetNetwork) Scheme() crypto.Scheme      { return *n.scheme }
func (n quicknetNetwork) SwitchChainHash(string) error {
	return errors.New("only quicknet is supported")
}

func (n quicknetNetwork) Signature(round uint64) ([]byte, error) {
	if round != n.round || len(n.sig) == 0 {
		return nil, ErrBeaconMissing
	}
	return n.sig, nil
}

func (m SubmissionMode) checkQuicknet() error {
	if !m.Sealed {
		return invalidf("survey is not sealed")
	}
	if m.ChainHash != quicknetHash() {
		return invalidf("unsupported drand chain %x", m.ChainHash)
	}
	if m.Round == 0 {
		return invalidf("sealed survey has no reveal round")
	}
	return nil
}

// maxPadding bounds the plaintext a sealed response is padded to. A larger
// padding size is refused rather than silently reduced, since a shorter
// plaintext would no longer hide its answers' length as the survey intends.
const maxPadding = 1 << 20

// answersPlaintext is the canonical CBOR of the answer array, right-padded with
// zero bytes to padding. A plaintext already longer than padding is not
// truncated.
func answersPlaintext(answers []Answer, padding uint64) ([]byte, error) {
	if padding > maxPadding {
		return nil, invalidf("padding size %d exceeds %d bytes", padding, maxPadding)
	}
	items := make([]metadatum, len(answers))
	for i, a := range answers {
		md, err := encodeAnswer(a)
		if err != nil {
			return nil, err
		}
		items[i] = md
	}
	raw, err := cbor.Encode(metaList{Items: items})
	if err != nil {
		return nil, err
	}
	if missing := int(padding) - len(raw); missing > 0 { //nolint:gosec // padding bounded above
		raw = append(raw, make([]byte, missing)...)
	}
	return raw, nil
}

// SealAnswers timelock-encrypts the answers to the mode's reveal round and
// returns the raw (not armored) ciphertext for a sealed response.
func SealAnswers(answers []Answer, mode SubmissionMode) ([]byte, error) {
	if err := mode.checkQuicknet(); err != nil {
		return nil, err
	}
	if len(answers) == 0 {
		return nil, invalidf("no answers to seal")
	}
	plaintext, err := answersPlaintext(answers, mode.PaddingSize)
	if err != nil {
		return nil, err
	}
	scheme, pub, err := quicknetScheme()
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	net := quicknetNetwork{scheme: scheme, pub: pub, round: mode.Round}
	if err := tlock.New(net).Strict().Encrypt(&out, bytes.NewReader(plaintext), mode.Round); err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	return out.Bytes(), nil
}

// UnsealAnswers decrypts a sealed response with the beacon signature for the
// mode's reveal round and reads the answers: the first CBOR item of the
// plaintext, ignoring the zero padding after it.
func UnsealAnswers(sealed []byte, mode SubmissionMode, beaconSig []byte) ([]Answer, error) {
	if err := mode.checkQuicknet(); err != nil {
		return nil, err
	}
	scheme, pub, err := quicknetScheme()
	if err != nil {
		return nil, err
	}
	net := quicknetNetwork{scheme: scheme, pub: pub, round: mode.Round, sig: beaconSig}
	var plaintext bytes.Buffer
	if err := tlock.New(net).Strict().Decrypt(&plaintext, bytes.NewReader(sealed)); err != nil {
		return nil, invalidf("unseal: %v", err)
	}
	var first cbor.RawMessage
	if _, err := cbor.Decode(plaintext.Bytes(), &first); err != nil {
		return nil, invalidf("unsealed answers: %v", err)
	}
	md, err := lcommon.DecodeMetadatumRaw(first)
	if err != nil {
		return nil, invalidf("unsealed answers: %v", err)
	}
	items, err := asList(md, 1, -1)
	if err != nil {
		return nil, err
	}
	answers := make([]Answer, len(items))
	for i, item := range items {
		if answers[i], err = decodeAnswer(item); err != nil {
			return nil, err
		}
	}
	return answers, nil
}
