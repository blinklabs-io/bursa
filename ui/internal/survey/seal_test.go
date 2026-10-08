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
	"strings"
	"testing"
	"time"
)

// Real drand quicknet beacons, copied from the public chain: signatures for
// rounds 1 and 100. They let the tests unseal against genuine network output
// without any network access.
const (
	quicknetRound1Sig   = "b55e7cb2d5c613ee0b2e28d6750aabbb78c39dcc96bd9d38c2c2e12198df95571de8e8e402a0cc48871c7089a2b3af4b"
	quicknetRound100Sig = "a4a4ff2320c23471a4bf9540ee5fc68e4c6a750dc89fd8bbeb9ba56e0708673b2d285461388f14537332492726efd282"
)

func sigBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sealedMode(round, padding uint64) SubmissionMode {
	m := SubmissionMode{Sealed: true, Round: round, PaddingSize: padding}
	b, _ := hex.DecodeString(QuicknetChainHash)
	copy(m.ChainHash[:], b)
	return m
}

// zeroAnswers ends its canonical CBOR in a 0x00 byte (the integer 0), the case
// where stripping trailing zeros would corrupt the plaintext.
func zeroAnswers() []Answer {
	return []Answer{
		{Kind: KindSingleChoice, Question: 0, Choice: 1},
		{Kind: KindNumericRange, Question: 1, Number: 0},
	}
}

func TestAnswersPlaintextIsCanonicalCBORRightPadded(t *testing.T) {
	t.Parallel()
	want := arr(
		arr(uintv(1), uintv(0), uintv(1)),
		arr(uintv(4), uintv(1), uintv(0)),
	)
	got, err := answersPlaintext(zeroAnswers(), 0)
	noErr(t, err)
	equal(t, want, got)

	got, err = answersPlaintext(zeroAnswers(), 64)
	if err != nil || len(got) != 64 {
		t.Fatalf("padded plaintext = %d bytes, err %v; want 64", len(got), err)
	}
	equal(t, want, got[:len(want)])
	equal(t, rep(0, 64-len(want)), got[len(want):])

	// Already longer than the padding size: left as is.
	got, err = answersPlaintext(zeroAnswers(), 3)
	noErr(t, err)
	equal(t, want, got)
}

func TestSealUnsealWithARealQuicknetBeacon(t *testing.T) {
	t.Parallel()
	// Sealing needs no network: only the bundled quicknet public key. Unsealing
	// with the genuine round-100 signature succeeds only if that key and the
	// ciphertext framing are right.
	mode := sealedMode(100, 512)
	sealed, err := SealAnswers(zeroAnswers(), mode)
	noErr(t, err)

	isTrue(t, len(sealed) >= 512)
	isFalse(t, strings.HasPrefix(string(sealed), "-----BEGIN")) // raw age, never the armored text
	isTrue(t, strings.HasPrefix(string(sealed), "age-encryption.org/"))

	got, err := UnsealAnswers(sealed, mode, sigBytes(t, quicknetRound100Sig))
	noErr(t, err)
	equal(t, zeroAnswers(), got)
}

func TestSealHidesAnswerLengthWithinPadding(t *testing.T) {
	t.Parallel()
	mode := sealedMode(100, 512)
	short, err := SealAnswers(zeroAnswers(), mode)
	noErr(t, err)
	long, err := SealAnswers(append(zeroAnswers(), Answer{Kind: KindMultiSelect, Question: 2, Indices: []uint64{0, 1, 2, 3, 4, 5}}), mode)
	noErr(t, err)
	equal(t, len(short), len(long))

	bigger, err := SealAnswers(zeroAnswers(), sealedMode(100, 1024))
	noErr(t, err)
	isTrue(t, len(bigger) > len(short))
}

func TestUnsealRejects(t *testing.T) {
	t.Parallel()
	mode := sealedMode(100, 64)
	sealed, err := SealAnswers(zeroAnswers(), mode)
	if err != nil || len(sealed) == 0 {
		t.Fatalf("seal: %d bytes, err %v", len(sealed), err)
	}
	good := sigBytes(t, quicknetRound100Sig)
	if len(good) < 48 {
		t.Fatal("beacon fixture too short")
	}

	// Sealed to an earlier round than the survey's: anyone could already open
	// it, so it is not a valid response to this survey.
	early, err := SealAnswers(zeroAnswers(), sealedMode(99, 64))
	noErr(t, err)

	corrupt := append([]byte(nil), sealed...)
	corrupt[len(corrupt)-1] ^= 0xff

	for name, tc := range map[string]struct {
		sealed []byte
		mode   SubmissionMode
		beacon []byte
	}{
		"another round's signature": {sealed, mode, sigBytes(t, quicknetRound1Sig)},
		"truncated signature":       {sealed, mode, good[:47]},
		"no signature":              {sealed, mode, nil},
		"corrupt ciphertext":        {corrupt, mode, good},
		"not a ciphertext":          {[]byte("hello"), mode, good},
		"sealed to another round":   {early, mode, good},
		"public survey":             {sealed, SubmissionMode{}, good},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := UnsealAnswers(tc.sealed, tc.mode, tc.beacon); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestSealRejectsUnsupportedModes(t *testing.T) {
	t.Parallel()
	otherChain := sealedMode(100, 64)
	otherChain.ChainHash[0] ^= 1
	for name, mode := range map[string]SubmissionMode{
		"public":           {},
		"unknown chain":    otherChain,
		"no round":         sealedMode(0, 64),
		"empty answer set": sealedMode(100, 64),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			answers := zeroAnswers()
			if name == "empty answer set" {
				answers = nil
			}
			if _, err := SealAnswers(answers, mode); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestVerifyBeacon(t *testing.T) {
	t.Parallel()
	noErr(t, VerifyBeacon(100, sigBytes(t, quicknetRound100Sig)))
	noErr(t, VerifyBeacon(1, sigBytes(t, quicknetRound1Sig)))
	isErr(t, VerifyBeacon(100, sigBytes(t, quicknetRound1Sig)))
	isErr(t, VerifyBeacon(101, sigBytes(t, quicknetRound100Sig)))
	isErr(t, VerifyBeacon(100, nil))
	isErr(t, VerifyBeacon(100, bytes.Repeat([]byte{1}, 48)))
}

func TestCurrentRound(t *testing.T) {
	t.Parallel()
	// Quicknet: genesis 1692803367, one round every 3 seconds, round 1 at genesis.
	at := func(unix int64) uint64 { return CurrentRound(time.Unix(unix, 0)) }
	equal(t, uint64(1), at(1692803367))
	equal(t, uint64(1), at(1692803369))
	equal(t, uint64(2), at(1692803370))
	equal(t, uint64(100), at(1692803367+99*3))
	equal(t, uint64(1), at(1692803000)) // before genesis
}

func TestAnswersPlaintextRefusesPaddingOverTheBound(t *testing.T) {
	t.Parallel()
	raw, err := answersPlaintext(zeroAnswers(), maxPadding)
	noErr(t, err)
	equal(t, maxPadding, len(raw))
	_, err = answersPlaintext(zeroAnswers(), maxPadding+1)
	isErr(t, err)
}
