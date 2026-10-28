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

package se050

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
)

// SE05x applet identifier.
var appletAID = []byte{
	0xa0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00,
	0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00,
}

const (
	claISO = 0x00
	claSE  = 0x80

	insWrite     = 0x01
	insRead      = 0x02
	insCrypto    = 0x03
	insMgmt      = 0x04
	insTransient = 0x80

	p1Default   = 0x00
	p1EC        = 0x01
	p1KeyPair   = 0x60
	p1Signature = 0x0c

	p2Default      = 0x00
	p2Sign         = 0x09
	p2Version      = 0x20
	p2Exist        = 0x27
	p2DeleteObject = 0x28
	p2Random       = 0x49

	tag1 = 0x41
	tag2 = 0x42
	tag3 = 0x43
	tag4 = 0x44

	curveEd25519   = 0x40
	sigEd25519Pure = 0xa3

	resultSuccess = 0x01

	swSuccess = 0x9000
)

// Applet configuration bits reported in AppletVersion.Config.
const (
	ConfigECDSA = 0x0002
	ConfigEdDSA = 0x0004
)

// StatusError is returned when the SE050 answers with a status word other
// than 0x9000.
type StatusError struct {
	SW uint16
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("se050: status word %#04x", e.SW)
}

// AppletVersion is the SE05x applet version and feature configuration.
type AppletVersion struct {
	Major, Minor, Patch uint8
	// Config is a bit mask of the cryptographic features enabled on this
	// SE050 variant.
	Config         uint16
	SecureBoxMajor uint8
	SecureBoxMinor uint8
}

// EdDSA reports whether this variant supports Ed25519 signing.
func (v AppletVersion) EdDSA() bool {
	return v.Config&ConfigEdDSA != 0
}

func (v AppletVersion) String() string {
	return fmt.Sprintf("%d.%d.%d config:%#04x securebox:%d.%d",
		v.Major, v.Minor, v.Patch, v.Config, v.SecureBoxMajor, v.SecureBoxMinor)
}

func parseVersion(b []byte) (v AppletVersion, err error) {
	if len(b) != 7 {
		return v, fmt.Errorf("se050: invalid version length %d", len(b))
	}

	return AppletVersion{
		Major:          b[0],
		Minor:          b[1],
		Patch:          b[2],
		Config:         be16(b[3:]),
		SecureBoxMajor: b[5],
		SecureBoxMinor: b[6],
	}, nil
}

// SE050 is a session with the SE05x applet.
type SE050 struct {
	t1 *T1

	ATR     *ATR
	Version AppletVersion
}

// Open resets the T=1 interface and selects the SE05x applet.
func Open(bus Bus) (*SE050, error) {
	se := &SE050{
		t1: NewT1(bus),
	}

	if err := se.Reopen(); err != nil {
		return nil, err
	}

	return se, nil
}

// Reopen soft resets the T=1 interface and selects the applet again, to
// recover a session after a transport error.
func (se *SE050) Reopen() (err error) {
	if se.ATR, err = se.t1.SoftReset(); err != nil {
		return fmt.Errorf("soft reset, %w", err)
	}

	apdu, err := command(claISO, 0xa4, 0x04, 0x00, appletAID, true)

	if err != nil {
		return
	}

	res, err := se.transmit(apdu)

	if err != nil {
		return fmt.Errorf("select, %w", err)
	}

	se.Version, err = parseVersion(res)

	return
}

func (se *SE050) transmit(apdu []byte) (data []byte, err error) {
	res, err := se.t1.Transceive(apdu)

	if err != nil {
		return
	}

	if len(res) < 2 {
		return nil, errors.New("se050: response without status word")
	}

	n := len(res) - 2

	if sw := be16(res[n:]); sw != swSuccess {
		return nil, &StatusError{SW: sw}
	}

	return res[:n], nil
}

// call sends an applet command and returns the value of the response tag1,
// if any.
func (se *SE050) call(ins, p1, p2 byte, tlvs []byte, le bool) ([]byte, error) {
	apdu, err := command(claSE, ins, p1, p2, tlvs, le)

	if err != nil {
		return nil, err
	}

	res, err := se.transmit(apdu)

	if err != nil || !le {
		return nil, err
	}

	return findTLV(res, tag1)
}

func objectID(id uint32) []byte {
	return appendTLV(nil, tag1, []byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)})
}

// GetVersion returns the applet version and configuration.
func (se *SE050) GetVersion() (AppletVersion, error) {
	res, err := se.call(insMgmt, p1Default, p2Version, nil, true)

	if err != nil {
		return AppletVersion{}, err
	}

	return parseVersion(res)
}

// Random returns n bytes from the SE050 random number generator.
func (se *SE050) Random(n uint16) ([]byte, error) {
	return se.call(insMgmt, p1Default, p2Random, appendTLV(nil, tag1, []byte{byte(n >> 8), byte(n)}), true)
}

// Exists reports whether a secure object is present.
func (se *SE050) Exists(id uint32) (bool, error) {
	res, err := se.call(insMgmt, p1Default, p2Exist, objectID(id), true)

	if err != nil {
		return false, err
	}

	if len(res) != 1 {
		return false, fmt.Errorf("se050: invalid exist result length %d", len(res))
	}

	return res[0] == resultSuccess, nil
}

// Delete removes a secure object.
func (se *SE050) Delete(id uint32) error {
	_, err := se.call(insMgmt, p1Default, p2DeleteObject, objectID(id), false)
	return err
}

func writeIns(transient bool) byte {
	if transient {
		return insWrite | insTransient
	}

	return insWrite
}

// GenerateEd25519 creates an Ed25519 key pair inside the SE050. Transient
// objects are discarded when the applet is deselected or reset.
func (se *SE050) GenerateEd25519(id uint32, transient bool) error {
	tlvs := objectID(id)
	tlvs = appendTLV(tlvs, tag2, []byte{curveEd25519})

	_, err := se.call(writeIns(transient), p1EC|p1KeyPair, p2Default, tlvs, false)

	return err
}

// ImportEd25519 writes an Ed25519 key pair derived from an RFC 8032 seed.
//
// The SE050 takes the seed in its natural order but stores and returns the
// public key byte-reversed.
func (se *SE050) ImportEd25519(id uint32, seed []byte, transient bool) error {
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("se050: invalid seed length %d", len(seed))
	}

	pub := reversed(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))

	tlvs := objectID(id)
	tlvs = appendTLV(tlvs, tag2, []byte{curveEd25519})
	tlvs = appendTLV(tlvs, tag3, seed)
	tlvs = appendTLV(tlvs, tag4, pub)

	_, err := se.call(writeIns(transient), p1EC|p1KeyPair, p2Default, tlvs, false)

	return err
}

// PublicKeyEd25519 reads the public half of an Ed25519 key pair.
func (se *SE050) PublicKeyEd25519(id uint32) (ed25519.PublicKey, error) {
	res, err := se.call(insRead, p1Default, p2Default, objectID(id), true)

	if err != nil {
		return nil, err
	}

	if len(res) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("se050: invalid public key length %d", len(res))
	}

	return ed25519.PublicKey(reversed(res)), nil
}

// SignEd25519 returns a PureEdDSA signature over msg.
func (se *SE050) SignEd25519(id uint32, msg []byte) ([]byte, error) {
	tlvs := objectID(id)
	tlvs = appendTLV(tlvs, tag2, []byte{sigEd25519Pure})
	tlvs = appendTLV(tlvs, tag3, msg)

	sig, err := se.call(insCrypto, p1Signature, p2Sign, tlvs, true)

	if err != nil {
		return nil, err
	}

	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("se050: invalid signature length %d", len(sig))
	}

	// R and S are each returned byte-reversed
	return append(reversed(sig[:32]), reversed(sig[32:])...), nil
}

func reversed(b []byte) []byte {
	r := slices.Clone(b)
	slices.Reverse(r)
	return r
}
