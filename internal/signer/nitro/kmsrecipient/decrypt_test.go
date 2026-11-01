// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package kmsrecipient

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecryptRejectsMalformedRecipientCiphertext(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for _, value := range [][]byte{nil, {}, {0x30}, {0x30, 0x80, 0, 0}, make([]byte, maxBERSize+1)} {
		plaintext, err := Decrypt(key, value)
		require.Nil(t, plaintext)
		require.ErrorIs(t, err, ErrDecrypt)
	}
}

func TestDecryptRejectsNilKeyWithoutParsing(t *testing.T) {
	plaintext, err := Decrypt(nil, []byte{0x30, 0})
	require.Nil(t, plaintext)
	require.ErrorIs(t, err, ErrDecrypt)
}

// The fixture is assembled from raw ASN.1 rather than the parser's own
// structs, so a wrong tag or field order in those structs cannot cancel out.
func derTLV(t *testing.T, class, tag int, compound bool, children ...[]byte) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(asn1.RawValue{
		Class: class, Tag: tag, IsCompound: compound, Bytes: bytes.Join(children, nil),
	})
	require.NoError(t, err)
	return encoded
}

func derValue(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(value)
	require.NoError(t, err)
	return encoded
}

func berIndefinite(identifier byte, children ...[]byte) []byte {
	out := []byte{identifier, 0x80}
	out = append(out, bytes.Join(children, nil)...)
	return append(out, 0, 0)
}

type recipientFixture struct {
	key        *rsa.PrivateKey
	plaintext  []byte
	encrypted  []byte
	iv         []byte
	ciphertext []byte
}

func newRecipientFixture(t *testing.T) recipientFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	plaintext := bytes.Repeat([]byte{0x5a}, 32)
	contentKey := bytes.Repeat([]byte{0x11}, aes256KeySize)
	iv := bytes.Repeat([]byte{0x22}, aes.BlockSize)
	padded := append(bytes.Clone(plaintext), bytes.Repeat([]byte{aes.BlockSize}, aes.BlockSize)...)
	block, err := aes.NewCipher(contentKey)
	require.NoError(t, err)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, contentKey, nil)
	require.NoError(t, err)
	return recipientFixture{key: key, plaintext: plaintext, encrypted: encrypted, iv: iv, ciphertext: ciphertext}
}

func (f recipientFixture) recipientInfo(t *testing.T) []byte {
	sha256ID := derTLV(t, asn1.ClassUniversal, asn1.TagSequence, true, derValue(t, oidSHA256), derValue(t, asn1.NullRawValue))
	oaepParams := derTLV(t, asn1.ClassUniversal, asn1.TagSequence, true,
		derTLV(t, asn1.ClassContextSpecific, 0, true, sha256ID),
		derTLV(t, asn1.ClassContextSpecific, 1, true,
			derTLV(t, asn1.ClassUniversal, asn1.TagSequence, true, derValue(t, oidMGF1), sha256ID)),
		derTLV(t, asn1.ClassContextSpecific, 2, true,
			derTLV(t, asn1.ClassUniversal, asn1.TagSequence, true, derValue(t, oidPSpecified), derValue(t, []byte{}))),
	)
	return derTLV(t, asn1.ClassUniversal, asn1.TagSequence, true,
		derValue(t, recipientInfoVersion),
		derTLV(t, asn1.ClassContextSpecific, 0, false, []byte("subject-key-id")),
		derTLV(t, asn1.ClassUniversal, asn1.TagSequence, true, derValue(t, oidRSAESOAEP), oaepParams),
		derValue(t, f.encrypted),
	)
}

func (f recipientFixture) contentAlgorithm(t *testing.T) []byte {
	return derTLV(t, asn1.ClassUniversal, asn1.TagSequence, true, derValue(t, oidAES256CBC), derValue(t, f.iv))
}

func (f recipientFixture) der(t *testing.T) []byte {
	enveloped := derTLV(t, asn1.ClassUniversal, asn1.TagSequence, true,
		derValue(t, envelopedDataVersion),
		derTLV(t, asn1.ClassUniversal, asn1.TagSet, true, f.recipientInfo(t)),
		derTLV(t, asn1.ClassUniversal, asn1.TagSequence, true,
			derValue(t, oidData),
			f.contentAlgorithm(t),
			derTLV(t, asn1.ClassContextSpecific, 0, false, f.ciphertext),
		),
	)
	return derTLV(t, asn1.ClassUniversal, asn1.TagSequence, true,
		derValue(t, oidEnvelopedData),
		derTLV(t, asn1.ClassContextSpecific, 0, true, enveloped),
	)
}

// ber uses indefinite lengths and a fragmented encrypted content, the
// streaming CMS form this package accepts from KMS.
func (f recipientFixture) ber(t *testing.T) []byte {
	half := len(f.ciphertext) / 2
	return berIndefinite(0x30,
		derValue(t, oidEnvelopedData),
		berIndefinite(0xa0, berIndefinite(0x30,
			derValue(t, envelopedDataVersion),
			berIndefinite(0x31, f.recipientInfo(t)),
			berIndefinite(0x30,
				derValue(t, oidData),
				f.contentAlgorithm(t),
				berIndefinite(0xa0, derValue(t, f.ciphertext[:half]), derValue(t, f.ciphertext[half:])),
			),
		)),
	)
}

func TestDecryptRecoversPlaintext(t *testing.T) {
	fixture := newRecipientFixture(t)
	for name, content := range map[string][]byte{"DER": fixture.der(t), "BER": fixture.ber(t)} {
		t.Run(name, func(t *testing.T) {
			plaintext, err := Decrypt(fixture.key, content)
			require.NoError(t, err)
			require.Equal(t, fixture.plaintext, plaintext)

			other, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)
			plaintext, err = Decrypt(other, content)
			require.Nil(t, plaintext)
			require.ErrorIs(t, err, ErrDecrypt)
		})
	}
}
