// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package kmsrecipient

import (
	"crypto/rand"
	"crypto/rsa"
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
