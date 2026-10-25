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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

package bursa

import (
	"testing"

	"github.com/blinklabs-io/gouroboros/vrf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cardano-cli 11.0 envelope types and the VRF signing key layout (seed
// followed by public key) that it requires.
func TestVRFKeyFilesAreCardanoCLICompatible(t *testing.T) {
	t.Parallel()
	root, err := GetRootKeyFromMnemonic(capabilityMnemonic, "")
	require.NoError(t, err)
	seed, err := GetVRFSeed(root, 0)
	require.NoError(t, err)
	pub, sec, err := GetVRFKeyPair(seed)
	require.NoError(t, err)

	vkey, err := GetVRFVKey(pub)
	require.NoError(t, err)
	assert.Equal(t, "VrfVerificationKey_PraosVRF", vkey.Type)

	want := append(append([]byte(nil), seed...), pub...)
	for name, input := range map[string][]byte{
		"seed":            sec,
		"seed+public key": want,
	} {
		skey, err := GetVRFSKey(input)
		require.NoError(t, err, name)
		assert.Equal(t, "VrfSigningKey_PraosVRF", skey.Type, name)
		assert.Equal(t, want, decodeCborBytes(t, skey.CborHex), name)
		assert.Len(t, decodeCborBytes(t, skey.CborHex), vrf.SeedSize+vrf.PublicKeySize, name)

		loaded, err := LoadKeyFromBytes(authoritativeEnvelopeJSON(t, skey))
		require.NoError(t, err, name)
		assert.Equal(t, pub, loaded.VKey, name)
	}
}

func TestKESKeyFilesAreCardanoCLICompatible(t *testing.T) {
	t.Parallel()
	root, err := GetRootKeyFromMnemonic(capabilityMnemonic, "")
	require.NoError(t, err)
	seed, err := GetKESSeed(root, 0)
	require.NoError(t, err)
	sec, pub, err := GetKESKeyPair(seed)
	require.NoError(t, err)

	vkey, err := GetKESVKey(pub)
	require.NoError(t, err)
	assert.Equal(t, "KesVerificationKey_ed25519_kes_2^6", vkey.Type)
	skey, err := GetKESSKey(sec)
	require.NoError(t, err)
	assert.Equal(t, "KesSigningKey_ed25519_kes_2^6", skey.Type)

	for _, kf := range []KeyFile{vkey, skey} {
		loaded, err := LoadKeyFromBytes(authoritativeEnvelopeJSON(t, kf))
		require.NoError(t, err, kf.Type)
		assert.Equal(t, pub, loaded.VKey, kf.Type)
	}
}
