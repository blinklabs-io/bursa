//go:build windows

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

package bursa

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

const testSecretKeyMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func writeBursaSecretKey(t *testing.T) string {
	t.Helper()
	wallet, err := NewWallet(testSecretKeyMnemonic)
	require.NoError(t, err)
	data, err := json.Marshal(wallet.PaymentSKey)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "secret.skey")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func bursaCurrentUserSID(t *testing.T) string {
	t.Helper()
	var token windows.Token
	require.NoError(t, windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token))
	defer token.Close()
	user, err := token.GetTokenUser()
	require.NoError(t, err)
	return user.User.Sid.String()
}

func setBursaDACL(t *testing.T, path, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	require.NoError(t, err)
	dacl, _, err := descriptor.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|
			windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	))
}

func TestLoadSecretKeyFromFileWindowsChecksOpenHandle(t *testing.T) {
	path := writeBursaSecretKey(t)
	setBursaDACL(t, path, "D:(A;;GR;;;WD)")

	_, err := LoadSecretKeyFromFile(path)
	assert.ErrorIs(t, err, ErrInsecureFileMode)
}

func TestLoadSecretKeyFromFileWindowsAllowsOwner(t *testing.T) {
	path := writeBursaSecretKey(t)
	setBursaDACL(t, path, fmt.Sprintf("D:P(A;;GA;;;%s)", bursaCurrentUserSID(t)))

	_, err := LoadSecretKeyFromFile(path)
	assert.NoError(t, err)
}

func TestWriteSecretKeyFileWindowsCreatesOwnerOnlyFile(t *testing.T) {
	path := writeBursaSecretKey(t)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	setBursaDACL(t, path, "D:(A;;GA;;;WD)")

	require.NoError(t, WriteSecretKeyFile(path, data))
	_, err = LoadSecretKeyFromFile(path)
	assert.NoError(t, err)
}

func TestCreateSecretKeyFileWindowsIsExclusiveAndUnshared(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.skey")
	file, err := CreateSecretKeyFile(path)
	require.NoError(t, err)
	defer file.Close()

	_, err = CreateSecretKeyFile(path)
	assert.Error(t, err)
	reader, err := os.Open(path)
	if reader != nil {
		_ = reader.Close()
	}
	assert.Error(t, err)
}

func TestLoadSecretKeyFromFileWindowsRejectsNullDACL(t *testing.T) {
	path := writeBursaSecretKey(t)
	require.NoError(t, windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil, nil, nil, nil,
	))

	_, err := LoadSecretKeyFromFile(path)
	assert.ErrorIs(t, err, ErrInsecureFileMode)
}

func TestAccessAllowedACEFormsWindows(t *testing.T) {
	for _, aceType := range []string{"A", "OA", "XA", "ZA"} {
		t.Run(aceType, func(t *testing.T) {
			sddl := fmt.Sprintf("O:SYD:(%s;;GR;;;WD)", aceType)
			sd, err := windows.SecurityDescriptorFromString(sddl)
			require.NoError(t, err)
			assert.ErrorIs(t, checkOpenSecurityDescriptor("test.skey", sd), ErrInsecureFileMode)
		})
	}
}

func TestKnownNonGrantACEFormsWindows(t *testing.T) {
	for _, aceType := range []string{"ZD", "XL", "ZU", "ZL"} {
		t.Run(aceType, func(t *testing.T) {
			assert.True(t, isKnownNonGrantACEType(aceType))
		})
	}
}

func TestWindowsAllowsCurrentUserWhenOwnerDiffers(t *testing.T) {
	sddl := fmt.Sprintf("O:SYD:P(A;;GA;;;%s)", bursaCurrentUserSID(t))
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	require.NoError(t, err)
	assert.NoError(t, checkOpenSecurityDescriptor("test.skey", descriptor))
}
