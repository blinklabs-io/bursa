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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

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
	path := filepath.Join(t.TempDir(), "secret.skey")
	require.NoError(t, os.WriteFile(path, []byte("test"), 0o600))
	setBursaDACL(t, path, "D:(A;;GR;;;WD)")

	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()
	err = checkOpenFilePermissions(file)
	assert.ErrorIs(t, err, ErrInsecureFileMode)
}

func TestLoadSecretKeyFromFileWindowsAllowsOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.skey")
	require.NoError(t, os.WriteFile(path, []byte("test"), 0o600))
	setBursaDACL(t, path, fmt.Sprintf("D:P(A;;GA;;;%s)", bursaCurrentUserSID(t)))

	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()
	assert.NoError(t, checkOpenFilePermissions(file))
}

func TestLoadSecretKeyFromFileWindowsRejectsNullDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.skey")
	require.NoError(t, os.WriteFile(path, []byte("test"), 0o600))
	require.NoError(t, windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil, nil, nil, nil,
	))

	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()
	assert.ErrorIs(t, checkOpenFilePermissions(file), ErrInsecureFileMode)
}
