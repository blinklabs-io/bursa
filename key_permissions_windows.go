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
	"strings"

	"golang.org/x/sys/windows"
)

var insecureKeyFileSIDs = map[string]string{
	"WD":           "Everyone",
	"S-1-1-0":      "Everyone",
	"BU":           `BUILTIN\Users`,
	"S-1-5-32-545": `BUILTIN\Users`,
	"AU":           "Authenticated Users",
	"S-1-5-11":     "Authenticated Users",
	// Built-in Administrators is rejected as a trustee outright (both the SDDL
	// alias and its numeric SID) so an allow ACE granting every local
	// administrator is refused even when the file is owned by that group
	// (O:BA), where the owner allow-list would otherwise re-admit it.
	"BA":           `BUILTIN\Administrators`,
	"S-1-5-32-544": `BUILTIN\Administrators`,
}

func isAccessAllowedACEType(aceType string) bool {
	switch aceType {
	case "A", "OA", "XA", "ZA":
		return true
	default:
		return false
	}
}

func isKnownNonGrantACEType(aceType string) bool {
	switch aceType {
	case "D", "OD", "XD", "ZD",
		"AU", "AL", "OU", "OL", "XU", "XL", "ZU", "ZL",
		"ML", "RA", "SP", "TL", "FL":
		return true
	default:
		return false
	}
}

func ownerOnlySecurityDescriptor() (*windows.SECURITY_DESCRIPTOR, string, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return nil, "", fmt.Errorf("failed to open process token: %w", err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get current user SID: %w", err)
	}
	userSID := user.User.Sid.String()
	descriptor, err := windows.SecurityDescriptorFromString(
		fmt.Sprintf("O:%[1]sD:P(A;;GA;;;%[1]s)", userSID),
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create owner-only security descriptor: %w", err)
	}
	return descriptor, userSID, nil
}

func restrictSecretKeyFilePermissions(file *os.File) error {
	descriptor, _, err := ownerOnlySecurityDescriptor()
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("failed to get owner-only DACL: %w", err)
	}
	if err := windows.SetSecurityInfo(
		windows.Handle(file.Fd()),
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	); err != nil {
		return fmt.Errorf("failed to set owner-only DACL: %w", err)
	}
	return nil
}

func checkOpenFilePermissions(file *os.File) error {
	descriptor, err := windows.GetSecurityInfo(
		windows.Handle(file.Fd()),
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("failed to get security info for %q: %w", file.Name(), err)
	}
	return checkOpenSecurityDescriptor(file.Name(), descriptor)
}

func checkOpenSecurityDescriptor(path string, descriptor *windows.SECURITY_DESCRIPTOR) error {
	daclObject, _, err := descriptor.DACL()
	if err != nil || daclObject == nil {
		return fmt.Errorf(
			"secret key file %q has no restrictive DACL: %w",
			path, ErrInsecureFileMode,
		)
	}
	sddl := descriptor.String()
	if sddl == "" {
		return fmt.Errorf("failed to read security descriptor for %q", path)
	}

	daclStart := strings.Index(sddl, "D:")
	if daclStart < 0 {
		return fmt.Errorf(
			"secret key file %q has no DACL (unrestricted access): %w",
			path, ErrInsecureFileMode,
		)
	}
	dacl := sddl[daclStart+2:]
	owner := sddlSection(sddl, "O:")
	if owner == "" {
		return fmt.Errorf(
			"secret key file %q has no owner in its security descriptor: %w",
			path, ErrInsecureFileMode,
		)
	}
	// Built-in Administrators is rejected earlier via insecureKeyFileSIDs (so an
	// (A;;GA;;;BA) ACE fails even when the owner is BA); it is therefore absent
	// here. Only the file owner, the current user, the OS (Local System), and
	// the owner-equivalent aliases may hold an allow ACE.
	allowed := map[string]bool{
		owner: true,
		"SY":  true, // Local System
		"CO":  true, // Creator Owner
		"OW":  true, // Owner Rights
	}
	_, currentUser, err := ownerOnlySecurityDescriptor()
	if err != nil {
		return err
	}
	allowed[currentUser] = true
	if saclStart := strings.Index(dacl, "S:"); saclStart >= 0 {
		dacl = dacl[:saclStart]
	}
	for {
		start := strings.IndexByte(dacl, '(')
		if start < 0 {
			break
		}
		end := strings.IndexByte(dacl[start:], ')')
		if end < 0 {
			return fmt.Errorf(
				"secret key file %q has unterminated DACL ACE: %w",
				path, ErrInsecureFileMode,
			)
		}
		ace := dacl[start+1 : start+end]
		fields := strings.Split(ace, ";")
		dacl = dacl[start+end+1:]
		if len(fields) < 6 {
			return fmt.Errorf(
				"secret key file %q has malformed DACL ACE %q: %w",
				path, ace, ErrInsecureFileMode,
			)
		}
		if !isAccessAllowedACEType(fields[0]) {
			if isKnownNonGrantACEType(fields[0]) {
				continue
			}
			return fmt.Errorf(
				"secret key file %q has unsupported DACL ACE type %q: %w",
				path, fields[0], ErrInsecureFileMode,
			)
		}
		if name, ok := insecureKeyFileSIDs[fields[5]]; ok {
			return fmt.Errorf(
				"secret key file %q grants access to %s: %w",
				path, name, ErrInsecureFileMode,
			)
		}
		if !allowed[fields[5]] {
			return fmt.Errorf(
				"secret key file %q grants access to unexpected trustee %s: %w",
				path, fields[5], ErrInsecureFileMode,
			)
		}
	}
	return nil
}

func sddlSection(sddl, section string) string {
	start := strings.Index(sddl, section)
	if start < 0 {
		return ""
	}
	value := sddl[start+len(section):]
	end := len(value)
	for _, next := range []string{"O:", "G:", "D:", "S:"} {
		if idx := strings.Index(value, next); idx >= 0 && idx < end {
			end = idx
		}
	}
	return value[:end]
}
