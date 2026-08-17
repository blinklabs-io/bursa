//go:build windows

package bursa

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openSecretKeyFile(path string) (*os.File, error) {
	return os.Open(path)
}

func createSecretKeyFile(path string) (*os.File, error) {
	return createWindowsSecretKeyFile(path)
}

func createSecretKeyFileExclusive(path string) (*os.File, error) {
	return createWindowsSecretKeyFile(path)
}

func createWindowsSecretKeyFile(path string) (*os.File, error) {
	descriptor, _, err := ownerOnlySecurityDescriptor()
	if err != nil {
		return nil, err
	}
	securityAttributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	handle, err := windows.CreateFile(
		windows.StringToUTF16Ptr(path),
		windows.GENERIC_WRITE|windows.READ_CONTROL|windows.WRITE_DAC,
		0,
		securityAttributes,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("failed to create file handle")
	}
	return file, nil
}
