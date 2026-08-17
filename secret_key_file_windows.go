//go:build windows

package bursa

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func openSecretKeyFile(path string) (*os.File, error) {
	return os.Open(path)
}

func createSecretKeyFile(path string) (*os.File, error) {
	return createWindowsSecretKeyFile(path, windows.CREATE_ALWAYS)
}

func createSecretKeyFileExclusive(path string) (*os.File, error) {
	return createWindowsSecretKeyFile(path, windows.CREATE_NEW)
}

func createWindowsSecretKeyFile(path string, creationDisposition uint32) (*os.File, error) {
	handle, err := windows.CreateFile(
		windows.StringToUTF16Ptr(path),
		windows.GENERIC_WRITE|windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		creationDisposition,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("failed to create file handle")
	}
	if err := restrictSecretKeyFilePermissions(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}
