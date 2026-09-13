//go:build windows

package bursa

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openSecretKeyFile(path string) (*os.File, error) {
	handle, err := windows.CreateFile(
		windows.StringToUTF16Ptr(path),
		windows.GENERIC_READ|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	var tagInfo struct {
		FileAttributes uint32
		ReparseTag     uint32
	}
	if err := windows.GetFileInformationByHandleEx(
		handle,
		windows.FileAttributeTagInfo,
		(*byte)(unsafe.Pointer(&tagInfo)),
		uint32(unsafe.Sizeof(tagInfo)),
	); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	if tagInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("secret key file is a reparse point")
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("failed to open file handle")
	}
	return file, nil
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
