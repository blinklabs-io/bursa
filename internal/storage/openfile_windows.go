// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build windows

package storage

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/blinklabs-io/bursa"
	"golang.org/x/sys/windows"
)

const (
	walletShareMode = windows.FILE_SHARE_READ |
		windows.FILE_SHARE_WRITE |
		windows.FILE_SHARE_DELETE
	walletFileAddFile         = 0x00000002
	walletFileAddSubdirectory = 0x00000004
)

type walletFileAttributeTagInfo struct {
	FileAttributes uint32
	ReparseTag     uint32
}

type walletFileRenameInformation struct {
	ReplaceIfExists uint32
	RootDirectory   windows.Handle
	FileNameLength  uint32
	FileName        [1]uint16
}

type walletFileDispositionInformation struct {
	DeleteFile byte
}

type walletFileDispositionInformationEx struct {
	Flags uint32
}

type walletFileBasicInformation struct {
	CreationTime   int64
	LastAccessTime int64
	LastWriteTime  int64
	ChangedTime    int64
	FileAttributes uint32
	_              uint32
}

const inspectWalletPathsByName = false

func walletNTPath(path string) (string, error) {
	fullPath, err := windows.FullPath(path)
	if err != nil {
		return "", err
	}
	switch {
	case strings.HasPrefix(fullPath, `\\?\UNC\`):
		return `\??\UNC\` + strings.TrimPrefix(fullPath, `\\?\UNC\`), nil
	case strings.HasPrefix(fullPath, `\\?\`):
		return `\??\` + strings.TrimPrefix(fullPath, `\\?\`), nil
	case strings.HasPrefix(fullPath, `\\`):
		return `\??\UNC\` + strings.TrimPrefix(fullPath, `\\`), nil
	default:
		return `\??\` + fullPath, nil
	}
}

func walletNTError(err error) error {
	var status windows.NTStatus
	if !errors.As(err, &status) {
		return err
	}
	if errno, ok := walletNTErrnos[status]; ok {
		return errno
	}
	return status.Errno()
}

// walletNTErrnos maps the statuses callers test with errors.Is to the errno
// values the portable storage code expects.
var walletNTErrnos = map[windows.NTStatus]syscall.Errno{
	windows.STATUS_REPARSE_POINT_ENCOUNTERED: syscall.ELOOP,
	windows.STATUS_OBJECT_NAME_COLLISION:     syscall.EEXIST,
	windows.STATUS_NOT_A_DIRECTORY:           syscall.ENOTDIR,
	windows.STATUS_FILE_IS_A_DIRECTORY:       syscall.EISDIR,
}

func isNormalizedWalletVolumeRoot(path string) bool {
	fullPath, err := windows.FullPath(path)
	if err != nil || fullPath != path {
		return false
	}
	volume := filepath.VolumeName(fullPath)
	return volume != "" && fullPath == volume+string(os.PathSeparator)
}

func openWalletObject(
	root windows.Handle,
	name string,
	access uint32,
	disposition uint32,
	directory bool,
) (*os.File, error) {
	// OBJ_DONT_REPARSE applies to every component resolved by NtCreateFile,
	// while RootDirectory keeps relative opens bound to the retained parent.
	objectName := name
	var err error
	if root == 0 {
		objectName, err = walletNTPath(name)
		if err != nil {
			return nil, err
		}
	}
	var ntName *windows.NTUnicodeString
	if objectName == "" {
		ntName = &windows.NTUnicodeString{}
	} else {
		ntName, err = windows.NewNTUnicodeString(objectName)
		if err != nil {
			return nil, err
		}
	}
	attrs := &windows.OBJECT_ATTRIBUTES{
		RootDirectory: root,
		ObjectName:    ntName,
		Attributes: windows.OBJ_CASE_INSENSITIVE |
			windows.OBJ_DONT_REPARSE,
	}
	attrs.Length = uint32(unsafe.Sizeof(*attrs))
	options := uint32(
		windows.FILE_SYNCHRONOUS_IO_NONALERT |
			windows.FILE_OPEN_FOR_BACKUP_INTENT,
	)
	if directory {
		options |= windows.FILE_DIRECTORY_FILE
	} else {
		options |= windows.FILE_NON_DIRECTORY_FILE
	}
	var handle windows.Handle
	open := func() error {
		return windows.NtCreateFile(
			&handle,
			access|windows.SYNCHRONIZE|windows.READ_CONTROL,
			attrs,
			&windows.IO_STATUS_BLOCK{},
			nil,
			windows.FILE_ATTRIBUTE_NORMAL,
			walletShareMode,
			disposition,
			options,
			0,
			0,
		)
	}
	err = open()
	relativeFallback := root != 0 && name != ".." &&
		!strings.ContainsAny(name, `\/:`)
	volumeRootFallback := root == 0 && directory &&
		disposition == windows.FILE_OPEN &&
		isNormalizedWalletVolumeRoot(name)
	if errors.Is(err, windows.STATUS_INVALID_PARAMETER) &&
		(relativeFallback || volumeRootFallback) {
		// Windows releases without OBJ_DONT_REPARSE support can still reject a
		// single relative component or normalized volume root by opening the
		// object itself and checking the returned handle below.
		attrs.Attributes &^= windows.OBJ_DONT_REPARSE
		options |= windows.FILE_OPEN_REPARSE_POINT
		handle = 0
		err = open()
	}
	if err != nil {
		return nil, walletNTError(err)
	}
	tagInfo := walletFileAttributeTagInfo{}
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
		return nil, fmt.Errorf("wallet path %q is a reparse point", name)
	}
	file := os.NewFile(uintptr(handle), name)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("failed to open wallet path handle")
	}
	return file, nil
}

func openWalletBase(baseDir string, create bool) (*os.File, error) {
	fullPath, err := windows.FullPath(baseDir)
	if err != nil {
		return nil, err
	}
	volume := filepath.VolumeName(fullPath)
	if volume == "" {
		return nil, fmt.Errorf("wallet storage path %q has no volume", baseDir)
	}
	relative := strings.TrimLeft(fullPath[len(volume):], `\/`)
	if relative == "" {
		return nil, errors.New("wallet storage directory cannot be a volume root")
	}
	current, err := openWalletObject(
		0,
		volume+string(os.PathSeparator),
		windows.FILE_GENERIC_READ,
		windows.FILE_OPEN,
		true,
	)
	if err != nil {
		return nil, err
	}
	parts := strings.FieldsFunc(relative, func(r rune) bool {
		return r == '\\' || r == '/'
	})
	// Walk one component per retained handle. Closing an ancestor after its
	// child is open cannot redirect later operations if the ancestor is renamed.
	for i, part := range parts {
		access := uint32(windows.FILE_GENERIC_READ)
		if create && i == len(parts)-1 {
			access |= walletFileAddSubdirectory | windows.WRITE_DAC
		}
		next, err := openWalletObject(
			windows.Handle(current.Fd()),
			part,
			access,
			windows.FILE_OPEN,
			true,
		)
		if create && errors.Is(err, fs.ErrNotExist) {
			parent, reopenErr := openWalletObject(
				windows.Handle(current.Fd()),
				"",
				windows.FILE_GENERIC_READ|walletFileAddSubdirectory,
				windows.FILE_OPEN,
				true,
			)
			if reopenErr != nil {
				_ = current.Close()
				return nil, reopenErr
			}
			_ = current.Close()
			current = parent
			next, err = openWalletObject(
				windows.Handle(parent.Fd()),
				part,
				access,
				windows.FILE_CREATE,
				true,
			)
		}
		_ = current.Close()
		if err != nil {
			return nil, err
		}
		current = next
	}
	if create {
		if err := secureWalletObject(current); err != nil {
			_ = current.Close()
			return nil, err
		}
	} else if err := bursa.CheckSecretFilePermissions(current); err != nil {
		_ = current.Close()
		return nil, err
	}
	return current, nil
}

func secureWalletObject(file *os.File) error {
	if err := bursa.RestrictSecretKeyFilePermissions(file); err != nil {
		return err
	}
	return bursa.CheckSecretFilePermissions(file)
}

func openWalletDirectory(base *os.File, name string, create, deleteAccess bool) (*os.File, error) {
	access := uint32(windows.FILE_GENERIC_READ)
	disposition := uint32(windows.FILE_OPEN)
	if create {
		access |= walletFileAddFile | windows.WRITE_DAC
		disposition = windows.FILE_OPEN_IF
	}
	if deleteAccess {
		access |= windows.DELETE | windows.FILE_WRITE_ATTRIBUTES
	}
	dir, err := openWalletObject(
		windows.Handle(base.Fd()),
		"wallet-"+name,
		access,
		disposition,
		true,
	)
	if err != nil {
		return nil, err
	}
	if create {
		err = secureWalletObject(dir)
	} else {
		err = bursa.CheckSecretFilePermissions(dir)
	}
	if err != nil {
		_ = dir.Close()
		return nil, err
	}
	return dir, nil
}

func openWalletDataFile(walletDir *os.File, access uint32) (*os.File, error) {
	file, err := openWalletObject(
		windows.Handle(walletDir.Fd()),
		"wallet.json",
		access,
		windows.FILE_OPEN,
		false,
	)
	if err != nil {
		return nil, err
	}
	if err := bursa.CheckSecretFilePermissions(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func openWalletFileForRead(baseDir, name string) (*os.File, error) {
	base, err := openWalletBase(baseDir, false)
	if err != nil {
		return nil, err
	}
	defer base.Close()
	walletDir, err := openWalletDirectory(base, name, false, false)
	if err != nil {
		return nil, err
	}
	defer walletDir.Close()
	return openWalletDataFile(walletDir, windows.FILE_GENERIC_READ)
}

func readWalletDirectory(baseDir string) ([]os.DirEntry, error) {
	base, err := openWalletBase(baseDir, false)
	if err != nil {
		return nil, err
	}
	defer base.Close()
	// Each listed wallet is opened through openWalletDirectory, which refuses
	// reparse points, so one unusable entry is skipped by ListWallets rather
	// than failing the whole listing here.
	return base.ReadDir(-1)
}

func createWalletTempFile(walletDir *os.File) (*os.File, error) {
	var suffix [8]byte
	for range 100 {
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, err
		}
		name := ".wallet.json.tmp-" + hex.EncodeToString(suffix[:])
		file, err := openWalletObject(
			windows.Handle(walletDir.Fd()),
			name,
			windows.FILE_GENERIC_WRITE|windows.WRITE_DAC|windows.DELETE,
			windows.FILE_CREATE,
			false,
		)
		if err == nil {
			if err := secureWalletObject(file); err != nil {
				_ = markWalletObjectForDeletion(file)
				_ = file.Close()
				return nil, err
			}
			return file, nil
		}
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return nil, err
	}
	return nil, errors.New("failed to create unique wallet temporary file")
}

func renameOpenWalletFile(file, walletDir *os.File, name string) error {
	nameUTF16, err := windows.UTF16FromString(name)
	if err != nil {
		return err
	}
	nameLength := (len(nameUTF16) - 1) * 2
	var layout walletFileRenameInformation
	bufferLength := int(unsafe.Offsetof(layout.FileName)) + nameLength
	if bufferLength > math.MaxUint32 {
		return fmt.Errorf("wallet file name %q is too long", name)
	}
	buffer := make([]byte, bufferLength)
	info := (*walletFileRenameInformation)(unsafe.Pointer(&buffer[0]))
	info.ReplaceIfExists = 1
	info.RootDirectory = windows.Handle(walletDir.Fd())
	info.FileNameLength = uint32(nameLength) // #nosec G115 -- nameLength < bufferLength
	destination := unsafe.Slice(&info.FileName[0], len(nameUTF16)-1)
	copy(destination, nameUTF16[:len(nameUTF16)-1])
	err = windows.NtSetInformationFile(
		windows.Handle(file.Fd()),
		&windows.IO_STATUS_BLOCK{},
		&buffer[0],
		uint32(bufferLength), // #nosec G115 -- bounded by math.MaxUint32 above
		windows.FileRenameInformation,
	)
	return walletNTError(err)
}

func writeWalletFile(baseDir, name string, data []byte) error {
	base, err := openWalletBase(baseDir, true)
	if err != nil {
		return err
	}
	defer base.Close()
	walletDir, err := openWalletDirectory(base, name, true, false)
	if err != nil {
		return err
	}
	defer walletDir.Close()
	file, err := createWalletTempFile(walletDir)
	if err != nil {
		return err
	}
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = markWalletObjectForDeletion(file)
		}
		_ = file.Close()
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	// Check before the rename: once it succeeds the handle names the committed
	// wallet.json and the previous file is gone, so a failure after that point
	// must not mark the handle for deletion.
	if err := bursa.CheckSecretFilePermissions(file); err != nil {
		return err
	}
	if err := renameOpenWalletFile(file, walletDir, "wallet.json"); err != nil {
		return err
	}
	removeTemp = false
	return nil
}

func markWalletObjectForDeletion(file *os.File) error {
	info := walletFileDispositionInformationEx{
		Flags: windows.FILE_DISPOSITION_DELETE |
			windows.FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK |
			windows.FILE_DISPOSITION_POSIX_SEMANTICS |
			windows.FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
	}
	err := windows.NtSetInformationFile(
		windows.Handle(file.Fd()),
		&windows.IO_STATUS_BLOCK{},
		(*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
		windows.FileDispositionInformationEx,
	)
	if err == nil {
		return nil
	}
	if !errors.Is(err, windows.STATUS_INVALID_INFO_CLASS) &&
		!errors.Is(err, windows.STATUS_INVALID_PARAMETER) &&
		!errors.Is(err, windows.STATUS_NOT_SUPPORTED) {
		return walletNTError(err)
	}
	var fileInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(
		windows.Handle(file.Fd()),
		&fileInfo,
	); err != nil {
		return err
	}
	if fileInfo.FileAttributes&windows.FILE_ATTRIBUTE_READONLY != 0 {
		basicInfo := walletFileBasicInformation{
			FileAttributes: fileInfo.FileAttributes &^ windows.FILE_ATTRIBUTE_READONLY,
		}
		if err := windows.SetFileInformationByHandle(
			windows.Handle(file.Fd()),
			windows.FileBasicInfo,
			(*byte)(unsafe.Pointer(&basicInfo)),
			uint32(unsafe.Sizeof(basicInfo)),
		); err != nil {
			return err
		}
	}
	legacy := walletFileDispositionInformation{DeleteFile: 1}
	err = windows.NtSetInformationFile(
		windows.Handle(file.Fd()),
		&windows.IO_STATUS_BLOCK{},
		(*byte)(unsafe.Pointer(&legacy)),
		uint32(unsafe.Sizeof(legacy)),
		windows.FileDispositionInformation,
	)
	return walletNTError(err)
}

func deleteWallet(baseDir, name string) error {
	base, err := openWalletBase(baseDir, false)
	if err != nil {
		return err
	}
	defer base.Close()
	walletDir, err := openWalletDirectory(base, name, false, true)
	if err != nil {
		return err
	}
	if err := deleteWalletContents(walletDir); err != nil {
		_ = walletDir.Close()
		return err
	}
	if err := markWalletObjectForDeletion(walletDir); err != nil {
		_ = walletDir.Close()
		return err
	}
	return walletDir.Close()
}

func deleteWalletContents(dir *os.File) error {
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		child, err := openWalletObject(
			windows.Handle(dir.Fd()),
			entry.Name(),
			windows.FILE_GENERIC_READ|windows.FILE_WRITE_ATTRIBUTES|windows.DELETE,
			windows.FILE_OPEN,
			entry.IsDir(),
		)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if err := bursa.CheckSecretFilePermissions(child); err != nil {
			_ = child.Close()
			return err
		}
		if entry.IsDir() {
			if err := deleteWalletContents(child); err != nil {
				_ = child.Close()
				return err
			}
		}
		if err := markWalletObjectForDeletion(child); err != nil {
			_ = child.Close()
			return err
		}
		if err := child.Close(); err != nil {
			return err
		}
	}
	return nil
}

// checkWalletFileMode is handled through the opened Windows file handle above.
func checkWalletFileMode(os.FileInfo) error { return nil }
