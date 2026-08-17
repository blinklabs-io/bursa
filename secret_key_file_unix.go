//go:build unix

package bursa

import (
	"os"
	"syscall"
)

func openSecretKeyFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

func createSecretKeyFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
}

func restrictSecretKeyFilePermissions(file *os.File) error {
	return file.Chmod(0o600)
}
