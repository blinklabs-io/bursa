//go:build wasip1

package bursa

import (
	"errors"
	"os"
)

var errWASIP1SecretFilePermissions = errors.New(
	"restrictive secret key file permissions are unsupported on wasip1",
)

func openSecretKeyFile(path string) (*os.File, error) {
	return os.Open(path)
}

func createSecretKeyFile(string) (*os.File, error) {
	return nil, errWASIP1SecretFilePermissions
}

func createSecretKeyFileExclusive(string) (*os.File, error) {
	return nil, errWASIP1SecretFilePermissions
}

func restrictSecretKeyFilePermissions(*os.File) error {
	return errWASIP1SecretFilePermissions
}
