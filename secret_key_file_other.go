//go:build !unix && !windows && !wasip1

package bursa

import "os"

func openSecretKeyFile(path string) (*os.File, error) {
	return os.Open(path)
}

func createSecretKeyFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

func createSecretKeyFileExclusive(path string) (*os.File, error) {
	return createSecretKeyFile(path)
}

func restrictSecretKeyFilePermissions(file *os.File) error {
	return file.Chmod(0o600)
}
