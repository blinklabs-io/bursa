//go:build !unix

package bursa

func syncSecretKeyDirectory(string) error {
	return nil
}
