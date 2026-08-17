//go:build !windows

package signer

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/config"
)

func TestBuildBackendsSoftwareRejectsPermissiveSecretKey(t *testing.T) {
	dir := t.TempDir()
	path := writeTestSkey(t, dir, "payment.skey", false, "")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := BuildBackends(context.Background(), []config.SignerBackendConfig{
		{Name: "sw", Type: "software", Path: dir},
	})
	if !errors.Is(err, bursa.ErrInsecureFileMode) {
		t.Fatalf("BuildBackends error = %v, want ErrInsecureFileMode", err)
	}
}
