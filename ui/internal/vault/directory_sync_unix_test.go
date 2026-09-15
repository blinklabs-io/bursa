//go:build unix

package vault

import (
	"path/filepath"
	"testing"
)

func TestSyncDirFSSyncsAnExistingDirectory(t *testing.T) {
	if err := syncDirFS(t.TempDir()); err != nil {
		t.Fatalf("syncDirFS on an existing directory: %v", err)
	}
}

func TestSyncDirFSReportsAMissingDirectory(t *testing.T) {
	if err := syncDirFS(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("syncDirFS should report a directory that is not there")
	}
}
