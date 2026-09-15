//go:build !unix

package vault

import (
	"path/filepath"
	"testing"
)

// Windows has no directory-flush primitive. os.Open returns a GENERIC_READ
// handle and FlushFileBuffers needs GENERIC_WRITE, so calling Sync there
// failed on every vault save and writeFileAtomic returned a
// committedWriteError to the caller each time.
func TestSyncDirFSIsANoOp(t *testing.T) {
	if err := syncDirFS(t.TempDir()); err != nil {
		t.Fatalf("syncDirFS should not fail: %v", err)
	}
	if err := syncDirFS(filepath.Join(t.TempDir(), "absent")); err != nil {
		t.Fatalf("syncDirFS should not fail on a missing directory: %v", err)
	}
}

func TestWriteFileAtomicDoesNotReturnACommittedWriteError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	if err := writeFileAtomic(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
}
