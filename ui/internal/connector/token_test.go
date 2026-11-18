package connector

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestTokenStoreVerifiesExactSignedRequest(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.RawURLEncoding.EncodeToString(encoded)
	store := NewTokenStore(filepath.Join(t.TempDir(), "pairing.json"), nil)
	if _, err := store.Mint("ext", publicKey); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"method":"getBalance"}`)
	digest := sha256.Sum256(canonicalRequest("challenge", "POST", "/connector/request", body))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	if authority, ok := store.VerifySignature(
		"chrome-extension://ext", "challenge", "POST", "/connector/request", body, encodedSignature,
	); !ok || authority != store.Authority() {
		t.Fatal("exact signed request was not authorized")
	}
	if _, ok := store.VerifySignature(
		"chrome-extension://ext", "challenge", "POST", "/connector/request", []byte(`{"method":"signTx"}`), encodedSignature,
	); ok {
		t.Fatal("signature authorized a substituted request body")
	}
}

func TestTokenStoreMintVerify(t *testing.T) {
	seq := 0
	ts := NewTokenStore(
		t.TempDir()+"/token.json",
		func() (string, error) { seq++; return "tok", nil },
	)
	tok, err := ts.Mint("abc")
	if err != nil || tok != "tok" {
		t.Fatalf("mint: %q %v", tok, err)
	}
	if !ts.Verify("tok", "chrome-extension://abc") {
		t.Fatal("verify should pass for matching token+chrome-extension origin")
	}
	if ts.Verify("tok", "chrome-extension://evil") {
		t.Fatal("verify must fail for wrong extension id")
	}
	if ts.Verify("wrong", "chrome-extension://abc") {
		t.Fatal("verify must fail for wrong token")
	}
}

func TestTokenStoreMintVerifyFirefoxOrigin(t *testing.T) {
	t.Parallel()
	ts := NewTokenStore(
		t.TempDir()+"/token.json",
		func() (string, error) { return "tok", nil },
	)
	const origin = "moz-extension://5c0cbe2a-0e5f-4b0a-9a3c-1f2f6c0c1d11"
	if _, err := ts.Mint(origin); err != nil {
		t.Fatalf("Mint(%q) error = %v", origin, err)
	}
	if !ts.Verify("tok", origin) {
		t.Fatal("verify should pass for the paired moz-extension origin")
	}
	if ts.Verify("tok", "moz-extension://other") {
		t.Fatal("verify must fail for a different moz-extension origin")
	}
	if ts.Verify(
		"tok",
		"chrome-extension://5c0cbe2a-0e5f-4b0a-9a3c-1f2f6c0c1d11",
	) {
		t.Fatal(
			"verify must not treat a chrome-extension origin as the paired moz-extension origin",
		)
	}
}

func TestTokenStoreMintDoesNotChangeMemoryOnPersistFailure(t *testing.T) {
	blockedPath := t.TempDir()
	ts := NewTokenStore(
		blockedPath,
		func() (string, error) { return "tok", nil },
	)
	if _, err := ts.Mint("abc"); err == nil {
		t.Fatal("Mint to a directory path should fail")
	}
	if ts.Verify("tok", "chrome-extension://abc") {
		t.Fatal("failed Mint must not leave token in memory")
	}
}

func TestTokenStoreMintPublishesCommittedStateWhenDirectorySyncFails(
	t *testing.T,
) {
	path := filepath.Join(t.TempDir(), "token.json")
	tokens := []string{"old-token", "new-token"}
	ts := NewTokenStore(path, func() (string, error) {
		token := tokens[0]
		tokens = tokens[1:]
		return token, nil
	})
	if _, err := ts.Mint("old-extension"); err != nil {
		t.Fatalf("initial Mint: %v", err)
	}

	syncErr := errors.New("directory sync failed")
	originalSyncDirectory := syncDirectory
	syncDirectory = func(string) error { return syncErr }
	t.Cleanup(func() { syncDirectory = originalSyncDirectory })

	token, err := ts.Mint("new-extension")
	if !errors.Is(err, syncErr) {
		t.Fatalf("Mint error = %v, want directory sync failure", err)
	}
	if token != "" {
		t.Fatalf("Mint token = %q after error, want empty", token)
	}
	if ts.Verify("old-token", "old-extension") {
		t.Fatal("old token remained valid after committed replacement")
	}
	if !ts.Verify("new-token", "new-extension") {
		t.Fatal("committed replacement was not published")
	}
	reloaded := NewTokenStore(path, nil)
	if !reloaded.Verify("new-token", "new-extension") {
		t.Fatal("reloaded token store did not contain committed replacement")
	}
}

func TestTokenStoreMintPreservesStateOnPrecommitFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.json")
	tokens := []string{"old-token", "new-token"}
	ts := NewTokenStore(path, func() (string, error) {
		token := tokens[0]
		tokens = tokens[1:]
		return token, nil
	})
	if _, err := ts.Mint("old-extension"); err != nil {
		t.Fatalf("initial Mint: %v", err)
	}

	writeErr := errors.New("token replacement failed")
	originalReplaceAuthFile := replaceAuthFile
	replaceAuthFile = func(
		string,
		[]byte,
		func(string) error,
	) (bool, error) {
		return false, writeErr
	}
	t.Cleanup(func() { replaceAuthFile = originalReplaceAuthFile })

	if _, err := ts.Mint("new-extension"); !errors.Is(err, writeErr) {
		t.Fatalf("Mint error = %v, want replacement failure", err)
	}
	if !ts.Verify("old-token", "old-extension") {
		t.Fatal("old token was lost after pre-commit failure")
	}
	if ts.Verify("new-token", "new-extension") {
		t.Fatal("new token was published after pre-commit failure")
	}
	if reloaded := NewTokenStore(path, nil); !reloaded.Verify(
		"old-token",
		"old-extension",
	) {
		t.Fatal("persisted token changed after pre-commit failure")
	}
}

func TestTokenStoreRejectsInvalidExtensionIDs(t *testing.T) {
	calls := 0
	ts := NewTokenStore(t.TempDir()+"/token.json", func() (string, error) {
		calls++
		return "tok", nil
	})
	for _, extID := range []string{"", "https://example.com", "chrome-extension://", "moz-extension://", "moz-extension://has/slash"} {
		if _, err := ts.Mint(extID); !errors.Is(err, ErrInvalidExtensionID) {
			t.Fatalf(
				"Mint(%q) error = %v, want ErrInvalidExtensionID",
				extID,
				err,
			)
		}
		if ts.Verify("tok", extID) {
			t.Fatalf("Verify(%q) should fail for invalid extension id", extID)
		}
	}
	if calls != 0 {
		t.Fatalf("invalid Mint called random source %d times, want 0", calls)
	}
}

func TestTokenStoreClearRevokesMemoryOnRemoveFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.json")
	ts := NewTokenStore(path, func() (string, error) { return "tok", nil })
	if _, err := ts.Mint("abc"); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	blockedDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(blockedDir, "child"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ts.path = blockedDir
	if err := ts.Clear(); err == nil {
		t.Fatal("Clear on non-empty directory path should fail")
	}
	if ts.Verify("tok", "chrome-extension://abc") {
		t.Fatal("failed Clear must still revoke the in-memory token")
	}
	if _, _, paired := ts.Pair(); paired {
		t.Fatal("failed Clear must not leave a pairing reported")
	}
}

func TestTokenStoreClearReportsDirectorySyncFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.json")
	ts := NewTokenStore(path, func() (string, error) { return "tok", nil })
	if _, err := ts.Mint("abc"); err != nil {
		t.Fatalf("Mint: %v", err)
	}

	syncErr := errors.New("directory sync failed")
	originalSyncDirectory := syncDirectory
	syncDirectory = func(string) error { return syncErr }
	t.Cleanup(func() { syncDirectory = originalSyncDirectory })

	if err := ts.Clear(); !errors.Is(err, syncErr) {
		t.Fatalf("Clear error = %v, want directory sync failure", err)
	}
	if ts.Verify("tok", "abc") {
		t.Fatal("committed Clear left token valid in memory")
	}
	if _, _, paired := NewTokenStore(path, nil).Pair(); paired {
		t.Fatal("removed token remained paired after reload")
	}
}

func TestTokenStoreClearReportsTruncateSyncFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.json")
	ts := NewTokenStore(path, func() (string, error) { return "tok", nil })
	if _, err := ts.Mint("abc"); err != nil {
		t.Fatalf("Mint: %v", err)
	}

	removeErr := errors.New("remove failed")
	syncErr := errors.New("token sync failed")
	originalRemoveAuthFile := removeAuthFile
	originalSyncTokenFile := syncTokenFile
	removeAuthFile = func(
		string,
		func(string) error,
	) (bool, error) {
		return false, removeErr
	}
	syncTokenFile = func(*os.File) error { return syncErr }
	t.Cleanup(func() {
		removeAuthFile = originalRemoveAuthFile
		syncTokenFile = originalSyncTokenFile
	})

	if err := ts.Clear(); !errors.Is(err, removeErr) ||
		!errors.Is(err, syncErr) {
		t.Fatalf("Clear error = %v, want remove and token sync failures", err)
	}
	if ts.Verify("tok", "abc") {
		t.Fatal("failed Clear left token valid in memory")
	}
	if _, _, paired := NewTokenStore(path, nil).Pair(); paired {
		t.Fatal("truncated token remained paired after reload")
	}
}

// TestTokenStoreClearNeutralizesUnremovableFile covers a token file that cannot
// be unlinked but can still be written: the revocation must survive a restart.
func TestTokenStoreClearNeutralizesUnremovableFile(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip(
			"needs POSIX directory permissions enforced for the current user",
		)
	}
	dir := filepath.Join(t.TempDir(), "connector")
	path := filepath.Join(dir, "token.json")
	ts := NewTokenStore(path, func() (string, error) { return "tok", nil })
	if _, err := ts.Mint("abc"); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := ts.Clear(); err != nil {
		t.Fatalf("Clear with a writable but unremovable token file: %v", err)
	}
	if _, _, paired := NewTokenStore(path, nil).Pair(); paired {
		t.Fatal("token file still authorizes after Clear and a restart")
	}
}

func TestTokenStorePersistsAndClears(t *testing.T) {
	path := t.TempDir() + "/token.json"
	a := NewTokenStore(path, func() (string, error) { return "tok", nil })
	if _, err := a.Mint("ext1"); err != nil {
		t.Fatal(err)
	}
	b := NewTokenStore(path, func() (string, error) { return "tok", nil })
	if !b.Verify("tok", "ext1") {
		t.Fatal("token should survive reload")
	}
	if err := b.Clear(); err != nil {
		t.Fatal(err)
	}
	c := NewTokenStore(path, func() (string, error) { return "tok", nil })
	if c.Verify("tok", "ext1") {
		t.Fatal("cleared token must not verify")
	}
}

func TestTokenStoreLoadsOnlyValidPersistedPairings(t *testing.T) {
	dir := t.TempDir()

	validPath := filepath.Join(dir, "valid-token.json")
	if err := os.WriteFile(validPath, []byte(`{"extension_id":"abc","public_key":"key"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	valid := NewTokenStore(
		validPath,
		func() (string, error) { return "unused", nil },
	)
	extID, tok, ok := valid.Pair()
	if !ok || extID != "chrome-extension://abc" || tok != "key" {
		t.Fatalf(
			"Pair() = (%q, %q, %v), want normalized valid persisted pair",
			extID,
			tok,
			ok,
		)
	}

	legacyPath := filepath.Join(dir, "legacy-token.json")
	if err := os.WriteFile(legacyPath, []byte(`{"extension_id":"abc","token":"captured-bearer"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, paired := NewTokenStore(legacyPath, nil).Pair(); paired {
		t.Fatal("legacy bearer token must not authorize after upgrade")
	}

	invalidPath := filepath.Join(dir, "invalid-token.json")
	if err := os.WriteFile(invalidPath, []byte(`{"extension_id":"https://evil.example","token":"tok"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	invalid := NewTokenStore(
		invalidPath,
		func() (string, error) { return "unused", nil },
	)
	extID, tok, ok = invalid.Pair()
	if ok || extID != "" || tok != "" {
		t.Fatalf(
			"Pair() = (%q, %q, %v), want invalid persisted pair ignored",
			extID,
			tok,
			ok,
		)
	}
}

func TestTokenStoreClearWhenAbsent(t *testing.T) {
	ts := NewTokenStore(
		t.TempDir()+"/token.json",
		func() (string, error) { return "tok", nil },
	)
	if err := ts.Clear(); err != nil {
		t.Fatalf("Clear on never-minted store should return nil, got %v", err)
	}
}

func TestApprovedWorkCannotSurviveSameKeyRepairing(t *testing.T) {
	s := NewService(t.TempDir(), &fakeBackend{}, nil)
	identity := bindTestIdentity(s)
	key := testPairingPublicKey(t)
	code, err := s.BeginPair("ext")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := s.ConfirmPair("ext", code, key)
	if err != nil {
		t.Fatal(err)
	}
	const origin = "https://same-key.example"
	s.prompt = func() {
		pending := s.Pending()
		if len(pending) != 1 {
			t.Fatalf("pending requests = %d", len(pending))
		}
		if err := s.Decide(pending[0].ID, Decision{Approved: true}); err != nil {
			t.Fatal(err)
		}
		if err := s.Unpair(); err != nil {
			t.Fatal(err)
		}
		code, err := s.BeginPair("ext")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.ConfirmPair("ext", code, key); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.HandleAuthorized(t.Context(), "ext", authority, origin, "enable", nil); !errors.Is(err, ErrRefused) {
		t.Fatal("revoked approval executed after repairing the same key")
	}
	if s.grants.IsGranted(origin, identity) {
		t.Fatal("revoked approval created a grant")
	}
}

func TestSignedChallengeRequiresKeyAndCannotBeReissued(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.RawURLEncoding.EncodeToString(encoded)
	dir := t.TempDir()
	s := NewService(dir, &fakeBackend{}, nil)
	code, err := s.BeginPair("ext")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmPair("ext", code, publicKey); err != nil {
		t.Fatal(err)
	}
	sign := func(nonce, method, path string) string {
		digest := sha256.Sum256(canonicalRequest(nonce, method, path, nil))
		r, v, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		raw := make([]byte, 64)
		r.FillBytes(raw[:32])
		v.FillBytes(raw[32:])
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint64(raw[:8], uint64(time.Now().UnixMilli()))
	nonce := base64.RawURLEncoding.EncodeToString(raw)
	proof := sign(nonce, "POST", "/connector/challenge")
	for range maxRequestChallenges + 1 {
		if _, err := s.IssueSignedChallenge("ext", nonce, "invalid"); !errors.Is(err, ErrRefused) {
			t.Fatal("unauthenticated challenge accepted")
		}
	}
	challenge, err := s.IssueSignedChallenge("ext", nonce, proof)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate, err := s.IssueSignedChallenge("ext", nonce, proof); err != nil || duplicate != challenge {
		t.Fatal("duplicate issuance did not reuse its challenge")
	}
	signature := sign(challenge, "GET", "/connector/request")
	if _, ok := s.AuthorizeRequest("ext", challenge, "GET", "/connector/request", nil, signature); !ok {
		t.Fatal("valid signed request rejected")
	}
	if _, err := s.IssueSignedChallenge("ext", nonce, proof); !errors.Is(err, ErrRefused) {
		t.Fatal("redeemed challenge reissued")
	}
	if _, ok := s.AuthorizeRequest("ext", challenge, "GET", "/connector/request", nil, signature); ok {
		t.Fatal("redeemed request replayed")
	}
	restarted := NewService(dir, &fakeBackend{}, nil)
	next, err := restarted.IssueSignedChallenge("ext", nonce, proof)
	if err != nil {
		t.Fatal(err)
	}
	if next == challenge {
		t.Fatal("server restart reused the request challenge")
	}
	if _, ok := restarted.AuthorizeRequest("ext", challenge, "GET", "/connector/request", nil, signature); ok {
		t.Fatal("request replay survived server restart")
	}
	if _, ok := restarted.AuthorizeRequest("ext", next, "GET", "/connector/request", nil, sign(next, "GET", "/connector/request")); !ok {
		t.Fatal("new challenge rejected after restart")
	}
}

func TestDesktopPairingBindsComparedKey(t *testing.T) {
	s := NewService(t.TempDir(), &fakeBackend{}, nil)
	key := testPairingPublicKey(t)
	if err := s.BeginKeyPair("ext", key); err != nil {
		t.Fatal(err)
	}
	code := s.PendingPairings()[0].Code
	if err := s.BeginKeyPair("ext", testPairingPublicKey(t)); !errors.Is(err, ErrRefused) {
		t.Fatal("pending key replaced")
	}
	if err := s.ConfirmDesktopPair("ext", code+"0"); !errors.Is(err, ErrPairCodeMismatch) {
		t.Fatal("wrong compared code accepted")
	}
	if err := s.ConfirmDesktopPair("ext", code); err != nil {
		t.Fatal(err)
	}
	if !s.tokens.Verify(key, "ext") {
		t.Fatal("compared key was not bound")
	}
}
