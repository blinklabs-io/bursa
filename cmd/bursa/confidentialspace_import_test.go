// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/bip32"
	"github.com/blinklabs-io/bursa/internal/signer/confidentialspace"
)

func TestConfidentialSpaceImportFlags(t *testing.T) {
	t.Parallel()
	const secret = "projects/p/secrets/s"
	tests := []struct {
		name                 string
		importMode           bool
		authority, state     string
		profiles, createProf []string
		wantErr              string
	}{
		{name: "not import"},
		{name: "import", importMode: true, authority: "a", state: secret},
		{
			name:      "authority without import",
			state:     secret,
			wantErr:   "--import-authority-file requires --import",
			authority: "a",
		},
		{
			name: "import without state secret", importMode: true,
			authority: "a", wantErr: "--import requires --state-secret",
		},
		{
			name: "import without authority", importMode: true, state: secret,
			wantErr: "--import requires --import-authority-file",
		},
		{
			name: "import with profile", importMode: true, authority: "a",
			state: secret, profiles: []string{"p"},
			wantErr: "--import excludes --profile",
		},
		{
			name: "import with create-profile-counter", importMode: true,
			authority: "a", state: secret, createProf: []string{"p"},
			wantErr: "--import excludes --create-profile-counter",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateConfidentialSpaceImport(
				tt.importMode, tt.authority, tt.state, tt.profiles, tt.createProf,
			)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" &&
				(err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("error %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// TestConfidentialSpaceCommandChecksImportFlags runs the workload command: the
// import flags are validated before any file or service is touched.
func TestConfidentialSpaceCommandChecksImportFlags(t *testing.T) {
	t.Parallel()
	cmd := confidentialSpaceCommand()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"--audience", "a", "--kms-key", "k",
		"--wif-credentials", "/nonexistent/wif.json",
		"--tls-cert-file", "/nonexistent/cert.pem",
		"--tls-key-file", "/nonexistent/key.pem",
		"--client-ca-file", "/nonexistent/ca.pem",
		"--state-secret", "projects/p/secrets/s", "--import",
	})
	err := cmd.Execute()
	if err == nil ||
		!strings.Contains(err.Error(), "--import requires --import-authority-file") {
		t.Fatalf("error %v", err)
	}
}

func TestServeConfidentialSpaceImportNeedsAnAuthority(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	zero := filepath.Join(dir, "zero")
	if err := os.WriteFile(
		zero, []byte(strings.Repeat("00", ed25519.PublicKeySize)), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	short := filepath.Join(dir, "short")
	if err := os.WriteFile(short, []byte("abcd"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Every other input is valid, so only the authority can be refused.
	cfg := confidentialspace.ImportConfig{
		Audience: "a", KMSKey: "k", Tokens: staticTokens{},
		Wrapper: identityWrapper{}, Store: &memoryImportStore{},
	}
	for name, tc := range map[string]struct{ file, want string }{
		"missing":  {filepath.Join(dir, "none"), "no such file"},
		"short":    {short, "import authority public key"},
		"all zero": {zero, "provisioning authority"},
	} {
		err := serveConfidentialSpaceImport(
			t.Context(), "127.0.0.1:0", nil, tc.file, cfg,
		)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s authority: %v, want %q", name, err, tc.want)
		}
	}
}

func TestParseImportProfiles(t *testing.T) {
	t.Parallel()
	got, err := parseImportProfiles([]string{"pool@preview=8", "pool@mainnet=0"})
	want := []confidentialspace.ImportProfile{
		{Profile: "pool@preview", NextIssueNumber: 8},
		{Profile: "pool@mainnet", NextIssueNumber: 0},
	}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("got %+v, %v", got, err)
	}
	for _, bad := range []string{
		"", "pool", "=1", "pool=", "pool=-1", "pool=x", "pool=1.5",
		"a b=1", "pool=18446744073709551616",
	} {
		if _, err := parseImportProfiles([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := parseImportProfiles(
		[]string{"pool=1", "pool=2"},
	); err == nil {
		t.Error("duplicate profile accepted")
	}
}

type importFixture struct {
	dir        string
	seed       []byte
	vkey       ed25519.PublicKey
	signingKey string
	vkeyFile   string
}

func writeKeyFile(t *testing.T, path, typ string, material []byte) {
	t.Helper()
	data := fmt.Sprintf(
		`{"type":%q,"description":"","cborHex":"5820%x"}`, typ, material,
	)
	if err := bursa.WriteSecretKeyFile(path, []byte(data)); err != nil {
		t.Fatal(err)
	}
}

func newImportFixture(t *testing.T) importFixture {
	t.Helper()
	f := importFixture{dir: t.TempDir(), seed: make([]byte, ed25519.SeedSize)}
	if _, err := rand.Read(f.seed); err != nil {
		t.Fatal(err)
	}
	f.vkey = ed25519.NewKeyFromSeed(f.seed).Public().(ed25519.PublicKey)
	f.signingKey = filepath.Join(f.dir, "cold.skey")
	f.vkeyFile = filepath.Join(f.dir, "cold.vkey")
	writeKeyFile(t, f.signingKey, importSigningKeyType, f.seed)
	writeKeyFile(t, f.vkeyFile, importVKeyType, f.vkey)
	return f
}

func TestLoadImportColdKey(t *testing.T) {
	t.Parallel()
	f := newImportFixture(t)
	seed, vkey, err := loadImportColdKey(f.signingKey, f.vkeyFile)
	if err != nil || !bytes.Equal(seed, f.seed) || !bytes.Equal(vkey, f.vkey) {
		t.Fatalf("seed %x vkey %x err %v", seed, vkey, err)
	}

	other := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(other); err != nil {
		t.Fatal(err)
	}
	otherVKey := ed25519.NewKeyFromSeed(other).Public().(ed25519.PublicKey)
	for name, mutate := range map[string]func(g importFixture){
		"vkey of another key": func(g importFixture) {
			writeKeyFile(t, g.vkeyFile, importVKeyType, otherVKey)
		},
		// A valid extended key: its first 32 bytes are a scalar, not the
		// seed the workload signs with, so it must not be imported.
		"extended signing key": func(g importFixture) {
			xprv := bip32.XPrv(bytes.Repeat([]byte{3}, 96))
			kf, err := bursa.GetPoolColdExtendedSKey(xprv)
			if err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(kf)
			if err != nil {
				t.Fatal(err)
			}
			if err := bursa.WriteSecretKeyFile(g.signingKey, data); err != nil {
				t.Fatal(err)
			}
		},
		"payment signing key": func(g importFixture) {
			writeKeyFile(t, g.signingKey, "PaymentSigningKeyShelley_ed25519", g.seed)
		},
		"vkey file of another type": func(g importFixture) {
			writeKeyFile(t, g.vkeyFile, "PaymentVerificationKeyShelley_ed25519", g.vkey)
		},
	} {
		g := newImportFixture(t)
		mutate(g)
		if _, _, err := loadImportColdKey(g.signingKey, g.vkeyFile); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestReadImportAuthorityKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := bursa.WriteSecretKeyFile(p, []byte(content)); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for name, content := range map[string]string{
		"seed": hex.EncodeToString(seed) + "\n",
		"priv": hex.EncodeToString(priv),
	} {
		got, err := readImportAuthorityKey(write(name, content))
		if err != nil || !bytes.Equal(got, priv) {
			t.Errorf("%s: %x, %v", name, got, err)
		}
	}
	mismatched := bytes.Clone(priv)
	mismatched[40] ^= 1
	for name, content := range map[string]string{
		"not hex":    "zz",
		"short":      "abcd",
		"mismatched": hex.EncodeToString(mismatched),
	} {
		if _, err := readImportAuthorityKey(write("bad-"+strings.ReplaceAll(name, " ", "-"), content)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// memoryImportStore keeps what an import would write.
type memoryImportStore struct {
	mu        sync.Mutex
	envelope  []byte
	nextIssue map[string]uint64
}

func (s *memoryImportStore) Import(
	_ context.Context,
	envelope []byte,
	nextIssue map[string]uint64,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.envelope, s.nextIssue = bytes.Clone(envelope), nextIssue
	return nil
}

type identityWrapper struct{}

func (identityWrapper) Wrap(_ context.Context, p, _ []byte) ([]byte, error) {
	return bytes.Clone(p), nil
}

func (identityWrapper) Unwrap(_ context.Context, c, _ []byte) ([]byte, error) {
	return bytes.Clone(c), nil
}

type staticTokens struct{}

func (staticTokens) Token(context.Context, string, []string) ([]byte, error) {
	return []byte("token"), nil
}

// directTransport reaches an Importer without a network and counts the
// import requests it sends.
type directTransport struct {
	importer *confidentialspace.Importer
	imports  *int
}

func (d directTransport) Challenge(
	ctx context.Context,
) (confidentialspace.ImportChallenge, error) {
	return d.importer.Challenge(ctx)
}

func (d directTransport) Import(
	ctx context.Context,
	req confidentialspace.ImportRequest,
) error {
	*d.imports++
	return d.importer.Import(ctx, req)
}

type fakeVerifier struct{ err error }

func (v fakeVerifier) Verify(context.Context, []byte, []byte) error {
	return v.err
}

func TestRunConfidentialSpaceImportReachesTheWorkload(t *testing.T) {
	t.Parallel()
	f := newImportFixture(t)
	authorityPub, authority, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryImportStore{}
	importer, err := confidentialspace.NewImporter(confidentialspace.ImportConfig{
		Audience: "a", KMSKey: "k", Tokens: staticTokens{},
		Wrapper: identityWrapper{}, Store: store, Authority: authorityPub,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = importer.Close() })
	params := confidentialspace.ImportParams{
		KMSKey: "k", Seed: f.seed, VKey: f.vkey, Authority: authority,
		Profiles: []confidentialspace.ImportProfile{
			{Profile: "pool@preview", NextIssueNumber: 8},
		},
	}

	// A token the verifier refuses sends nothing.
	var imports int
	transport := directTransport{importer: importer, imports: &imports}
	refused := runConfidentialSpaceImport(
		t.Context(), transport,
		fakeVerifier{err: errors.New("bad token")}, params,
	)
	if refused == nil || !strings.Contains(refused.Error(), "bad token") {
		t.Fatalf("unverified workload: %v", refused)
	}
	if imports != 0 {
		t.Fatalf("%d import requests sent to an unverified workload", imports)
	}
	store.mu.Lock()
	wrote := store.envelope != nil
	store.mu.Unlock()
	if wrote {
		t.Fatal("a key was sent to an unverified workload")
	}

	if err := runConfidentialSpaceImport(
		t.Context(), transport, fakeVerifier{}, params,
	); err != nil {
		t.Fatal(err)
	}
	if imports != 1 {
		t.Fatalf("%d import requests sent, want 1", imports)
	}
	select {
	case <-importer.Done():
	default:
		t.Fatal("import did not finish")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !bytes.Contains(store.envelope, []byte(base64.StdEncoding.EncodeToString(f.vkey))) {
		t.Fatalf("envelope does not carry the imported public key: %s", store.envelope)
	}
	if len(store.nextIssue) != 1 || store.nextIssue["pool@preview"] != 8 {
		t.Fatalf("starting counters %v", store.nextIssue)
	}
}

func TestConfidentialSpaceImportCommandRequiresItsFlags(t *testing.T) {
	t.Parallel()
	cmd := confidentialSpaceClientCommand()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"import"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "required flag(s)") {
		t.Fatalf("error %v", err)
	}
	for _, name := range []string{"--address", "--signing-key-file", "--vkey-file", "--authority-key-file", "--profile"} {
		if !strings.Contains(err.Error(), name[2:]) {
			t.Errorf("%s is not required", name)
		}
	}
}

// The import's response closes done, which starts the shutdown; the response
// must still reach the client, over HTTP/2 as over HTTP/1.1.
func TestServeConfidentialSpaceAnswersTheRequestThatEndsIt(t *testing.T) {
	t.Parallel()
	fixture := httptest.NewUnstartedServer(http.NotFoundHandler())
	fixture.EnableHTTP2 = true
	fixture.StartTLS()
	cert := fixture.TLS.Certificates[0]
	client := fixture.Client()
	fixture.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	handler := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		close(done)
		// Shutdown closes the listener before it waits for this handler,
		// so a refused dial shows the shutdown has started.
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			conn, err := net.DialTimeout(
				"tcp", ln.Addr().String(), time.Second,
			)
			if err != nil {
				break
			}
			_ = conn.Close()
			time.Sleep(time.Millisecond)
		}
		_, _ = io.WriteString(rw, "imported")
	})
	errCh := make(chan error, 1)
	go func() {
		errCh <- serveConfidentialSpaceOn(
			t.Context(), ln, handler,
			&tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: []tls.Certificate{cert},
			},
			done,
		)
	}()
	resp, err := client.Post(
		"https://"+ln.Addr().String()+"/", "application/json", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "imported" ||
		resp.ProtoMajor != 2 {
		t.Fatalf("response %s %d %q", resp.Proto, resp.StatusCode, body)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("serve returned %v", err)
	}
}
