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

package bursa

import (
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	pushTestUser  = "blinklabs-io"
	pushTestToken = "ghp_not-a-real-token-0123456789"
)

// gitPushRun is the outcome of running openapi/git_push.sh against a real
// smart-HTTP git server.
type gitPushRun struct {
	err           error
	output        string // stdout and stderr, with git tracing enabled
	remoteURL     string // remote.origin.url as stored in the work tree
	gitConfig     string // the work tree's .git/config
	bareHead      string // the pushed master in the server repository, if any
	authenticated int32  // requests that carried the expected credentials
	challenged    int32  // requests that carried any credentials
	workDir       string // the directory the script ran in
}

// runGitPush runs the script against a local smart-HTTPS server that only
// accepts pushTestUser with serverToken, while the script is given
// pushTestToken. GIT_TRACE echoes every argument git is run with, so the
// captured output also covers process arguments.
func runGitPush(t *testing.T, serverToken string) gitPushRun {
	t.Helper()
	return runGitPushAs(t, pushTestUser, serverToken)
}

// runGitPushAs is runGitPush with the git_user_id argument set to userID.
func runGitPushAs(t *testing.T, userID, serverToken string) gitPushRun {
	t.Helper()

	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	execPath, err := exec.Command(gitPath, "--exec-path").Output()
	require.NoError(t, err)
	backend := filepath.Join(strings.TrimSpace(string(execPath)), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git-http-backend is not installed")
	}

	root := t.TempDir()
	bare := filepath.Join(root, "srv", pushTestUser, "bursa.git")
	require.NoError(t, os.MkdirAll(bare, 0o755))
	for _, args := range [][]string{
		{"init", "--bare", "--initial-branch=master", bare},
		{"-C", bare, "config", "http.receivepack", "true"},
	} {
		out, err := exec.Command(gitPath, args...).CombinedOutput()
		require.NoError(t, err, string(out))
	}

	var run gitPushRun
	cgiHandler := &cgi.Handler{
		Path: backend,
		Root: "/",
		Env: []string{
			"GIT_PROJECT_ROOT=" + filepath.Join(root, "srv"),
			"GIT_HTTP_EXPORT_ALL=1",
			"PATH=" + os.Getenv("PATH"),
		},
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if ok {
			atomic.AddInt32(&run.challenged, 1)
		}
		if !ok || user != pushTestUser || pass != serverToken {
			w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		atomic.AddInt32(&run.authenticated, 1)
		cgiHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	host := server.Listener.Addr().String()

	work := filepath.Join(root, "work")
	require.NoError(t, os.MkdirAll(work, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(work, "file.txt"), []byte("x"), 0o600))

	script, err := filepath.Abs(filepath.Join("openapi", "git_push.sh"))
	require.NoError(t, err)
	cmd := exec.Command("sh", script, userID, "bursa", "msg", host)
	cmd.Dir = work
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + root,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_TRACE=1",
		"GIT_TOKEN=" + pushTestToken,
		// The test server's certificate is self-signed; the commit needs an
		// identity.
		"GIT_SSL_NO_VERIFY=true",
		"GIT_CONFIG_COUNT=2",
		"GIT_CONFIG_KEY_0=user.name",
		"GIT_CONFIG_VALUE_0=test",
		"GIT_CONFIG_KEY_1=user.email",
		"GIT_CONFIG_VALUE_1=test@example.com",
	}
	out, err := cmd.CombinedOutput()
	run.workDir = work
	run.err = err
	run.output = string(out)

	// Read the stored value: `git remote get-url` would apply insteadOf.
	urlOut, urlErr := exec.Command(
		gitPath, "-C", work, "config", "--get", "remote.origin.url",
	).Output()
	require.NoError(t, urlErr)
	run.remoteURL = strings.TrimSpace(string(urlOut))
	cfg, err := os.ReadFile(filepath.Join(work, ".git", "config"))
	require.NoError(t, err)
	run.gitConfig = string(cfg)
	if head, err := exec.Command(
		gitPath, "-C", bare, "rev-parse", "--verify", "refs/heads/master",
	).Output(); err == nil {
		run.bareHead = strings.TrimSpace(string(head))
	}
	return run
}

func assertNoCredentialLeak(t *testing.T, run gitPushRun) {
	t.Helper()
	assert.NotContains(t, run.output, pushTestToken,
		"command output and traced process arguments must not carry the token")
	assert.NotContains(t, run.remoteURL, pushTestToken)
	assert.NotContains(t, run.gitConfig, pushTestToken,
		".git/config must not carry the token")
	assert.NotContains(t, run.remoteURL, "@",
		"the configured remote must not embed credentials")
}

func TestGitPushScriptKeepsTokenOutOfRemoteOnSuccess(t *testing.T) {
	t.Parallel()

	run := runGitPush(t, pushTestToken)

	require.NoError(t, run.err, run.output)
	assert.NotEmpty(t, run.bareHead, "the commit must reach the server")
	assert.Positive(t, atomic.LoadInt32(&run.authenticated),
		"git must authenticate with the token")
	assertNoCredentialLeak(t, run)
}

func TestGitPushScriptKeepsTokenOutOfRemoteOnFailure(t *testing.T) {
	t.Parallel()

	run := runGitPush(t, "a-different-token")

	require.Error(t, run.err, "a rejected push must fail the script")
	assert.Empty(t, run.bareHead, "nothing must reach the server")
	assert.Zero(t, atomic.LoadInt32(&run.authenticated),
		"the server must have rejected the credential")
	assertNoCredentialLeak(t, run)
}

func TestGitPushScriptDoesNotEvaluateUserID(t *testing.T) {
	t.Parallel()

	// The credential helper runs through a shell, so a user ID spliced into
	// its text would execute this command substitution.
	run := runGitPushAs(t, "u`>pwned`", pushTestToken)

	require.Error(t, run.err, "the server rejects this user")
	assert.Positive(t, run.challenged,
		"git must have asked the credential helper")
	assert.NoFileExists(t, filepath.Join(run.workDir, "pwned"),
		"git_user_id must not be evaluated by the credential helper")
}
