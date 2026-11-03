package secretstest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// useFakeGit puts a `git` shell script on a PATH that contains nothing else.
func useFakeGit(t *testing.T, script string) {
	t.Helper()

	if runtime.GOOS == "windows" {
		t.Skip("fake git script is not supported on windows")
	}

	binDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(binDir, gitBinaryName), []byte("#!/bin/sh\n"+script+"\n"), 0o700)) //nolint:gosec // test executable
	t.Setenv("PATH", binDir)
}

// gitOutput runs git in dir and returns its trimmed output.
func gitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()

	cmd := exec.CommandContext(t.Context(), gitBinaryName, args...) //nolint:gosec // test helper
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)

	return strings.TrimSpace(string(out))
}

// newTestRepo creates a repository with the given number of commits.
func newTestRepo(t *testing.T, commits int) string {
	t.Helper()

	if _, err := exec.LookPath(gitBinaryName); err != nil {
		t.Skip("git is not installed")
	}

	dir := t.TempDir()
	gitOutput(t, dir, "init", "--quiet")
	for i := range commits {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "file.txt"), []byte(strings.Repeat("line\n", i+1)), 0o600))
		gitOutput(t, dir, "add", ".")
		gitOutput(t, dir,
			"-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false",
			"commit", "--quiet", "-m", "commit "+strconv.Itoa(i))
	}

	return dir
}

func TestCloneRepository_GitNotFound(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	_, err := cloneRepository(context.Background(), t.TempDir(), t.TempDir())

	require.ErrorIs(t, err, ErrGitNotFound)
}

func TestCloneRepository_GitFailure(t *testing.T) {
	useFakeGit(t, `echo "fatal: repository not found" >&2; exit 128`)

	_, err := cloneRepository(context.Background(), t.TempDir(), t.TempDir())

	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrGitNotFound)
	assert.Contains(t, err.Error(), "repository not found")
}

func TestRepackRepository(t *testing.T) {
	const commits = 3
	src := newTestRepo(t, commits)

	mirror, err := cloneRepository(context.Background(), src, t.TempDir())
	require.NoError(t, err)

	require.NoError(t, repackRepository(context.Background(), mirror))

	// all the history survives and is stored in a single pack without loose objects
	assert.Equal(t, strconv.Itoa(commits), gitOutput(t, mirror, "rev-list", "--all", "--count"))
	counts := gitOutput(t, mirror, "count-objects", "-v")
	assert.Contains(t, counts, "packs: 1")
	assert.Contains(t, counts, "count: 0")

	// the original repository is left untouched
	assert.Empty(t, gitOutput(t, src, "status", "--porcelain"))
}

func TestRepackRepository_NotARepository(t *testing.T) {
	if _, err := exec.LookPath(gitBinaryName); err != nil {
		t.Skip("git is not installed")
	}

	err := repackRepository(context.Background(), t.TempDir())

	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrGitNotFound)
}

func TestRepackRepository_GitNotFound(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	err := repackRepository(context.Background(), t.TempDir())

	require.ErrorIs(t, err, ErrGitNotFound)
}

func TestCreateBundle(t *testing.T) {
	const commits = 3
	src := newTestRepo(t, commits)
	gitOutput(t, src, "branch", "feature")
	gitOutput(t, src, "tag", "v1")

	workDir := t.TempDir()
	mirror, err := cloneRepository(context.Background(), src, workDir)
	require.NoError(t, err)
	require.NoError(t, repackRepository(context.Background(), mirror))

	bundlePath, err := createBundle(context.Background(), mirror, workDir)
	require.NoError(t, err)

	// the bundle is a single file next to the clone
	assert.Equal(t, filepath.Join(workDir, bundleFileName), bundlePath)
	info, err := os.Stat(bundlePath)
	require.NoError(t, err)
	assert.Positive(t, info.Size())

	// it is a valid bundle that carries all the refs
	gitOutput(t, mirror, gitBundleCmd, "verify", bundlePath)
	heads := gitOutput(t, workDir, gitBundleCmd, "list-heads", bundlePath)
	assert.Contains(t, heads, "refs/heads/feature")
	assert.Contains(t, heads, "refs/tags/v1")

	// and the full history can be restored from it
	restored := filepath.Join(t.TempDir(), "restored")
	gitOutput(t, workDir, gitCloneCmd, "--quiet", bundlePath, restored)
	assert.Equal(t, strconv.Itoa(commits), gitOutput(t, restored, "rev-list", "--all", "--count"))
}

func TestCreateBundle_EmptyRepository(t *testing.T) {
	src := newTestRepo(t, 0)

	workDir := t.TempDir()
	mirror, err := cloneRepository(context.Background(), src, workDir)
	require.NoError(t, err)

	_, err = createBundle(context.Background(), mirror, workDir)

	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrGitNotFound)
}

func TestCreateHistoryBundle(t *testing.T) {
	const commits = 3
	src := newTestRepo(t, commits)
	workDir := t.TempDir()
	nop := zerolog.Nop()
	c := &Command{Logger: &nop, GitRootDir: src}

	bundlePath, err := c.createHistoryBundle(context.Background(), workDir)
	require.NoError(t, err)

	// only the bundle is left behind, the clone is gone
	assert.Equal(t, filepath.Join(workDir, bundleFileName), bundlePath)
	assert.FileExists(t, bundlePath)
	assert.NoDirExists(t, filepath.Join(workDir, repoCloneDirName))
	entries, err := os.ReadDir(workDir)
	require.NoError(t, err)
	assert.Len(t, entries, 1)

	// and the bundle alone holds the whole history
	restored := filepath.Join(t.TempDir(), "restored")
	gitOutput(t, workDir, gitCloneCmd, "--quiet", bundlePath, restored)
	assert.Equal(t, strconv.Itoa(commits), gitOutput(t, restored, "rev-list", "--all", "--count"))
}

func TestCreateHistoryBundle_FailureKeepsErrorKind(t *testing.T) {
	nop := zerolog.Nop()
	c := &Command{Logger: &nop, GitRootDir: t.TempDir()}

	t.Run("git not found", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())

		_, err := c.createHistoryBundle(context.Background(), t.TempDir())

		require.ErrorIs(t, err, ErrGitNotFound)
	})

	t.Run("git command fails", func(t *testing.T) {
		useFakeGit(t, `echo "fatal: something went wrong" >&2; exit 128`)

		_, err := c.createHistoryBundle(context.Background(), t.TempDir())

		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrGitNotFound)
		assert.Contains(t, err.Error(), "something went wrong")
	})
}

func TestNewGitHistoryError(t *testing.T) {
	nop := zerolog.Nop()
	ef := NewErrorFactory(&nop)

	tests := []struct {
		name       string
		in         error
		wantCode   string
		wantDetail string
	}{
		{name: "git not found", in: ErrGitNotFound, wantCode: "SNYK-CLI-0010", wantDetail: GitNotFoundMsg},
		{name: "git command failure", in: errors.New("git clone failed: boom"), wantCode: "SNYK-SECRETS-0004", wantDetail: "git clone failed: boom"},
		{name: "wrapped git command failure", in: fmt.Errorf("packaging: %w", errors.New("boom")), wantCode: "SNYK-SECRETS-0004", wantDetail: "packaging: boom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ef.NewGitHistoryError(tt.in)

			var snykErr snyk_errors.Error
			require.ErrorAs(t, got, &snykErr)
			assert.Equal(t, tt.wantCode, snykErr.ErrorCode)
			if tt.wantDetail != "" {
				assert.Equal(t, tt.wantDetail, snykErr.Detail)
			}
			require.ErrorIs(t, got, tt.in)
		})
	}

	assert.NoError(t, ef.NewGitHistoryError(nil))
}
