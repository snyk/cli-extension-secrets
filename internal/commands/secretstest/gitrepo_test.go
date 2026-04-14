//nolint:gosec // testing credential stripping with mock secrets
package secretstest

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/snyk/go-application-framework/pkg/utils/git"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindGitRoot(t *testing.T) {
	oldRepoURLFromDir := repoURLFromDirFunc
	defer func() {
		repoURLFromDirFunc = oldRepoURLFromDir
	}()

	tempDir := t.TempDir()
	dir1 := filepath.Join(tempDir, "my-dir")
	err := os.MkdirAll(filepath.Join(dir1, Git), 0o750)
	assert.NoError(t, err)

	fileInRootPath := filepath.Join(dir1, "file.txt")
	fileInRoot, err := os.Create(filepath.Clean(fileInRootPath))
	assert.NoError(t, err)
	assert.NoError(t, fileInRoot.Close())

	err = os.MkdirAll(filepath.Join(dir1, "subdir"), 0o750)
	assert.NoError(t, err)
	fileInSubdirPath := filepath.Join(dir1, "subdir", "another-file.txt")
	fileInSubdir, err := os.Create(filepath.Clean(fileInSubdirPath))
	assert.NoError(t, err)
	assert.NoError(t, fileInSubdir.Close())

	dir2 := filepath.Join(tempDir, "my-second-dir")
	err = os.MkdirAll(dir2, 0o750)
	assert.NoError(t, err)
	fileInNonGitDirPath := filepath.Join(dir2, "some-file.txt")
	fileInNonGitDir, err := os.Create(filepath.Clean(fileInNonGitDirPath))
	assert.NoError(t, err)
	assert.NoError(t, fileInNonGitDir.Close())

	testCases := []struct {
		name              string
		inputPath         string
		expectErr         bool
		expectedErrString string
		mockRepoURLErr    error
		expectedRoot      string
	}{
		{
			name:         "input path is a file in the repo root",
			inputPath:    fileInRootPath,
			expectedRoot: dir1,
			expectErr:    false,
		},
		{
			name:         "input path is a file in the repo subdir",
			inputPath:    fileInSubdirPath,
			expectedRoot: dir1,
			expectErr:    false,
		},
		{
			name:              "input path is a file in a non-git dir",
			inputPath:         fileInNonGitDirPath,
			expectedRoot:      "",
			expectErr:         true,
			expectedErrString: "reached root without finding target",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			root, err := findGitRoot(tc.inputPath)
			if tc.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrString)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedRoot, root)
			}
		})
	}
}

func TestComputeRelativeInput(t *testing.T) {
	tempDir := t.TempDir()
	dir1 := filepath.Join(tempDir, "my-dir")
	err := os.MkdirAll(dir1, 0o750)
	assert.NoError(t, err)

	fileInRootPath := filepath.Join(dir1, "file.txt")
	fileInRoot, err := os.Create(filepath.Clean(fileInRootPath))
	assert.NoError(t, err)
	assert.NoError(t, fileInRoot.Close())

	err = os.MkdirAll(filepath.Join(dir1, "subdir"), 0o750)
	assert.NoError(t, err)
	fileInSubdirPath := filepath.Join(dir1, "subdir", "another-file.txt")
	fileInSubdir, err := os.Create(filepath.Clean(fileInSubdirPath))
	assert.NoError(t, err)
	assert.NoError(t, fileInSubdir.Close())

	dir2 := filepath.Join(tempDir, "my-second-dir")
	err = os.MkdirAll(dir2, 0o750)
	assert.NoError(t, err)
	fileInNonGitDirPath := filepath.Join(dir2, "some-file.txt")
	fileInNonGitDir, err := os.Create(filepath.Clean(fileInNonGitDirPath))
	assert.NoError(t, err)
	assert.NoError(t, fileInNonGitDir.Close())

	testCases := []struct {
		name              string
		inputPath         string
		dir               string
		expectedPath      string
		expectErr         bool
		expectedErrString string
	}{
		{
			name:         "input path is a file in the root",
			inputPath:    fileInRootPath,
			dir:          dir1,
			expectedPath: ".",
			expectErr:    false,
		},
		{
			name:         "input path is a file in a subdirectory",
			inputPath:    fileInSubdirPath,
			dir:          dir1,
			expectedPath: "subdir",
			expectErr:    false,
		},
		{
			name:         "input path is the root directory",
			inputPath:    dir1,
			dir:          dir1,
			expectedPath: ".",
			expectErr:    false,
		},
		{
			name:         "input path is a subdirectory",
			inputPath:    filepath.Join(dir1, "subdir"),
			dir:          dir1,
			expectedPath: "subdir",
			expectErr:    false,
		},
		{
			name:         "path is outside the directory",
			inputPath:    fileInNonGitDirPath,
			dir:          dir1,
			expectedPath: "../my-second-dir",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			relativeFolder, err := computeRelativeInput(tc.inputPath, dir1)
			if tc.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrString)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedPath, relativeFolder)
			}
		})
	}
}

func TestComputeRelativeInput_NormalizesToUnixPaths(t *testing.T) {
	tempDir := t.TempDir()
	root := filepath.Join(tempDir, "repo")
	sub := filepath.Join(root, "src", "deep", "dir")
	err := os.MkdirAll(sub, 0o750)
	require.NoError(t, err)

	result, err := computeRelativeInput(sub, root)
	require.NoError(t, err)
	assert.Equal(t, "src/deep/dir", result)
	assert.NotContains(t, result, `\`)
}

func TestFindBranchName(t *testing.T) {
	oldBranchNameFromDir := branchNameFromDirFunc
	defer func() {
		branchNameFromDirFunc = oldBranchNameFromDir
	}()

	testCases := []struct {
		name           string
		gitRootDir     string
		mockBranch     string
		mockErr        error
		expectedBranch string
		expectErr      bool
		expectedErrMsg string
	}{
		{
			name:           "returns branch from git root",
			gitRootDir:     "/some/repo",
			mockBranch:     "main",
			expectedBranch: "main",
		},
		{
			name:           "returns feature branch",
			gitRootDir:     "/some/repo",
			mockBranch:     "feat/PS-389/determine-branch",
			expectedBranch: "feat/PS-389/determine-branch",
		},
		{
			name:           "empty git root returns error",
			gitRootDir:     "",
			expectedBranch: "",
			expectErr:      true,
			expectedErrMsg: "git root directory not available",
		},
		{
			name:           "git error propagated",
			gitRootDir:     "/some/repo",
			mockErr:        errors.New("HEAD is detached"),
			expectedBranch: "",
			expectErr:      true,
			expectedErrMsg: "could not determine branch name",
		},
		{
			name:           "empty branch returned without error",
			gitRootDir:     "/some/repo",
			mockBranch:     "",
			expectedBranch: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			branchNameFromDirFunc = func(_ string) (string, error) {
				return tc.mockBranch, tc.mockErr
			}

			branch, err := findBranchName(tc.gitRootDir)
			if tc.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedBranch, branch)
			}
		})
	}
}

func TestFindCommitRef(t *testing.T) {
	oldCommitRefFromDir := commitRefFromDirFunc
	defer func() {
		commitRefFromDirFunc = oldCommitRefFromDir
	}()

	testCases := []struct {
		name              string
		gitRootDir        string
		mockCommitRef     string
		mockErr           error
		expectedCommitRef string
		expectErr         bool
		expectedErrMsg    string
	}{
		{
			name:              "returns commit ref from git root",
			gitRootDir:        "/some/repo",
			mockCommitRef:     "abc123def456",
			expectedCommitRef: "abc123def456",
		},
		{
			name:              "empty git root returns error",
			gitRootDir:        "",
			expectedCommitRef: "",
			expectErr:         true,
			expectedErrMsg:    "git root directory not available",
		},
		{
			name:              "git error propagated",
			gitRootDir:        "/some/repo",
			mockErr:           errors.New("reference not found"),
			expectedCommitRef: "",
			expectErr:         true,
			expectedErrMsg:    "could not determine commit ref",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			commitRefFromDirFunc = func(_ string) (string, error) {
				return tc.mockCommitRef, tc.mockErr
			}

			commitRef, err := findCommitRef(tc.gitRootDir)
			if tc.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedCommitRef, commitRef)
			}
		})
	}
}

func TestFindRepoURLWithOverride(t *testing.T) {
	oldRepoURLFromDir := repoURLFromDirFunc
	defer func() {
		repoURLFromDirFunc = oldRepoURLFromDir
	}()

	testCases := []struct {
		name              string
		gitRoot           string
		remoteRepoURLFlag string
		expectErr         bool
		expectedErrString string
		mockRepoURL       string
		mockRepoURLErr    error
		expectedRepoURL   string
	}{
		{
			name:              "no git root and no flag",
			gitRoot:           "",
			remoteRepoURLFlag: "",
			expectErr:         true,
			expectedErrString: "repository URL could not be determined",
		},
		{
			name:            "git root, no flag",
			gitRoot:         "proj/my-project-root",
			mockRepoURL:     "https://github.com/snyk/my-repo.git",
			expectedRepoURL: "https://github.com/snyk/my-repo.git",
			expectErr:       false,
		},
		{
			name:              "git root and flag - flag takes precedence",
			mockRepoURL:       "https://github.com/snyk/my-repo.git",
			remoteRepoURLFlag: "https://github.com/snyk/another-repo.git",
			expectedRepoURL:   "https://github.com/snyk/another-repo.git",
			expectErr:         false,
		},
		{
			name:              "no git root, remote repo flag set",
			gitRoot:           "",
			remoteRepoURLFlag: "https://github.com/snyk/another-repo.git",
			expectedRepoURL:   "https://github.com/snyk/another-repo.git",
			expectErr:         false,
		},
		{
			name:              "git root dir without repo url, no flag",
			gitRoot:           "/some/git_folder",
			mockRepoURL:       "",
			mockRepoURLErr:    errors.New("remote not found"),
			expectedRepoURL:   "",
			expectErr:         true,
			expectedErrString: "no remote repository URL configured ",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			repoURLFromDirFunc = func(_ string) (string, error) {
				return tc.mockRepoURL, tc.mockRepoURLErr
			}

			repoURL, err := findRepoURLWithOverride(tc.gitRoot, tc.remoteRepoURLFlag)
			if tc.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrString)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedRepoURL, repoURL)
			}
		})
	}
}

func TestNormalizeGitURL(t *testing.T) {
	tests := []struct {
		raw      string
		expected string
	}{
		// Standard parseable URLs — .git suffix is stripped for stable identity
		{
			raw:      "https://github.com/snyk/repo.git",
			expected: "https://github.com/snyk/repo",
		},
		{
			raw:      "https://github.com/org/repo.git",
			expected: "https://github.com/org/repo",
		},
		// URLs with credentials are stripped
		{
			raw:      "https://user:password@github.com/snyk/repo.git",
			expected: "https://github.com/snyk/repo",
		},
		{
			raw:      "https://user:token@github.com/org/repo.git",
			expected: "https://github.com/org/repo",
		},
		{
			raw:      "https://oauth2:glpat-123456@gitlab.com/group/repo.git",
			expected: "https://gitlab.com/group/repo",
		},
		// HTTP URLs are upgraded to HTTPS
		{
			raw:      "http://user:pass@gitea.local/snyk/repo.git",
			expected: "https://gitea.local/snyk/repo",
		},
		// SCP-like URLs
		{
			raw:      "git@github.com:org/repo.git",
			expected: "https://github.com/org/repo",
		},
		// Invalid URLs fall back to the original raw string
		{
			raw:      "://invalid-url",
			expected: "://invalid-url",
		},
	}

	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			sanitized := git.NormalizeGitURL(test.raw)
			require.Equal(t, test.expected, sanitized)
		})
	}
}
