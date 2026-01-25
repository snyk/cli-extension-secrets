package secretstest

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFindGitRoot(t *testing.T) {
	oldRepoURLFromDir := repoURLFromDirFunc
	defer func() {
		repoURLFromDirFunc = oldRepoURLFromDir
	}()

	tempDir := t.TempDir()
	dir1 := filepath.Join(tempDir, "my-dir")
	err := os.MkdirAll(filepath.Join(dir1, Git), 0o755)
	assert.NoError(t, err)

	fileInRootPath := filepath.Join(dir1, "file.txt")
	fileInRoot, err := os.Create(fileInRootPath)
	assert.NoError(t, err)
	assert.NoError(t, fileInRoot.Close())

	err = os.MkdirAll(filepath.Join(dir1, "subdir"), 0o755)
	assert.NoError(t, err)
	fileInSubdirPath := filepath.Join(dir1, "subdir", "another-file.txt")
	fileInSubdir, err := os.Create(fileInSubdirPath)
	assert.NoError(t, err)
	assert.NoError(t, fileInSubdir.Close())

	dir2 := filepath.Join(tempDir, "my-second-dir")
	err = os.MkdirAll(dir2, 0o755)
	assert.NoError(t, err)
	fileInNonGitDirPath := filepath.Join(dir2, "some-file.txt")
	fileInNonGitDir, err := os.Create(fileInNonGitDirPath)
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
	err := os.MkdirAll(dir1, 0o755)
	assert.NoError(t, err)

	fileInRootPath := filepath.Join(dir1, "file.txt")
	fileInRoot, err := os.Create(fileInRootPath)
	assert.NoError(t, err)
	assert.NoError(t, fileInRoot.Close())

	err = os.MkdirAll(filepath.Join(dir1, "subdir"), 0o755)
	assert.NoError(t, err)
	fileInSubdirPath := filepath.Join(dir1, "subdir", "another-file.txt")
	fileInSubdir, err := os.Create(fileInSubdirPath)
	assert.NoError(t, err)
	assert.NoError(t, fileInSubdir.Close())

	dir2 := filepath.Join(tempDir, "my-second-dir")
	err = os.MkdirAll(dir2, 0o755)
	assert.NoError(t, err)
	fileInNonGitDirPath := filepath.Join(dir2, "some-file.txt")
	fileInNonGitDir, err := os.Create(fileInNonGitDirPath)
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
