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
		mockRepoURL       string
		mockRepoURLErr    error
		expectedRoot      string
		expectedRepoURL   string
	}{
		{
			name:            "input path is a file in the repo root",
			inputPath:       fileInRootPath,
			mockRepoURL:     "https://github.com/snyk/my-repo.git",
			expectedRoot:    dir1,
			expectedRepoURL: "https://github.com/snyk/my-repo.git",
			expectErr:       false,
		},
		{
			name:            "input path is a file in the repo subdir",
			inputPath:       fileInSubdirPath,
			mockRepoURL:     "https://github.com/snyk/my-repo.git",
			expectedRoot:    dir1,
			expectedRepoURL: "https://github.com/snyk/my-repo.git",
			expectErr:       false,
		},
		{
			name:              "input path is a file in a non-git dir",
			inputPath:         fileInNonGitDirPath,
			mockRepoURL:       "",
			mockRepoURLErr:    errors.New("not a git dir"),
			expectedRoot:      "",
			expectedRepoURL:   "",
			expectErr:         true,
			expectedErrString: "reached root without finding target",
		},
		{
			name:              "input path is a file in a git dir without repo url",
			inputPath:         fileInRootPath,
			mockRepoURL:       "",
			mockRepoURLErr:    nil,
			expectedRoot:      "",
			expectedRepoURL:   "",
			expectErr:         true,
			expectedErrString: "no remote URL configured",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			repoURLFromDirFunc = func(_ string) (string, error) {
				return tc.mockRepoURL, tc.mockRepoURLErr
			}

			url, root, err := findGitRoot(tc.inputPath)
			if tc.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrString)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedRepoURL, url)
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

func TestComputeGitRootAndRepoUrl(t *testing.T) {
	tempDir := t.TempDir()
	projRootDir := filepath.Join(tempDir, "project-root")
	err := os.MkdirAll(projRootDir, 0o755)
	assert.NoError(t, err)

	err = os.MkdirAll(filepath.Join(projRootDir, Git), 0o755)
	assert.NoError(t, err)

	fileInRootPath := filepath.Join(projRootDir, ".env")
	fileInRoot, err := os.Create(fileInRootPath)
	assert.NoError(t, err)
	assert.NoError(t, fileInRoot.Close())

	projSubDirPath := filepath.Join(projRootDir, "src")
	err = os.MkdirAll(projSubDirPath, 0o755)
	assert.NoError(t, err)

	fileInSubdirPath := filepath.Join(projRootDir, "src", "main.js")
	fileInSubdir, err := os.Create(fileInSubdirPath)
	assert.NoError(t, err)
	assert.NoError(t, fileInSubdir.Close())

	nonProjDir := filepath.Join(tempDir, "non-proj-dir")
	err = os.MkdirAll(nonProjDir, 0o755)
	assert.NoError(t, err)

	fileInNonGitDirPath := filepath.Join(nonProjDir, "non-proj-file.txt")
	fileInNonGitDir, err := os.Create(fileInNonGitDirPath)
	assert.NoError(t, err)
	assert.NoError(t, fileInNonGitDir.Close())

	mockGitRepoURL := "https://github.com/snyk/my-repo.git"
	flagRemoteRepoURL := "https://github.com/snyk/a-different-repo.git"

	testCases := []struct {
		name                               string
		inputPath                          string
		remoteRepoURLFlag                  string
		expectedRepoURL                    string
		expectedInputPathRelativeToGitRoot string
	}{
		{
			name:                               "local git root and no flag",
			inputPath:                          projRootDir,
			remoteRepoURLFlag:                  "",
			expectedRepoURL:                    mockGitRepoURL,
			expectedInputPathRelativeToGitRoot: ".",
		},
		{
			name:                               "nested file in local git and no flag",
			inputPath:                          fileInSubdirPath,
			remoteRepoURLFlag:                  "",
			expectedRepoURL:                    mockGitRepoURL,
			expectedInputPathRelativeToGitRoot: "src",
		},
		{
			name:                               "local git root and flag",
			inputPath:                          fileInSubdirPath,
			expectedRepoURL:                    mockGitRepoURL,
			expectedInputPathRelativeToGitRoot: "src",
		},
		{
			name:                               "no local git root and no flag",
			inputPath:                          fileInNonGitDirPath,
			expectedInputPathRelativeToGitRoot: ".",
			expectedRepoURL:                    "",
		},
		{
			name:                               "no local git and flag",
			inputPath:                          nonProjDir,
			remoteRepoURLFlag:                  flagRemoteRepoURL,
			expectedRepoURL:                    flagRemoteRepoURL,
			expectedInputPathRelativeToGitRoot: ".",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			repoURLFromDirFunc = func(_ string) (string, error) {
				return mockGitRepoURL, nil
			}

			repoURL, inputPathRelativeToGitRoot, err := computeGitRootAndRepoURL(tc.inputPath, tc.remoteRepoURLFlag)

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedRepoURL, repoURL)
			assert.Equal(t, tc.expectedInputPathRelativeToGitRoot, inputPathRelativeToGitRoot)
		})
	}
}
