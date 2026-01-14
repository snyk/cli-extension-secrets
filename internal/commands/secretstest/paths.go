package secretstest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/snyk/go-application-framework/pkg/utils/git"
)

func findCommonRoot(inputPaths []string) (rootFolderID, repoURL string, err error) {
	rootFolderID, err = getRootFolderID(inputPaths)
	if err != nil {
		return "", "", fmt.Errorf("failed to determine common root: %w", err)
	}

	repoURL, err = git.RepoUrlFromDir(rootFolderID)
	if err != nil {
		return "", "", fmt.Errorf("could not get repository URL for %s: %w", rootFolderID, err)
	}

	if repoURL == "" {
		return "", "", fmt.Errorf("repository at %s has no remote URL configured", rootFolderID)
	}

	return rootFolderID, repoURL, nil
}

func getDir(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("failed to stat %s: %w", path, err)
	}

	if info.IsDir() {
		return path, nil
	}

	return filepath.Dir(path), nil
}

func getRootFolderID(inputPaths []string) (string, error) {
	if len(inputPaths) == 0 {
		return "", fmt.Errorf("no paths provided")
	}

	var rootFolderID string

	seenDirs := make(map[string]string)

	for _, path := range inputPaths {
		var gitRoot string

		parentDir, err := getDir(path)
		if err != nil {
			return "", fmt.Errorf("can't stat %s: %w", path, err)
		}

		resolved, ok := seenDirs[parentDir]

		if ok {
			gitRoot = resolved
		} else {
			gd, err := walkUpDirToGit(parentDir)
			if err != nil {
				return "", fmt.Errorf("could not find git root for %s: %w", path, err)
			}
			gitRoot = gd
			seenDirs[parentDir] = gd
		}

		// if rootDir is set, but we find a new git root, return error
		if rootFolderID != "" && rootFolderID != gitRoot {
			return "", fmt.Errorf("ambiguous root: paths belong to multiple repositories (%s and %s)", rootFolderID, gitRoot)
		}
		if rootFolderID == "" {
			rootFolderID = gitRoot
		}
	}

	return rootFolderID, nil
}

// that contains a .git folder and returns the parent of the .git folder.
func walkUpDirToGit(startPath string) (string, error) {
	absPath, err := filepath.Abs(startPath)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %w", err)
	}

	current := absPath

	for {
		target := filepath.Join(current, ".git")

		info, err := os.Stat(target)

		if err == nil {
			if info.IsDir() {
				return current, nil
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("error accessing %s: %w", target, err)
		}

		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}

	return "", fmt.Errorf("reached root without finding target")
}
