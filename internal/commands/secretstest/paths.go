package secretstest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/utils/git"
)

var (
	Git                = ".git"
	repoURLFromDirFunc = git.RepoUrlFromDir
)

func findGitRoot(inputPath string) (repoURL, gitRootFolder string, err error) {
	gitRootFolder, err = getRootFolderID(inputPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to determine git root: %w", err)
	}

	repoURL, err = repoURLFromDirFunc(gitRootFolder)
	if err != nil {
		return "", "", fmt.Errorf("could not get repository URL for %s: %w", gitRootFolder, err)
	}

	if repoURL == "" {
		return "", "", fmt.Errorf("repository at %s has no remote URL configured", gitRootFolder)
	}

	return repoURL, gitRootFolder, nil
}

func computeRelativeInput(inputPath, gitRootFolder string) (relativeInputPath string, err error) {
	// file input paths need to be treated as a separate case
	// we want to compute the relativity of the file's directory to the gitRootFolder -> this will give the correct relativeInputPath
	ok, err := isFile(inputPath)
	if err != nil {
		return "", fmt.Errorf("could not determine if %s is a file: %w", inputPath, err)
	}
	if ok {
		inputPath = filepath.Dir(inputPath)
	}

	// input path is outside the gitRootFolder
	relativeInputPath, err = filepath.Rel(inputPath, gitRootFolder)
	if err != nil {
		return "", fmt.Errorf("could not determine relative root folder: %w", err)
	}
	if strings.HasPrefix(relativeInputPath, "..") {
		// input path is a child of the gitRootFolder
		relativeInputPath, err = filepath.Rel(gitRootFolder, inputPath)
		if err != nil {
			return "", fmt.Errorf("could not determine relative root folder: %w", err)
		}
	}

	return relativeInputPath, nil
}

func computeGitRootAndRepoURL(inputPath, remoteRepoURLFlag string) (repoURL, inputPathRelativeToGitRoot string, err error) {
	repoURL, gitRootDir, err := findGitRoot(inputPath)

	if err == nil {
		inputPathRelativeToGitRoot, err = computeRelativeInput(inputPath, gitRootDir)
		if err != nil {
			return "", "", cli_errors.NewGeneralSecretsFailureError("could not compute relative path from input to git root", snyk_errors.WithCause(err))
		}
	} else {
		// will be either the flag value or empty string if not set
		repoURL = remoteRepoURLFlag
		// in case of no .git, we assume the input path dir as root
		inputPathRelativeToGitRoot = "."
	}

	return repoURL, inputPathRelativeToGitRoot, nil
}

func isFile(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, fmt.Errorf("failed to stat %s: %w", path, err)
	}

	return !info.IsDir(), nil
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

func getRootFolderID(inputPath string) (string, error) {
	if inputPath == "" {
		return "", fmt.Errorf("no path provided")
	}

	parentDir, err := getDir(inputPath)
	if err != nil {
		return "", fmt.Errorf("can't stat %s: %w", inputPath, err)
	}

	gd, err := walkUpDirToGit(parentDir)
	if err != nil {
		return "", fmt.Errorf("could not find git root for %s: %w", inputPath, err)
	}

	return gd, nil
}

// that contains a .git folder and returns the parent of the .git folder.
func walkUpDirToGit(startPath string) (string, error) {
	absPath, err := filepath.Abs(startPath)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %w", err)
	}

	current := absPath

	for {
		target := filepath.Join(current, Git)

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
