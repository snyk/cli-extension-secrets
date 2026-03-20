package secretstest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"

	gogit "github.com/go-git/go-git/v5"
	"github.com/snyk/go-application-framework/pkg/utils/git"
)

var (
	Git                   = ".git"
	repoURLFromDirFunc    = git.RepoUrlFromDir
	branchNameFromDirFunc = git.BranchNameFromDir
	commitRefFromDirFunc  = commitRefFromDir
)

type gitRepoContext struct {
	gitRootDir                 string
	inputPathRelativeToGitRoot string
	repoURL                    string
	branch                     string
	commitRef                  string
}

func resolveGitContext(
	inputPath string,
	gitRootDir string,
	remoteRepoURLOverride string,
	logger *zerolog.Logger,
) gitRepoContext {
	var repoCtx gitRepoContext
	var err error

	repoCtx.gitRootDir = gitRootDir
	repoCtx.inputPathRelativeToGitRoot, err = computeRelativeInput(inputPath, gitRootDir)
	if err != nil {
		logger.Err(err).Str("inputPathRelativeToGitRoot", repoCtx.inputPathRelativeToGitRoot).Msg("could not determine common repo root")
	}

	repoCtx.repoURL, err = findRepoURLWithOverride(gitRootDir, remoteRepoURLOverride)
	if err != nil {
		logger.Err(err).Str("remoteRepoURLFlag", remoteRepoURLOverride).Str(InputPathKey, inputPath).Msg("could not compute gitRoot or repoURL")
	}

	repoCtx.branch, err = findBranchName(gitRootDir)
	if err != nil {
		logger.Warn().Err(err).Msg("could not determine git branch")
	}

	repoCtx.commitRef, err = findCommitRef(gitRootDir)
	if err != nil {
		logger.Warn().Err(err).Msg("could not determine git commit ref")
	}

	return repoCtx
}

func findGitRoot(inputPath string) (string, error) {
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

func findRepoURLWithOverride(gitRootFolder, remoteRepoURLFlag string) (repoURL string, err error) {
	if remoteRepoURLFlag != "" {
		return remoteRepoURLFlag, nil
	}

	if gitRootFolder == "" {
		return "", fmt.Errorf("repository URL could not be determined, git root not found and remote repo url flag not set")
	}

	repoURL, err = repoURLFromDirFunc(gitRootFolder)
	if err != nil {
		return "", fmt.Errorf("no remote repository URL configured for %s: %w", gitRootFolder, err)
	}

	if repoURL == "" {
		return "", fmt.Errorf("empty remote repository URL found at %s", gitRootFolder)
	}

	return repoURL, nil
}

func findBranchName(gitRootDir string) (string, error) {
	if gitRootDir == "" {
		return "", fmt.Errorf("git root directory not available")
	}

	branch, err := branchNameFromDirFunc(gitRootDir)
	if err != nil {
		return "", fmt.Errorf("could not determine branch name from %s: %w", gitRootDir, err)
	}

	return branch, nil
}

func commitRefFromDir(inputDir string) (string, error) {
	repo, err := gogit.PlainOpenWithOptions(inputDir, &gogit.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to open git repository at %s: %w", inputDir, err)
	}

	ref, err := repo.Head()
	if err != nil {
		return "", fmt.Errorf("failed to resolve HEAD: %w", err)
	}

	return ref.Hash().String(), nil
}

func findCommitRef(gitRootDir string) (string, error) {
	if gitRootDir == "" {
		return "", fmt.Errorf("git root directory not available")
	}

	commitRef, err := commitRefFromDirFunc(gitRootDir)
	if err != nil {
		return "", fmt.Errorf("could not determine commit ref from %s: %w", gitRootDir, err)
	}

	return commitRef, nil
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

	return filepath.ToSlash(relativeInputPath), nil
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
