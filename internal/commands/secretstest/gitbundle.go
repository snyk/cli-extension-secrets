package secretstest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// Errors raised while packaging the git history.
var (
	// ErrGitNotFound means the git binary is not available on the PATH.
	ErrGitNotFound = errors.New("git executable not found")
	// ErrInsufficientDiskSpace means there is not enough disk space to clone the repository.
	ErrInsufficientDiskSpace = errors.New("not enough disk space")
)

const (
	gitBinaryName         = "git"
	historyTempDirPattern = "snyk-secrets-history-*"
	repoCloneDirName      = "repo.git"
	gitCloneCmd           = "clone"
	gitBundleCmd          = "bundle"
	bundleFileName        = "repo.bundle"
	allRefsFlag           = "--all"
	repackWindow          = "--window=250"
	repackDepth           = "--depth=50"
)

func createHistoryTempDir(config configuration.Configuration) (string, error) {
	cliTempDir := config.GetString(configuration.TEMP_DIR_PATH)

	dir, err := os.MkdirTemp(cliTempDir, historyTempDirPattern)
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir in %q: %w", cliTempDir, err)
	}

	return dir, nil
}

// gitSubcommand returns the git subcommand in args, skipping a leading "-C <dir>".
func gitSubcommand(args []string) string {
	if len(args) >= 3 && args[0] == "-C" {
		return args[2]
	}

	return args[0]
}

// captureGit runs git with the given arguments and returns its combined output.
// A missing git binary is reported as ErrGitNotFound. Failures are not classified any further here,
// see diagnoseDiskSpace.
func captureGit(ctx context.Context, args ...string) (string, error) {
	gitPath, err := exec.LookPath(gitBinaryName)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrGitNotFound, err)
	}

	cmd := exec.CommandContext(ctx, gitPath, args...) //nolint:gosec // args are not user-shell-interpreted
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s failed: %w: %s", gitSubcommand(args), err, out)
	}

	return string(out), nil
}

// runGit runs git with the given arguments, discarding its output.
func runGit(ctx context.Context, args ...string) error {
	_, err := captureGit(ctx, args...)

	return err
}

// cloneRepository makes a full bare mirror of repoSrc inside workDir, without touching the original repository.
// It returns the path of the mirror.
func cloneRepository(ctx context.Context, repoSrc, workDir string) (string, error) {
	repoCloneDir := filepath.Join(workDir, repoCloneDirName)

	if err := runGit(ctx, gitCloneCmd, "--mirror", "--no-local", "--", repoSrc, repoCloneDir); err != nil {
		return "", diagnoseDiskSpace(ctx, err, repoSrc, workDir)
	}

	return repoCloneDir, nil
}

// repackRepository repacks the repository's objects into a single, aggressively delta-compressed pack.
func repackRepository(ctx context.Context, repoDir string) error {
	err := runGit(ctx, "-C", repoDir, "repack", "-adf", repackWindow, repackDepth)

	return diagnoseDiskSpace(ctx, err, repoDir, filepath.Dir(repoDir))
}

// createBundle packages the whole history of the repository at repoDir into a single bundle file
// inside workDir. It returns the path of the bundle.
func createBundle(ctx context.Context, repoDir, workDir string) (string, error) {
	bundlePath := filepath.Join(workDir, bundleFileName)

	if err := runGit(ctx, "-C", repoDir, gitBundleCmd, "create", bundlePath, allRefsFlag); err != nil {
		return "", diagnoseDiskSpace(ctx, err, repoDir, workDir)
	}

	return bundlePath, nil
}

// createHistoryBundle packages the whole history of the repository at c.GitRootDir into a single bundle file
// inside workDir, and returns the path of the bundle.
//
// The intermediate clone is removed as soon as the bundle exists, so that only the bundle takes up disk space
// while it is uploaded and scanned. Errors are returned as they come, see ErrorFactory.NewGitHistoryError.
func (c *Command) createHistoryBundle(ctx context.Context, workDir string) (string, error) {
	// make the bare clone of the repository into the tmp dir
	clonedRepoDir, err := cloneRepository(ctx, c.GitRootDir, workDir)
	if err != nil {
		return "", err
	}
	c.Logger.Debug().Str("clonedRepoDir", clonedRepoDir).Msg("cloned repository")

	// compress the data by repacking
	if err := repackRepository(ctx, clonedRepoDir); err != nil {
		return "", err
	}
	c.Logger.Debug().Msg("repacked repository clone")

	// package the whole repo into a single file
	bundlePath, err := createBundle(ctx, clonedRepoDir, workDir)
	if err != nil {
		return "", err
	}

	// the clone, repacked or not, is not used any more. Failing to remove it is not fatal,
	// the deferred cleanup of workDir removes it at the latest.
	if rmErr := os.RemoveAll(clonedRepoDir); rmErr != nil {
		c.Logger.Warn().Err(rmErr).Str("clonedRepoDir", clonedRepoDir).Msg("could not remove cloned repository")
	}

	return bundlePath, nil
}
