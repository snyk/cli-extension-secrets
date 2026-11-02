package secretstest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const bytesPerKiB = 1024

// diagnoseDiskSpace decides whether a failed git step is a disk space problem.
//
// sizedRepo is the repository whose object store approximates the space the failed step needed:
// the source repository for the clone, the mirror itself for repack and bundle.
func diagnoseDiskSpace(ctx context.Context, err error, sizedRepo, workDir string) error {
	// Nothing to diagnose, a missing git cannot be a disk problem and a canceled context is not either.
	if err == nil || ctx.Err() != nil || errors.Is(err, ErrGitNotFound) {
		return err
	}

	need, sizeErr := estimateRepoSize(ctx, sizedRepo)
	if sizeErr != nil {
		return err
	}

	free, freeErr := availableBytes(workDir)
	if freeErr != nil {
		return err
	}

	if free >= need {
		return err
	}

	return fmt.Errorf("%w: about %d bytes needed but only %d available in %q: %w", ErrInsufficientDiskSpace, need, free, workDir, err)
}

// estimateRepoSize returns how many bytes the repository's objects take on disk: loose objects plus packs.
//
// It stands in for the free space a git step needs, because each step creates about one more copy of the
// history: the clone copies the source repository, repack writes a new pack with the mirror's objects and
// bundle writes a file of about the same size. That new copy is usually smaller than the original, since it
// is a single compressed pack, so the estimate is slightly generous.
func estimateRepoSize(ctx context.Context, repoDir string) (uint64, error) {
	out, err := captureGit(ctx, "-C", repoDir, "count-objects", "-v")
	if err != nil {
		return 0, err
	}

	return parseCountObjects(out)
}

func parseCountObjects(out string) (uint64, error) {
	var kib uint64
	var found bool

	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}

		key = strings.TrimSpace(key)
		if key != "size" && key != "size-pack" {
			continue
		}

		n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("unexpected count-objects value for %q: %w", key, err)
		}

		kib += n
		found = true
	}

	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("failed to read count-objects output: %w", err)
	}

	if !found {
		return 0, fmt.Errorf("no size information in count-objects output")
	}

	return kib * bytesPerKiB, nil
}
