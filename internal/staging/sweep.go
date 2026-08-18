package staging

import (
	stderrors "errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

// DefaultStaleAge is how old an orphaned staging directory must be before a
// sweep will remove it.
//
// Deliberately generous. It is the backstop for runs that were killed, not a
// primary cleanup mechanism, and it must never remove the staging area of a
// history scan that is still running.
const DefaultStaleAge = 24 * time.Hour

// pidDirPattern matches the per-process directory names the framework creates
// under the version cache directory, e.g. "pid12345".
var pidDirPattern = regexp.MustCompile(`^pid(\d+)$`)

// SweepStale removes staging directories orphaned by earlier runs that were
// killed before any cleanup could run.
//
// Scope is deliberately narrow: only directories under a "secrets-history"
// folder are considered, and nothing else in the temporary directory is touched.
// The framework's temporary directory is shared with the consuming application -
// the CLI keeps certificate and error files there - and the meaning of those
// files is not ours to assume, so a general sweep of per-process directories
// would risk deleting data belonging to another component.
//
// Because the temporary directory is PID-scoped, a previous run's staging area
// lives under a *sibling* per-process directory, so sibling directories are
// searched too. Siblings are only enumerated when the base directory is itself a
// pid<N> directory: if the user has redirected the base with SNYK_TMP_PATH, its
// siblings are arbitrary directories that must not be inspected, let alone
// deleted.
//
// A per-process directory whose PID belongs to a live process is skipped
// entirely, so a concurrently running history scan is never disturbed regardless
// of maxAge. The sweep is best effort: individual failures are collected and
// returned but do not stop it, and callers should not treat the error as fatal.
// It returns the paths removed.
func (r *Root) SweepStale(maxAge time.Duration) ([]string, error) {
	cutoff := time.Now().Add(-maxAge)
	currentPid := os.Getpid()

	var removed []string
	var sweepErrors []error

	for _, parent := range r.sweepParents() {
		// Skip a whole per-process directory when its PID is held by another
		// live process: that process may be part-way through its own scan.
		if match := pidDirPattern.FindStringSubmatch(filepath.Base(parent)); match != nil {
			if pid, err := strconv.Atoi(match[1]); err == nil && pid != currentPid && processIsRunning(pid) {
				continue
			}
		}

		stagingDir := filepath.Join(parent, stagingDirName)

		entries, err := os.ReadDir(stagingDir)
		if err != nil {
			// No staging directory here, which is the common case.
			if !os.IsNotExist(err) {
				sweepErrors = append(sweepErrors, fmt.Errorf("could not read %s: %w", stagingDir, err))
			}
			continue
		}

		for _, entry := range entries {
			candidate := filepath.Join(stagingDir, entry.Name())

			if !entry.IsDir() || candidate == r.path {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				sweepErrors = append(sweepErrors, fmt.Errorf("could not stat %s: %w", candidate, err))
				continue
			}

			if info.ModTime().After(cutoff) {
				continue
			}

			if err := os.RemoveAll(candidate); err != nil {
				sweepErrors = append(sweepErrors, fmt.Errorf("could not remove %s: %w", candidate, err))
				continue
			}

			r.logger.Debug().Str(logFieldPath, candidate).Msg("removed orphaned staging directory")
			removed = append(removed, candidate)
		}
	}

	return removed, stderrors.Join(sweepErrors...)
}

// sweepParents returns the directories that may contain a staging folder: this
// run's base directory, plus its sibling per-process directories when the base
// is itself one.
func (r *Root) sweepParents() []string {
	base := filepath.Dir(r.path) // strip the "secrets-history" segment
	base = filepath.Dir(base)    // ...leaving the framework temporary directory

	parents := []string{base}

	if !pidDirPattern.MatchString(filepath.Base(base)) {
		return parents
	}

	siblings, err := os.ReadDir(filepath.Dir(base))
	if err != nil {
		return parents
	}

	for _, sibling := range siblings {
		if !sibling.IsDir() || !pidDirPattern.MatchString(sibling.Name()) {
			continue
		}

		path := filepath.Join(filepath.Dir(base), sibling.Name())
		if path != base {
			parents = append(parents, path)
		}
	}

	return parents
}
