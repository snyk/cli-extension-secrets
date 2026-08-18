package staging

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// orphanedRunID is the run ID used for staging directories left behind by a
// previous run. Any fixed value works; it only has to differ from the run ID the
// test's own Root generates.
const orphanedRunID = "aabbccddeeff"

// orphanedStagingDir creates <parent>/secrets-history/<orphanedRunID> with
// content and the given age, simulating a run killed before it could clean up.
func orphanedStagingDir(t *testing.T, parent string, age time.Duration) string {
	t.Helper()

	dir := filepath.Join(parent, stagingDirName, orphanedRunID)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "shard-0000", scanRootName, hunksDirName), stagedDirPerm))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "shard-0000", scanRootName, hunksDirName, "a1b2c3"), []byte("hunk"), stagedFilePerm))

	modTime := time.Now().Add(-age)
	require.NoError(t, os.Chtimes(dir, modTime, modTime))

	return dir
}

// unrelatedFile creates a file directly in a per-process directory, standing in
// for the certificate and error files the CLI keeps there.
func unrelatedFile(t *testing.T, parent, name string, age time.Duration) string {
	t.Helper()

	require.NoError(t, os.MkdirAll(parent, stagedDirPerm))
	path := filepath.Join(parent, name)
	require.NoError(t, os.WriteFile(path, []byte("not ours"), stagedFilePerm))

	modTime := time.Now().Add(-age)
	require.NoError(t, os.Chtimes(path, modTime, modTime))

	return path
}

// pidTempDir builds a framework-shaped temporary directory: <cache>/tmp/pid<N>.
func pidTempDir(t *testing.T, cache string, pid int) string {
	t.Helper()

	dir := filepath.Join(cache, "tmp", fmt.Sprintf("pid%d", pid))
	require.NoError(t, os.MkdirAll(dir, stagedDirPerm))

	return dir
}

// deadPid returns a PID that is not currently in use.
func deadPid(t *testing.T) int {
	t.Helper()

	for pid := 1 << 21; pid < (1<<21)+512; pid++ {
		if !processIsRunning(pid) {
			return pid
		}
	}

	t.Fatal("could not find an unused pid")
	return 0
}

func Test_SweepStale_removesOrphanedStagingDirFromDeadProcess(t *testing.T) {
	cache := t.TempDir()
	ownTempDir := pidTempDir(t, cache, os.Getpid())
	deadTempDir := pidTempDir(t, cache, deadPid(t))

	orphan := orphanedStagingDir(t, deadTempDir, 48*time.Hour)

	root, err := NewRoot(configWithTempDir(t, ownTempDir), testLogger())
	require.NoError(t, err)

	removed, err := root.SweepStale(DefaultStaleAge)

	require.NoError(t, err)
	assert.Equal(t, []string{orphan}, removed)
	assert.NoDirExists(t, orphan)
}

func Test_SweepStale_leavesUnrelatedFilesAlone(t *testing.T) {
	cache := t.TempDir()
	ownTempDir := pidTempDir(t, cache, os.Getpid())
	deadTempDir := pidTempDir(t, cache, deadPid(t))

	// The reason the sweep is scoped: these belong to the CLI, and what they
	// mean is not ours to assume.
	certFile := unrelatedFile(t, deadTempDir, "snyk-embedded-proxy-cert.pem", 48*time.Hour)
	errFile := unrelatedFile(t, deadTempDir, "err-file-8fbd0a12", 48*time.Hour)
	orphan := orphanedStagingDir(t, deadTempDir, 48*time.Hour)

	root, err := NewRoot(configWithTempDir(t, ownTempDir), testLogger())
	require.NoError(t, err)

	removed, err := root.SweepStale(DefaultStaleAge)

	require.NoError(t, err)
	assert.Equal(t, []string{orphan}, removed)
	assert.FileExists(t, certFile, "the sweep must not touch files it did not create")
	assert.FileExists(t, errFile, "the sweep must not touch files it did not create")
	assert.DirExists(t, deadTempDir, "the per-process directory itself must survive")
}

func Test_SweepStale_neverRemovesTheCurrentRun(t *testing.T) {
	cache := t.TempDir()
	ownTempDir := pidTempDir(t, cache, os.Getpid())

	root, err := NewRoot(configWithTempDir(t, ownTempDir), testLogger())
	require.NoError(t, err)

	// Age the current run's directory past the cutoff: it must still survive,
	// since a history scan can outlive any cutoff we pick.
	modTime := time.Now().Add(-72 * time.Hour)
	require.NoError(t, os.Chtimes(root.Path(), modTime, modTime))

	removed, err := root.SweepStale(DefaultStaleAge)

	require.NoError(t, err)
	assert.Empty(t, removed)
	assert.DirExists(t, root.Path())
}

func Test_SweepStale_skipsDirectoriesOfLiveProcesses(t *testing.T) {
	cache := t.TempDir()
	ownTempDir := pidTempDir(t, cache, os.Getpid())
	// The parent process is alive and is not us, standing in for a concurrent
	// snyk invocation part-way through its own history scan.
	liveTempDir := pidTempDir(t, cache, os.Getppid())

	inUse := orphanedStagingDir(t, liveTempDir, 48*time.Hour)

	root, err := NewRoot(configWithTempDir(t, ownTempDir), testLogger())
	require.NoError(t, err)

	removed, err := root.SweepStale(DefaultStaleAge)

	require.NoError(t, err)
	assert.Empty(t, removed)
	assert.DirExists(t, inUse, "a live process may still be writing to its staging area")
}

func Test_SweepStale_keepsRecentOrphans(t *testing.T) {
	cache := t.TempDir()
	ownTempDir := pidTempDir(t, cache, os.Getpid())
	deadTempDir := pidTempDir(t, cache, deadPid(t))

	recent := orphanedStagingDir(t, deadTempDir, 1*time.Hour)

	root, err := NewRoot(configWithTempDir(t, ownTempDir), testLogger())
	require.NoError(t, err)

	removed, err := root.SweepStale(DefaultStaleAge)

	require.NoError(t, err)
	assert.Empty(t, removed)
	assert.DirExists(t, recent)
}

func Test_SweepStale_reclaimsOwnDirectoryAfterPidReuse(t *testing.T) {
	cache := t.TempDir()
	ownTempDir := pidTempDir(t, cache, os.Getpid())

	// A previous run crashed while holding this same PID, so its staging area is
	// under *our* per-process directory.
	previous := orphanedStagingDir(t, ownTempDir, 48*time.Hour)

	root, err := NewRoot(configWithTempDir(t, ownTempDir), testLogger())
	require.NoError(t, err)

	removed, err := root.SweepStale(DefaultStaleAge)

	require.NoError(t, err)
	assert.Equal(t, []string{previous}, removed)
	assert.DirExists(t, root.Path(), "the current run must survive its own sweep")
}

func Test_SweepStale_doesNotEnumerateSiblingsOfARedirectedTempDir(t *testing.T) {
	// With SNYK_TMP_PATH set, the base is an arbitrary directory whose siblings
	// are unrelated - possibly the user's home directory - and must never be
	// inspected or deleted.
	parent := t.TempDir()
	redirected := filepath.Join(parent, "my-snyk-tmp")
	require.NoError(t, os.MkdirAll(redirected, stagedDirPerm))

	sibling := filepath.Join(parent, "important-work")
	siblingOrphan := orphanedStagingDir(t, sibling, 48*time.Hour)

	root, err := NewRoot(configWithTempDir(t, redirected), testLogger())
	require.NoError(t, err)

	removed, err := root.SweepStale(DefaultStaleAge)

	require.NoError(t, err)
	assert.Empty(t, removed)
	assert.DirExists(t, siblingOrphan, "siblings of a redirected temp dir are out of scope")
}

func Test_SweepStale_sweepsWithinARedirectedTempDir(t *testing.T) {
	// Within the redirected directory itself, our own orphans are still fair game.
	redirected := t.TempDir()
	orphan := orphanedStagingDir(t, redirected, 48*time.Hour)

	root, err := NewRoot(configWithTempDir(t, redirected), testLogger())
	require.NoError(t, err)

	removed, err := root.SweepStale(DefaultStaleAge)

	require.NoError(t, err)
	assert.Equal(t, []string{orphan}, removed)
	assert.NoDirExists(t, orphan)
}

func Test_SweepStale_ignoresFilesNamedLikeRunDirectories(t *testing.T) {
	cache := t.TempDir()
	ownTempDir := pidTempDir(t, cache, os.Getpid())
	deadTempDir := pidTempDir(t, cache, deadPid(t))

	strayFile := unrelatedFile(t, filepath.Join(deadTempDir, stagingDirName), orphanedRunID, 48*time.Hour)

	root, err := NewRoot(configWithTempDir(t, ownTempDir), testLogger())
	require.NoError(t, err)

	removed, err := root.SweepStale(DefaultStaleAge)

	require.NoError(t, err)
	assert.Empty(t, removed)
	assert.FileExists(t, strayFile)
}

func Test_SweepStale_succeedsWhenNothingHasBeenStagedBefore(t *testing.T) {
	root := newTestRoot(t)

	removed, err := root.SweepStale(DefaultStaleAge)

	require.NoError(t, err)
	assert.Empty(t, removed)
}
