package staging

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	gafutils "github.com/snyk/go-application-framework/pkg/utils"
)

func testLogger() *zerolog.Logger {
	logger := zerolog.Nop()
	return &logger
}

func configWithTempDir(t *testing.T, tempDir string) configuration.Configuration {
	t.Helper()

	config := configuration.NewWithOpts()
	config.Set(configuration.TEMP_DIR_PATH, tempDir)

	return config
}

func newTestRoot(t *testing.T) *Root {
	t.Helper()

	root, err := NewRoot(configWithTempDir(t, t.TempDir()), testLogger())
	require.NoError(t, err)

	return root
}

func Test_NewRunID_isUniquePerCall(t *testing.T) {
	seen := make(map[string]struct{}, 100)
	for range 100 {
		id := NewRunID()
		assert.Len(t, id, 12, "run ID length is budgeted for in the Windows path limit")
		_, duplicate := seen[id]
		require.False(t, duplicate, "run IDs must not collide: %s", id)
		seen[id] = struct{}{}
	}
}

func Test_NewRoot_createsRunScopedDirectory(t *testing.T) {
	tempDir := t.TempDir()

	root, err := NewRoot(configWithTempDir(t, tempDir), testLogger())

	require.NoError(t, err)
	assert.DirExists(t, root.Path())
	assert.Equal(t, filepath.Join(tempDir, stagingDirName), filepath.Dir(root.Path()))
}

func Test_NewRoot_isNotWorldReadable(t *testing.T) {
	if runtime.GOOS == windowsGOOS {
		t.Skip("POSIX mode bits are not meaningful on Windows")
	}

	root := newTestRoot(t)

	info, err := os.Stat(root.Path())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(stagedDirPerm), info.Mode().Perm(),
		"staged hunks may contain the secrets being scanned for")
}

func Test_NewRoot_concurrentInvocationsDoNotCollide(t *testing.T) {
	// Two invocations sharing a temp dir (same PID directory, e.g. after PID
	// reuse) must still get separate staging areas.
	config := configWithTempDir(t, t.TempDir())

	first, err := NewRoot(config, testLogger())
	require.NoError(t, err)
	second, err := NewRoot(config, testLogger())
	require.NoError(t, err)

	assert.NotEqual(t, first.Path(), second.Path())
}

func Test_NewRoot_failsWhenNoTempDirConfigured(t *testing.T) {
	_, err := NewRoot(configuration.NewWithOpts(), testLogger())

	require.ErrorIs(t, err, ErrUnavailable)
	assert.Contains(t, err.Error(), "SNYK_TMP_PATH", "the error must name the override")
}

func Test_NewRoot_failsWhenBaseIsNotWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}

	unwritable := filepath.Join(t.TempDir(), "locked")
	require.NoError(t, os.Mkdir(unwritable, 0o500))

	_, err := NewRoot(configWithTempDir(t, unwritable), testLogger())

	require.ErrorIs(t, err, ErrUnavailable)
	assert.Contains(t, err.Error(), "SNYK_TMP_PATH")
}

func Test_NewRoot_normalizesMixedSeparators(t *testing.T) {
	tempDir := t.TempDir()

	// TEMP_DIR_PATH is built with path.Join upstream, so it can arrive with
	// trailing or duplicated separators.
	config := configWithTempDir(t, tempDir+string(filepath.Separator)+string(filepath.Separator))

	root, err := NewRoot(config, testLogger())

	require.NoError(t, err)
	assert.Equal(t, filepath.Clean(root.Path()), root.Path())
}

func Test_NewRoot_rejectsPathThatBreachesTheLimit(t *testing.T) {
	original := maxPathLength
	t.Cleanup(func() { maxPathLength = original })
	// Exercise the Windows budget regardless of the host platform.
	maxPathLength = func() int { return maxWindowsPathLength }

	deepBase := filepath.Join(t.TempDir(), strings.Repeat("d", 150))
	require.NoError(t, os.MkdirAll(deepBase, stagedDirPerm))

	_, err := NewRoot(configWithTempDir(t, deepBase), testLogger())

	require.ErrorIs(t, err, ErrPathTooLong)
	assert.Contains(t, err.Error(), "SNYK_TMP_PATH")
}

func Test_checkPathBudget_realisticWindowsBasePathFits(t *testing.T) {
	original := maxPathLength
	t.Cleanup(func() { maxPathLength = original })
	maxPathLength = func() int { return maxWindowsPathLength }

	// A realistic TEMP_DIR_PATH on Windows: <cache>/<version>/tmp/pid<PID>.
	// Checked as a string rather than a real directory, because a temp directory
	// created by the test framework carries a long prefix of its own that a real
	// Windows base path does not have. Separators are '\' in the literal and '/'
	// once joined on a Unix host; only the length matters here.
	base := `C:\Users\mara\AppData\Local\snyk\snyk-cli\1.1298.0\tmp\pid12345`
	root := filepath.Join(base, stagingDirName, NewRunID())

	require.NoError(t, checkPathBudget(root),
		"the layout must fit under MAX_PATH for a realistic base path")

	// Document the actual headroom: this is what absorbs a longer user name or a
	// redirected AppData location before the limit is hit.
	deepest := filepath.Join(root, "shard-9999", scanRootName, hunksDirName, strings.Repeat("a", maxHunkIDLength))
	assert.Less(t, len(deepest), maxWindowsPathLength)
	t.Logf("deepest staged path is %d characters, %d below MAX_PATH", len(deepest), maxWindowsPathLength-len(deepest))
}

func Test_NewShard_createsScanRootWithHunksDirectory(t *testing.T) {
	root := newTestRoot(t)

	shard, err := root.NewShard(0)

	require.NoError(t, err)
	assert.Equal(t, scanRootName, filepath.Base(shard.ScanRoot()))
	assert.Equal(t, "shard-0000", filepath.Base(filepath.Dir(shard.ScanRoot())))
	assert.DirExists(t, filepath.Join(shard.ScanRoot(), hunksDirName))
}

func Test_WriteHunk_streamsContentAndTracksUsage(t *testing.T) {
	root := newTestRoot(t)
	shard, err := root.NewShard(0)
	require.NoError(t, err)

	// Larger than the copy buffer, so the streaming path is actually exercised.
	content := strings.Repeat("secret-ish content\n", 8000)

	written, err := shard.WriteHunk("a1b2c3", strings.NewReader(content))

	require.NoError(t, err)
	assert.Equal(t, int64(len(content)), written)

	staged, err := os.ReadFile(filepath.Join(shard.ScanRoot(), hunksDirName, "a1b2c3"))
	require.NoError(t, err)
	assert.Equal(t, content, string(staged))

	hunks, bytes := shard.Stats()
	assert.Equal(t, 1, hunks)
	assert.Equal(t, int64(len(content)), bytes)
}

func Test_WriteHunk_rejectsTraversingHunkIDs(t *testing.T) {
	root := newTestRoot(t)
	shard, err := root.NewShard(0)
	require.NoError(t, err)

	for _, hunkID := range []string{
		"",
		".",
		"..",
		"../escaped",
		"nested/hunk",
		`nested\hunk`,
		strings.Repeat("a", maxHunkIDLength+1),
	} {
		t.Run("id="+hunkID, func(t *testing.T) {
			_, err := shard.WriteHunk(hunkID, strings.NewReader("content"))
			require.Error(t, err, "a hunk ID derived from repository content must not escape the staging directory")
		})
	}

	hunks, _ := shard.Stats()
	assert.Zero(t, hunks)
}

func Test_WriteHunk_removesPartialHunkOnReadFailure(t *testing.T) {
	root := newTestRoot(t)
	shard, err := root.NewShard(0)
	require.NoError(t, err)

	_, err = shard.WriteHunk("failing", &failingReader{})

	require.Error(t, err)
	assert.NoFileExists(t, filepath.Join(shard.ScanRoot(), hunksDirName, "failing"),
		"a partially written hunk would otherwise be uploaded as if complete")
	hunks, bytes := shard.Stats()
	assert.Zero(t, hunks)
	assert.Zero(t, bytes)
}

func Test_WriteHunk_failsWhenHunkCountLimitReached(t *testing.T) {
	root := newTestRoot(t)
	shard, err := root.NewShard(0)
	require.NoError(t, err)

	shard.hunkCount = MaxHunksPerShard

	_, err = shard.WriteHunk("overflowing", strings.NewReader("content"))

	require.ErrorIs(t, err, ErrShardFull)
}

func Test_Fits_respectsRevisionLimits(t *testing.T) {
	root := newTestRoot(t)
	shard, err := root.NewShard(0)
	require.NoError(t, err)

	assert.True(t, shard.Fits(1024))

	shard.byteCount = MaxShardBytes
	assert.False(t, shard.Fits(1), "a shard at the size limit cannot take another hunk")

	shard.byteCount = 0
	shard.hunkCount = MaxHunksPerShard
	assert.False(t, shard.Fits(1), "a shard at the count limit cannot take another hunk")
}

func Test_Complete_writesManifestLast(t *testing.T) {
	root := newTestRoot(t)
	shard, err := root.NewShard(0)
	require.NoError(t, err)

	_, err = shard.WriteHunk("a1b2c3", strings.NewReader("hunk content"))
	require.NoError(t, err)

	manifestPath := filepath.Join(shard.ScanRoot(), manifestFileName)
	assert.NoFileExists(t, manifestPath, "the manifest is the completion marker, so it cannot exist yet")

	require.NoError(t, shard.Complete(strings.NewReader(`{"a1b2c3":[{"commit":"5c01e4fa"}]}`)))

	assert.FileExists(t, manifestPath)
	assert.NoFileExists(t, manifestPath+".partial", "the temporary manifest must not be left behind")
}

func Test_Complete_rejectsOversizedManifest(t *testing.T) {
	root := newTestRoot(t)
	shard, err := root.NewShard(0)
	require.NoError(t, err)

	err = shard.Complete(strings.NewReader(strings.Repeat("x", MaxManifestBytes+1)))

	require.ErrorIs(t, err, ErrShardFull)
	assert.NoFileExists(t, filepath.Join(shard.ScanRoot(), manifestFileName),
		"an over-limit manifest must not be left in place, or the shard would look complete")
}

func Test_Discard_removesTheWholeShard(t *testing.T) {
	root := newTestRoot(t)
	shard, err := root.NewShard(0)
	require.NoError(t, err)
	_, err = shard.WriteHunk("a1b2c3", strings.NewReader("hunk content"))
	require.NoError(t, err)

	shardDir := filepath.Dir(shard.ScanRoot())
	shard.Discard()

	assert.NoDirExists(t, shardDir)
	assert.DirExists(t, root.Path(), "discarding one shard must not affect the staging root")
}

func Test_Cleanup_removesEverything(t *testing.T) {
	root := newTestRoot(t)
	shard, err := root.NewShard(0)
	require.NoError(t, err)
	_, err = shard.WriteHunk("a1b2c3", strings.NewReader("hunk content"))
	require.NoError(t, err)

	root.Cleanup()

	assert.NoDirExists(t, root.Path())
}

func Test_Cleanup_isSafeToCallTwice(t *testing.T) {
	root := newTestRoot(t)

	root.Cleanup()
	root.Cleanup()

	assert.NoDirExists(t, root.Path())
}

func Test_CleanupOnSignal_stopIsIdempotentAndLeavesStagingIntact(t *testing.T) {
	root := newTestRoot(t)

	stop := root.CleanupOnSignal()
	stop()

	assert.DirExists(t, root.Path(), "uninstalling the handler must not remove the staging area")
}

func Test_NewShard_reportsInsufficientDiskSpaceDistinctly(t *testing.T) {
	// The point of the per-shard preflight: a full volume must be reported as
	// such, not as a raw ENOSPC from inside a write.
	available, err := gafutils.AvailableDiskSpace(t.TempDir())
	require.NoError(t, err)

	if available > uint64(MaxShardBytes*diskAmplificationFactor) {
		t.Skip("volume has room for a shard, so the preflight cannot be triggered here")
	}

	root := newTestRoot(t)
	_, err = root.NewShard(0)

	var insufficient *gafutils.ErrInsufficientDiskSpace
	require.ErrorAs(t, err, &insufficient)
}

type failingReader struct{}

func (r *failingReader) Read([]byte) (int, error) {
	return 0, assert.AnError
}
