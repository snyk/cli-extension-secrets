// Package staging manages the on-disk staging area used by history scans.
//
// A history scan cannot stream straight to the upload API: shard boundaries are
// only known once enumeration and deduplication have finished, a shard's
// manifest is only complete once every hunk in it is known, and retrying a
// single shard needs its content to still exist. So hunks are materialized into
// bounded shards on disk first, and each shard is uploaded as its own revision.
//
// The staging area lives under the framework-provided temporary directory
// (configuration.TEMP_DIR_PATH), which resolves per-OS and which the consuming
// application already removes on teardown. Layout:
//
//	<TEMP_DIR_PATH>/secrets-history/<runID>/
//	└── shard-0000/
//	    └── __history__/          <- the scan root that gets uploaded
//	        ├── hunks/<hunkID>
//	        └── manifest.json     <- written last; its presence means "complete"
//
// Deliberately not /tmp: that is correct for the detection service, which runs
// in a container, but Windows has no /tmp and a client machine's temporary
// location has to be discovered rather than assumed.
package staging

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/configuration"
	gafutils "github.com/snyk/go-application-framework/pkg/utils"
)

// Revision limits a single shard must satisfy to be uploadable.
const (
	MaxManifestBytes = 1 << 20         // 1 MB
	MaxShardBytes    = 100 * (1 << 20) // 100 MB
	MaxHunksPerShard = 100_000
)

// Path length limits.
const (
	// MaxUploadPathLength is the longest file path the upload API accepts,
	// measured relative to the scan root.
	MaxUploadPathLength = 256

	// maxWindowsPathLength is MAX_PATH. Long-path support has to be opted into
	// per-process and cannot be assumed on a customer machine, so staged paths
	// are kept under this limit instead.
	maxWindowsPathLength = 260

	// maxUnixPathLength is the conventional PATH_MAX. Far more headroom than the
	// staging layout needs, checked only so the failure mode is identical on
	// both platforms.
	maxUnixPathLength = 4096

	// maxHunkIDLength is the longest hunk file name to budget for: a hex-encoded
	// SHA-256 content hash, with no extension.
	maxHunkIDLength = 64
)

const (
	stagingDirName   = "secrets-history"
	scanRootName     = "__history__"
	hunksDirName     = "hunks"
	manifestFileName = "manifest.json"

	// partialSuffix marks a manifest that is still being written. Complete renames
	// it into place, so a file carrying this suffix means a shard was abandoned
	// mid-write.
	partialSuffix = ".partial"

	windowsGOOS = "windows"

	// logFieldPath is the structured-log key for a filesystem path.
	logFieldPath = "path"

	// shardDirPattern is padded to four digits: a full history scan of a large
	// repository produces hundreds of shards, and fixed-width names keep both
	// sorting and the path-length budget predictable.
	shardDirPattern = "shard-%04d"

	// stagedDirPerm is deliberately tighter than the 0755 the framework uses for
	// cache directories. Staged hunks are extracted from the customer's git
	// history and may contain the very secrets being looked for, so they should
	// not be world-readable while they exist.
	stagedDirPerm  = 0o700
	stagedFilePerm = 0o600

	// copyBufferSize matches the fixed buffer size the detection service uses per
	// worker. Hunks are streamed through a reused buffer rather than buffered
	// whole, so peak memory stays flat regardless of repository size.
	copyBufferSize = 64 * 1024

	// diskAmplificationFactor scales a shard's content size to its allocated
	// size before a free-space check. Hunks are very many tiny files, each
	// rounded up to a filesystem block, so a shard occupies materially more than
	// the sum of its content lengths - measured at roughly 2.2x on the benchmark
	// repository (1.3 GB of content, ~2.8 GB on disk).
	diskAmplificationFactor = 2.2
)

// Errors callers are expected to distinguish. Each has a different remedy, so
// none of them should reach the user as a generic scan failure.
var (
	// ErrUnavailable means no staging directory could be established at all.
	ErrUnavailable = errors.New("staging directory is unavailable")

	// ErrPathTooLong means the resolved staging path leaves no room for the
	// files that must live under it.
	ErrPathTooLong = errors.New("staging path is too long")

	// ErrShardFull means the shard has reached a revision limit and the caller
	// should open the next one.
	ErrShardFull = errors.New("shard is full")
)

// maxPathLength is a variable so tests can exercise the Windows budget on any
// platform.
var maxPathLength = func() int {
	if runtime.GOOS == windowsGOOS {
		return maxWindowsPathLength
	}
	return maxUnixPathLength
}

// NewRunID returns a short identifier that is unique per invocation.
//
// The framework's temporary directory is already PID-scoped, which is enough to
// keep concurrent invocations apart, but PIDs are recycled, so a stale directory
// can be adopted by an unrelated later process. A run ID makes that impossible.
// It is truncated to 12 hex characters rather than a full 36-character UUID
// purely to buy back path-length budget on Windows.
func NewRunID() string {
	id := uuid.New()
	return hex.EncodeToString(id[:6])
}

// Root is the staging area for a single history scan.
type Root struct {
	path   string
	logger *zerolog.Logger
}

// NewRoot establishes the staging area for one invocation.
//
// The base directory comes from configuration.TEMP_DIR_PATH, which the user can
// redirect with SNYK_TMP_PATH; that is the documented escape hatch for a base
// directory that is unwritable or on a full volume, and it is what the returned
// errors point at.
func NewRoot(config configuration.Configuration, logger *zerolog.Logger) (*Root, error) {
	base := strings.TrimSpace(config.GetString(configuration.TEMP_DIR_PATH))
	if base == "" {
		return nil, fmt.Errorf("%w: no temporary directory is configured, set SNYK_TMP_PATH to choose one", ErrUnavailable)
	}

	// TEMP_DIR_PATH can arrive with mixed separators, because the framework
	// builds it with path.Join rather than filepath.Join. Normalize before doing
	// any length arithmetic or joining.
	base = filepath.Clean(sanitizePath(base))

	root := filepath.Join(base, stagingDirName, NewRunID())

	if err := checkPathBudget(root); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(root, stagedDirPerm); err != nil {
		return nil, fmt.Errorf("%w: could not create %s: %w, set SNYK_TMP_PATH to stage elsewhere", ErrUnavailable, root, err)
	}

	logger.Debug().Str(logFieldPath, root).Msg("created staging directory")

	return &Root{path: root, logger: logger}, nil
}

// Path returns the staging root.
func (r *Root) Path() string {
	return r.path
}

// NewShard creates the directory tree for one shard and checks that the volume
// can still hold it.
//
// The free-space check is per shard rather than once for the whole scan: the
// total size of a history scan is not known up front, and a disk that fills
// mid-scan should fail at a clean shard boundary with an actionable message
// instead of surfacing a raw ENOSPC from somewhere inside a write.
func (r *Root) NewShard(index int) (*Shard, error) {
	scanRoot := filepath.Join(r.path, fmt.Sprintf(shardDirPattern, index), scanRootName)
	hunksDir := filepath.Join(scanRoot, hunksDirName)

	required := uint64(MaxShardBytes * diskAmplificationFactor)
	if err := gafutils.EnsureFreeDiskSpace(r.path, required); err != nil {
		return nil, fmt.Errorf("cannot stage shard %d: %w, free up space or set SNYK_TMP_PATH to a different volume", index, err)
	}

	if err := os.MkdirAll(hunksDir, stagedDirPerm); err != nil {
		return nil, fmt.Errorf("%w: could not create shard %d: %w", ErrUnavailable, index, err)
	}

	return &Shard{
		index:    index,
		scanRoot: scanRoot,
		hunksDir: hunksDir,
		buffer:   make([]byte, copyBufferSize),
		logger:   r.logger,
	}, nil
}

// Cleanup removes the whole staging area.
//
// Callers should defer this. The consuming application also removes
// TEMP_DIR_PATH wholesale on teardown, but that teardown does not run when the
// process is killed, and a history scan's staging area is large enough that
// leaving it behind is not acceptable.
func (r *Root) Cleanup() {
	if err := os.RemoveAll(r.path); err != nil {
		r.logger.Warn().Err(err).Str(logFieldPath, r.path).Msg("failed to remove staging directory")
		return
	}

	r.logger.Debug().Str(logFieldPath, r.path).Msg("removed staging directory")
}

// CleanupOnSignal removes the staging area if the process is interrupted, and
// returns a function that uninstalls the handler.
//
// Neither the CLI nor the framework installs a signal handler today, so a Ctrl-C
// part-way through a history scan terminates the process without any teardown
// running and leaves the staged hunks on disk. Re-raising the signal after
// cleaning up preserves the normal exit status.
func (r *Root) CleanupOnSignal() (stop func()) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)

	done := make(chan struct{})

	go func() {
		select {
		case received := <-signals:
			r.logger.Debug().Stringer("signal", received).Msg("interrupted, removing staging directory")
			r.Cleanup()

			signal.Stop(signals)
			if process, err := os.FindProcess(os.Getpid()); err == nil {
				_ = process.Signal(received)
			}
		case <-done:
		}
	}()

	return func() {
		signal.Stop(signals)
		close(done)
	}
}

// Shard is one uploadable revision's worth of staged hunks.
type Shard struct {
	index    int
	scanRoot string
	hunksDir string

	hunkCount int
	byteCount int64

	// completed records that Complete has written the manifest. Uploading a shard
	// before then would produce a revision the detection service cannot recognize
	// as a history scan.
	completed bool

	// buffer is reused across every hunk written to this shard, so materializing
	// does not allocate per hunk.
	buffer []byte

	logger *zerolog.Logger
}

// ScanRoot returns the __history__ directory holding this shard's files.
func (s *Shard) ScanRoot() string {
	return s.scanRoot
}

// ManifestPath returns the shard's attribution manifest.
func (s *Shard) ManifestPath() string {
	return filepath.Join(s.scanRoot, manifestFileName)
}

// Index returns the shard's ordinal.
func (s *Shard) Index() int {
	return s.index
}

// Stats reports what the shard currently holds, so the caller can decide when to
// roll over to the next one.
func (s *Shard) Stats() (hunks int, bytes int64) {
	return s.hunkCount, s.byteCount
}

// Fits reports whether a hunk of the given size can still be added without
// breaching a revision limit.
func (s *Shard) Fits(size int64) bool {
	return s.hunkCount < MaxHunksPerShard && s.byteCount+size <= MaxShardBytes
}

// WriteHunk streams one hunk into the shard.
//
// The content is copied through the shard's reused buffer rather than read into
// memory, which is what keeps peak memory independent of repository size. It
// returns ErrShardFull if the shard is already at a revision limit, in which
// case nothing is written and the caller should open the next shard.
func (s *Shard) WriteHunk(hunkID string, content io.Reader) (written int64, err error) {
	if err := validateHunkID(hunkID); err != nil {
		return 0, err
	}

	if s.hunkCount+1 > MaxHunksPerShard {
		return 0, fmt.Errorf("%w: shard %d already holds %d hunks", ErrShardFull, s.index, s.hunkCount)
	}

	target := filepath.Join(s.hunksDir, hunkID)

	//nolint:gosec // target is hunksDir joined with a hunk ID that validateHunkID has constrained to a bare file name.
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, stagedFilePerm)
	if err != nil {
		return 0, fmt.Errorf("could not create hunk %s: %w", hunkID, err)
	}

	written, err = io.CopyBuffer(file, content, s.buffer)
	if err != nil {
		// A partially written hunk must not survive: it would be uploaded as if
		// it were complete.
		_ = file.Close()
		_ = os.Remove(target)
		return 0, fmt.Errorf("could not write hunk %s: %w", hunkID, err)
	}

	if err := file.Close(); err != nil {
		_ = os.Remove(target)
		return 0, fmt.Errorf("could not close hunk %s: %w", hunkID, err)
	}

	s.hunkCount++
	s.byteCount += written

	return written, nil
}

// Complete writes the shard's attribution manifest, which must be the last thing
// written.
//
// The detection service uses the presence of __history__/manifest.json to
// recognize a history revision, so writing it last makes "manifest present" and
// "shard fully materialized" the same condition: a shard abandoned part-way
// through can never be mistaken for a complete one. It is written to a temporary
// name and renamed, so even a crash mid-write cannot leave a truncated manifest
// in place.
func (s *Shard) Complete(manifest io.Reader) error {
	target := s.ManifestPath()
	temporary := target + partialSuffix

	//nolint:gosec // temporary is derived from the shard's own scan root, not from user input.
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, stagedFilePerm)
	if err != nil {
		return fmt.Errorf("could not create manifest for shard %d: %w", s.index, err)
	}

	written, err := io.CopyBuffer(file, manifest, s.buffer)
	if err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return fmt.Errorf("could not write manifest for shard %d: %w", s.index, err)
	}

	if err := file.Close(); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("could not close manifest for shard %d: %w", s.index, err)
	}

	if written > MaxManifestBytes {
		_ = os.Remove(temporary)
		return fmt.Errorf("%w: manifest for shard %d is %d bytes, limit is %d",
			ErrShardFull, s.index, written, MaxManifestBytes)
	}

	if err := os.Rename(temporary, target); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("could not finalize manifest for shard %d: %w", s.index, err)
	}

	s.completed = true

	s.logger.Debug().
		Int("shard", s.index).
		Int("hunks", s.hunkCount).
		Int64("bytes", s.byteCount).
		Msg("completed shard")

	return nil
}

// Discard removes a shard that could not be completed, so it is never uploaded.
func (s *Shard) Discard() {
	shardDir := filepath.Dir(s.scanRoot)
	if err := os.RemoveAll(shardDir); err != nil {
		s.logger.Warn().Err(err).Str(logFieldPath, shardDir).Msg("failed to discard incomplete shard")
	}
}

// checkPathBudget verifies that the deepest file the layout will produce still
// fits within the platform's path limit.
//
// The check is done up front, against the longest path rather than the root,
// because discovering the limit part-way through materializing hundreds of
// thousands of hunks is far worse than refusing to start.
func checkPathBudget(root string) error {
	deepest := filepath.Join(
		root,
		fmt.Sprintf(shardDirPattern, 9999),
		scanRootName,
		hunksDirName,
		strings.Repeat("a", maxHunkIDLength),
	)

	limit := maxPathLength()
	if len(deepest) > limit {
		return fmt.Errorf(
			"%w: staging under %s would produce paths of %d characters, above the %d character limit, set SNYK_TMP_PATH to a shorter location",
			ErrPathTooLong, root, len(deepest), limit,
		)
	}

	// The uploaded path is relative to the scan root and always short, but it is
	// checked too so a change to the layout cannot silently breach the upload
	// limit.
	uploaded := path.Join(hunksDirName, strings.Repeat("a", maxHunkIDLength))
	if len(uploaded) > MaxUploadPathLength {
		return fmt.Errorf("%w: upload path %s exceeds %d characters", ErrPathTooLong, uploaded, MaxUploadPathLength)
	}

	return nil
}

// validateHunkID rejects anything that is not a bare file name, so a hunk ID
// derived from repository content can never escape the staging directory.
func validateHunkID(hunkID string) error {
	if hunkID == "" {
		return errors.New("hunk ID is empty")
	}

	if len(hunkID) > maxHunkIDLength {
		return fmt.Errorf("hunk ID %q is longer than %d characters", hunkID, maxHunkIDLength)
	}

	if hunkID != filepath.Base(hunkID) || strings.ContainsAny(hunkID, `/\`) || hunkID == "." || hunkID == ".." {
		return fmt.Errorf("hunk ID %q is not a valid file name", hunkID)
	}

	return nil
}

// sanitizePath strips double-quote characters from a filesystem path. On
// Windows, " is an invalid path character that commonly appears when the shell
// misinterprets a trailing backslash-quote (e.g. "C:\path\"). On Unix, " is
// valid, so the path is returned unchanged.
//
// Mirrors the helper in the secretstest package; both should move to one shared
// location if a third caller appears.
func sanitizePath(p string) string {
	if runtime.GOOS != windowsGOOS {
		return p
	}
	return strings.ReplaceAll(p, `"`, "")
}
