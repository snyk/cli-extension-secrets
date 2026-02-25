//go:build windows

package secretstest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindGitRoot_PathWithTrailingQuote(t *testing.T) {
	// On Windows, "snyk secrets test "C:\path\"" causes the shell to pass
	// C:\path" (with a trailing ") to the CLI. The " is an invalid path
	// character on Windows, making getDir -> os.Stat fail.
	tempDir := t.TempDir()
	err := os.MkdirAll(filepath.Join(tempDir, Git), 0o755)
	require.NoError(t, err)

	pathWithQuote := tempDir + `"`

	// Without sanitization: findGitRoot fails because " is invalid in Windows paths.
	_, err = findGitRoot(pathWithQuote)
	require.Error(t, err, "unsanitized path with quote should fail on Windows")

	// With sanitization: the " is stripped and findGitRoot succeeds.
	sanitized := sanitizePath(pathWithQuote)
	root, err := findGitRoot(sanitized)
	require.NoError(t, err, "sanitized path should succeed")
	assert.Equal(t, tempDir, root)
}
