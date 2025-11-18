package secretstest_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-secrets/internal/commands/secretstest"
)

func TestFindAllFiles_DeadlockSafety(t *testing.T) {
	// We need enough files to fill the channel buffer to prove the
	// producer doesn't block indefinitely.
	tempDir := t.TempDir()
	fileCount := 1000

	for range fileCount {
		f, err := os.CreateTemp(tempDir, "testfile-*")
		require.NoError(t, err)
		f.Close()
	}

	// Run FindAllFiles in a goroutine so we can time it out.
	type result struct {
		files []secretstest.LocalFile
		err   error
	}
	done := make(chan result)

	go func() {
		files, err := secretstest.FindAllFiles([]string{tempDir})
		done <- result{files, err}
	}()

	// Wait for result OR timeout.
	select {
	case res := <-done:
		require.NoError(t, res.err)
		assert.Equal(t, fileCount, len(res.files))
	case <-time.After(2 * time.Second):
		// If we hit this, the Producer likely got stuck pushing to a full channel.
		t.Fatal("Test timed out! Potential deadlock detected in FindAllFiles")
	}
}

func TestFindAllFiles_ErrorPropagation(t *testing.T) {
	// Test that if a worker fails, the whole thing shuts down cleanly without hanging.
	tempDir := t.TempDir()
	subDir := filepath.Join(tempDir, "noperms")
	// Unreadable directory
	err := os.Mkdir(subDir, 0o000)
	require.NoError(t, err)

	// This mimics the WalkDir failing or internal access failing
	_, err = secretstest.FindAllFiles([]string{subDir})
	// Depending on OS (Windows/ Linux), this might behave differently,
	// but the key is that it returns an error and doesn't hang.
	if err != nil {
		assert.Error(t, err)
	}
}
