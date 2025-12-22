//go:build windows

package filefilter

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAllowedFilesWindows_GitignoreWithWindowsPaths(t *testing.T) {
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()
	tmpDir := t.TempDir()

	gitignoreContents := `
node_modules\
src\config\secret.txt
`

	files := map[string]string{
		// should be kept
		`keep.go`:    "",
		`.gitignore`: gitignoreContents,

		// should be ignored from gitignore rules
		`src\config\secret.txt`: "",
		`node_modules\lib.js`:   "",
	}

	for relPath, content := range files {
		fullPath := filepath.Join(tmpDir, relPath)
		require.NoError(t, os.MkdirAll(filepath.Dir(fullPath), 0o755))
		require.NoError(t, os.WriteFile(fullPath, []byte(content), 0o644))
	}

	oldWd, _ := os.Getwd()
	require.NoError(t, os.Chdir(tmpDir))
	t.Cleanup(func() { os.Chdir(oldWd) })

	ctx := context.Background()
	stream := streamAllowedFiles(ctx, []string{"."}, []string{".gitignore"}, nil, &logger)

	var results []string
	for path := range stream {
		results = append(results, path)
		t.Logf("output: %s", path)
	}
	sort.Strings(results)

	assert.Contains(t, results, ".gitignore")
	assert.Contains(t, results, "keep.go")

	for _, r := range results {
		assert.NotContains(t, r, "node_modules")
		assert.NotContains(t, r, "secret.txt")
	}
}

func TestAllowedFilesWindows_GitignoreWithUnixPaths(t *testing.T) {
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()
	tmpDir := t.TempDir()

	gitignoreContents := `
vendor/
build/
`

	files := map[string]string{
		// should be kept
		`keep.go`:    "",
		`.gitignore`: gitignoreContents,

		// should be ignored from gitignore rules
		`vendor\pkg\lib.go`: "",
		`build\cli.preview`: "",
	}

	for relPath, content := range files {
		fullPath := filepath.Join(tmpDir, relPath)
		require.NoError(t, os.MkdirAll(filepath.Dir(fullPath), 0o755))
		require.NoError(t, os.WriteFile(fullPath, []byte(content), 0o644))
	}

	oldWd, _ := os.Getwd()
	require.NoError(t, os.Chdir(tmpDir))
	t.Cleanup(func() { os.Chdir(oldWd) })

	ctx := context.Background()
	stream := streamAllowedFiles(ctx, []string{"."}, []string{".gitignore"}, nil, &logger)

	var results []string
	for path := range stream {
		results = append(results, path)
		t.Logf("output: %s", path)
	}

	assert.Contains(t, results, "keep.go")
	assert.Contains(t, results, ".gitignore")

	for _, r := range results {
		assert.NotContains(t, r, "vendor")
		assert.NotContains(t, r, "build")
	}
}

func TestAllowedFilesWindows_CustomGlobRules(t *testing.T) {
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()
	tmpDir := t.TempDir()

	files := map[string]string{
		// should be kept
		`keep.go`: "",

		// should be ignored from generic rules
		`Images\logo.png`:              "",
		`node_modules\lodash.js`:       "",
		`vendor\github.com\pkg\lib.go`: "",
		`assets\jquery-3.6.0.js`:       "",
	}

	for relPath, content := range files {
		fullPath := filepath.Join(tmpDir, relPath)
		require.NoError(t, os.MkdirAll(filepath.Dir(fullPath), 0o755))
		require.NoError(t, os.WriteFile(fullPath, []byte(content), 0o644))
	}

	oldWd, _ := os.Getwd()
	require.NoError(t, os.Chdir(tmpDir))
	t.Cleanup(func() { os.Chdir(oldWd) })

	ctx := context.Background()
	customRules := getCustomGlobIgnoreRules()
	stream := streamAllowedFiles(ctx, []string{"."}, nil, customRules, &logger)

	var results []string
	for path := range stream {
		results = append(results, path)
		t.Logf("output: %s", path)
	}

	assert.Contains(t, results, "keep.go")

	for _, r := range results {
		assert.NotContains(t, r, ".png", "*.png extension pattern should filter")
		assert.NotContains(t, r, "node_modules", "node_modules/ dir pattern should filter")
		assert.NotContains(t, r, "vendor", "vendor/github.com/ path pattern should filter")
		assert.NotContains(t, r, "jquery", "jquery*.js wildcard pattern should filter")
	}
}
