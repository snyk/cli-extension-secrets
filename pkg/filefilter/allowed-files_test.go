//nolint:errcheck,gocyclo,usetesting,prealloc // Complex initialisation of test cases
package filefilter_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/rs/zerolog"

	ff "github.com/snyk/cli-extension-secrets/pkg/filefilter"
)

// setupTempDir creates a temporary directory populated with the provided file map.
func setupTempDir(t *testing.T, files map[string]string) string {
	t.Helper()
	tmpDir := t.TempDir()

	canonicalPath, err := filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatalf("failed to eval symlinks: %v", err)
	}

	for path, content := range files {
		fullPath := filepath.Join(canonicalPath, path)
		err := os.MkdirAll(filepath.Dir(fullPath), 0o755)
		if err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
		err = os.WriteFile(fullPath, []byte(content), 0o600)
		if err != nil {
			t.Fatalf("failed to write file: %v", err)
		}
	}
	return canonicalPath
}

// collectStream drains the channel and returns sorted results relative to the root.
func collectStream(ch chan string, root string) []string {
	var results []string
	for path := range ch {
		// If root is ".", path is already relative.
		if root == "." {
			results = append(results, path)
			continue
		}
		// Convert absolute path back to relative for assertion
		rel, _ := filepath.Rel(root, path)
		results = append(results, rel)
	}
	sort.Strings(results)
	return results
}

func TestStreamAllowedFiles(t *testing.T) {
	// Use a console logger in tests so we can see errors if they occur.
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()

	t.Run("Input: Single directory path (Respects .gitignore)", func(t *testing.T) {
		// Structure:
		// .gitignore     (ignores *.secret)
		// main.go
		// config.secret  (should be ignored)
		// src/
		//   utils.go
		//   api.secret   (should be ignored)
		files := map[string]string{
			// Added newline to ensure rule is parsed
			".gitignore":     "*.secret\n",
			"main.go":        "package main",
			"config.secret":  "SUPER_SECRET",
			"src/utils.go":   "package utils",
			"src/api.secret": "API_KEY",
		}

		rootDir := setupTempDir(t, files)

		// Execute test from within the directory using relative paths ".".
		// This accommodates the gitignore matcher which likely fails on absolute paths.
		oldWd, _ := os.Getwd()
		err := os.Chdir(rootDir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chdir(oldWd) })

		ctx := context.Background()

		// Pass "." to simulate running from CLI root.
		stream := ff.StreamAllowedFiles(ctx, []string{"."}, []string{".gitignore"}, &logger)
		results := collectStream(stream, ".")

		// Assert
		expected := []string{
			".gitignore",
			"main.go",
			"src/utils.go",
		}
		sort.Strings(expected)

		if len(results) != len(expected) {
			t.Fatalf("got %d files, want %d. Got: %v", len(results), len(expected), results)
		}

		for i, want := range expected {
			if results[i] != want {
				t.Errorf("index %d: got %q, want %q", i, results[i], want)
			}
		}
	})

	t.Run("Input: Single directory path (No ignores)", func(t *testing.T) {
		files := map[string]string{
			"code.go": "package main",
		}
		rootDir := setupTempDir(t, files)

		oldWd, _ := os.Getwd()
		err := os.Chdir(rootDir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chdir(oldWd) })

		ctx := context.Background()

		stream := ff.StreamAllowedFiles(ctx, []string{"."}, []string{".gitignore"}, &logger)
		results := collectStream(stream, ".")

		if len(results) != 1 || results[0] != "code.go" {
			t.Errorf("expected [code.go], got %v", results)
		}
	})

	t.Run("Input: Multiple directory paths", func(t *testing.T) {
		// Note: This test uses absolute paths. Since we aren't asserting ignore logic here.
		// (just merging), absolute paths are fine even if the filter doesn't catch them.
		filesA := map[string]string{"fileA.txt": "content"}
		dirA := setupTempDir(t, filesA)

		filesB := map[string]string{"fileB.txt": "content"}
		dirB := setupTempDir(t, filesB)

		ctx := context.Background()
		stream := ff.StreamAllowedFiles(ctx, []string{dirA, dirB}, []string{".gitignore"}, &logger)

		// Collect results using Base name to ignore path prefix differences.
		var results []string
		for p := range stream {
			results = append(results, filepath.Base(p))
		}
		sort.Strings(results)

		expected := []string{"fileA.txt", "fileB.txt"}
		if len(results) != 2 {
			t.Fatalf("expected 2 merged files, got %d", len(results))
		}
		for i, want := range expected {
			if results[i] != want {
				t.Errorf("got %q, want %q", results[i], want)
			}
		}
	})

	t.Run("Input: Mixed directories and file paths", func(t *testing.T) {
		files := map[string]string{
			"dir1/fileA.txt": "content",
			"rootFile.txt":   "content",
			// Not in input list.
			"ignored.txt": "content",
		}
		rootDir := setupTempDir(t, files)

		dir1 := filepath.Join(rootDir, "dir1")
		rootFile := filepath.Join(rootDir, "rootFile.txt")

		ctx := context.Background()
		// Input: one directory and one specific file.
		// Note: Absolute paths used here.
		inputs := []string{dir1, rootFile}
		stream := ff.StreamAllowedFiles(ctx, inputs, []string{".gitignore"}, &logger)

		var results []string
		for p := range stream {
			results = append(results, filepath.Base(p))
		}
		sort.Strings(results)

		// Should find fileA.txt (from dir1) and rootFile.txt (explicitly passed).
		expected := []string{"fileA.txt", "rootFile.txt"}

		if len(results) != len(expected) {
			t.Fatalf("got %d files, want %d. Got: %v", len(results), len(expected), results)
		}
		for i, want := range expected {
			if results[i] != want {
				t.Errorf("got %q, want %q", results[i], want)
			}
		}
	})

	t.Run("Input: Multiple file paths only", func(t *testing.T) {
		files := map[string]string{
			"fileA.txt": "content",
			"fileB.txt": "content",
			// Not in input.
			"fileC.txt": "content",
		}
		rootDir := setupTempDir(t, files)

		fileA := filepath.Join(rootDir, "fileA.txt")
		fileB := filepath.Join(rootDir, "fileB.txt")

		ctx := context.Background()
		stream := ff.StreamAllowedFiles(ctx, []string{fileA, fileB}, nil, &logger)

		var results []string
		for p := range stream {
			results = append(results, filepath.Base(p))
		}
		sort.Strings(results)

		expected := []string{"fileA.txt", "fileB.txt"}

		if len(results) != len(expected) {
			t.Fatalf("got %d files, want %d. Got: %v", len(results), len(expected), results)
		}
		for i, want := range expected {
			if results[i] != want {
				t.Errorf("got %q, want %q", results[i], want)
			}
		}
	})

	t.Run("Handles context cancellation", func(t *testing.T) {
		files := make(map[string]string)
		for i := 0; i < 1000; i++ {
			files[filepath.Join("data", fmt.Sprintf("file-%d", i))] = "data"
		}
		rootDir := setupTempDir(t, files)

		ctx, cancel := context.WithCancel(context.Background())
		stream := ff.StreamAllowedFiles(ctx, []string{rootDir}, []string{".gitignore"}, &logger)
		cancel()

		count := 0
		timeout := time.After(2 * time.Second)

		done := make(chan bool)
		go func() {
			for range stream {
				count++
			}
			done <- true
		}()

		select {
		case <-done:
			// Success
		case <-timeout:
			t.Fatal("stream did not close after context cancellation")
		}
	})
}
