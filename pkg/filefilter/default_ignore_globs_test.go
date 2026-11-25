//nolint:testpackage // exercises unexported ignore glob lists
package filefilter

import (
	"context"
	"slices"
	"testing"

	"github.com/rs/zerolog"
)

func TestDefaultIgnoreGlobsMergedParity(t *testing.T) {
	t.Parallel()

	rules := getCustomGlobIgnoreRules()

	// Former CLI-only and service-only patterns must both be present after the merge.
	required := []string{
		"vendor/github.com/", // previously CLI-only
		"go.mod",             // previously CLI-only
		"*.exe",              // previously service-only
		"Cargo.lock",         // previously service-only
		"bun.lock",           // previously service-only
		"*.tif",              // previously service-only (CLI had *.tiff only)
	}
	for _, pattern := range required {
		if !slices.Contains(rules, pattern) {
			t.Errorf("default ignore globs missing merged pattern %q", pattern)
		}
	}

	wantLen := len(ignoredExtensionsGlob) + len(ignoreGenericFilesGlob)
	if len(rules) != wantLen {
		t.Fatalf("getCustomGlobIgnoreRules returned %d patterns, want %d", len(rules), wantLen)
	}

	// Defensive copy: callers must not be able to mutate the package defaults.
	rules[0] = "mutated-by-test"
	if ignoredExtensionsGlob[0] == "mutated-by-test" {
		t.Fatal("getCustomGlobIgnoreRules must return a copy, not the package slice")
	}
}

func TestDefaultIgnoreGlobsFilterServiceOnlyPatterns(t *testing.T) {
	rootDir := setupTempDir(t, map[string]string{
		"app.go":     "package main\n",
		"Cargo.lock": "[[package]]\n",
		"secret.exe": "MZ",
		"photo.webp": "RIFF",
		"LICENSE":    "MIT",
		"vendor.txt": "keep",
	})

	t.Chdir(rootDir)

	logger := zerolog.Nop()
	stream := streamAllowedFiles(
		context.Background(),
		[]string{"."},
		nil,
		getCustomGlobIgnoreRules(),
		getTestInvocationContext(t),
		&logger,
	)
	results := collectStream(stream, ".")

	if !slices.Contains(results, "app.go") {
		t.Fatalf("expected app.go to be allowed, got %v", results)
	}
	if !slices.Contains(results, "vendor.txt") {
		t.Fatalf("expected vendor.txt to be allowed, got %v", results)
	}
	for _, blocked := range []string{"Cargo.lock", "secret.exe", "photo.webp", "LICENSE"} {
		if slices.Contains(results, blocked) {
			t.Errorf("expected %s to be ignored by default globs, got %v", blocked, results)
		}
	}
}
