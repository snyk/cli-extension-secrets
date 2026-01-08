//nolint:prealloc,testpackage // We cannot know the size of the channel stream in advance
package filefilter

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

// mockFilter implements FileFilter for testing purposes.
type mockFilter struct {
	fn func(path string) bool
}

func (m *mockFilter) FilterOut(path string) bool {
	if m.fn == nil {
		return false
	}
	return m.fn(path)
}

// chanToSlice collects all items from a channel into a slice.
func chanToSlice(ch chan string) []string {
	var results []string
	for item := range ch {
		results = append(results, item)
	}
	return results
}

// sortStrings sorts strings to ensure deterministic assertions.
func sortStrings(s []string) {
	sort.Strings(s)
}

func TestFilter_Logic(t *testing.T) {
	logger := newTestLogger()

	// Setup standard input paths
	inputFiles := map[string]string{
		"keep_me.txt":        "test content",
		"drop_binary.exe":    "test content",
		"drop_vendor/lib.js": "test content",
		"keep_me_too.go":     "test content",
	}
	dirPath := setupTempDir(t, inputFiles)
	var inputPaths []string
	for k := range inputFiles {
		inputPaths = append(inputPaths, filepath.Join(dirPath, k))
	}

	// Drops .exe files
	exeFilter := &mockFilter{
		fn: func(path string) bool {
			return strings.Contains(path, "drop_binary.exe")
		},
	}

	// Drops vendor folder
	vendorFilter := &mockFilter{
		fn: func(path string) bool {
			return strings.Contains(path, "drop_vendor/lib.js")
		},
	}

	t.Run("Single Filter", func(t *testing.T) {
		// Use Pipeline with 2 workers
		pipeline := NewPipeline(
			WithConcurrency(2),
			WithFilters(exeFilter),
		)

		outChan := pipeline.Filter(t.Context(), inputPaths, []string{}, &logger)
		results := chanToSlice(outChan)

		// Sort results because concurrent workers do not guarantee order
		sortStrings(results)

		if len(results) != 3 {
			t.Fatalf("got %d files, want 3", len(results))
		}

		expected := []string{path.Join(dirPath, "drop_vendor/lib.js"), path.Join(dirPath, "keep_me.txt"), path.Join(dirPath, "keep_me_too.go")}
		for i, want := range expected {
			if results[i] != want {
				t.Errorf("index %d: got path %q, want %q", i, results[i], want)
			}
		}
	})

	t.Run("Multiple Filters (Short Circuiting)", func(t *testing.T) {
		// Use Pipeline with 4 workers and multiple filters
		pipeline := NewPipeline(
			WithConcurrency(4),
			WithFilters(exeFilter, vendorFilter),
		)

		outChan := pipeline.Filter(t.Context(), inputPaths, []string{}, &logger)
		results := chanToSlice(outChan)

		sortStrings(results)

		if len(results) != 2 {
			t.Fatalf("got %d files, want 2", len(results))
		}

		expected := []string{path.Join(dirPath, "keep_me.txt"), path.Join(dirPath, "keep_me_too.go")}
		for i, want := range expected {
			if results[i] != want {
				t.Errorf("index %d: got path %q, want %q", i, results[i], want)
			}
		}
	})

	t.Run("Empty Input", func(t *testing.T) {
		pipeline := NewPipeline(
			WithConcurrency(1),
			WithFilters(exeFilter),
		)

		outChan := pipeline.Filter(t.Context(), []string{}, []string{}, &logger)
		results := chanToSlice(outChan)

		if len(results) != 0 {
			t.Errorf("got %d files, want 0", len(results))
		}
	})
}

// TestPipeline_Configuration uses white-box testing (same package)
// to verify that options are correctly applied to the struct fields.
func TestPipeline_Configuration(t *testing.T) {
	t.Run("Defaults", func(t *testing.T) {
		p := NewPipeline()

		// Expect default CPU count
		if p.concurrency != runtime.NumCPU() {
			t.Errorf("expected default concurrency %d, got %d", runtime.NumCPU(), p.concurrency)
		}
		// Expect no filters
		if len(p.filters) != 0 {
			t.Errorf("expected 0 filters, got %d", len(p.filters))
		}
	})

	t.Run("WithConcurrency", func(t *testing.T) {
		// Valid custom concurrency
		p := NewPipeline(WithConcurrency(42))
		if p.concurrency != 42 {
			t.Errorf("expected concurrency 42, got %d", p.concurrency)
		}

		// Invalid concurrency (should fallback to default or ignore)
		// Assuming implementation ignores <= 0
		pDefault := NewPipeline(WithConcurrency(-1))
		if pDefault.concurrency <= 0 {
			t.Error("concurrency should remain positive even if option is invalid")
		}
	})

	t.Run("WithFilters", func(t *testing.T) {
		f1 := &mockFilter{}
		f2 := &mockFilter{}

		p := NewPipeline(WithFilters(f1, f2))

		if len(p.filters) != 2 {
			t.Errorf("expected 2 filters, got %d", len(p.filters))
		}

		// Verify append behavior (if called multiple times)
		p2 := NewPipeline(WithFilters(f1), WithFilters(f2))
		if len(p2.filters) != 2 {
			t.Errorf("expected 2 filters when chaining options, got %d", len(p2.filters))
		}
	})
}

// TestFilter_ConcurrencyStress checks for race conditions and data loss.
// Run this with 'go test -race'.
func TestFilter_ConcurrencyStress(t *testing.T) {
	count := 10000
	inputFiles := map[string]string{}
	logger := newTestLogger()

	// Generate massive input.
	for i := 0; i < count; i++ {
		inputFiles[fmt.Sprintf("file-%d", i)] = "test content"
	}

	dirPath := setupTempDir(t, inputFiles)

	var inputPaths []string
	for k := range inputFiles {
		inputPaths = append(inputPaths, filepath.Join(dirPath, k))
	}

	// A filter that keeps everything.
	passAllFilter := &mockFilter{
		fn: func(string) bool { return false },
	}

	// Use Pipeline with high concurrency
	pipeline := NewPipeline(
		WithConcurrency(10),
		WithFilters(passAllFilter),
	)

	outChan := pipeline.Filter(t.Context(), inputPaths, []string{}, &logger)

	// Collect results.
	results := chanToSlice(outChan)

	// Assert count match.
	if len(results) != count {
		t.Errorf("Stress test failed: Should return all files. Got %d, want %d", len(results), count)
	}
}

func TestFilter_UserAndExtensionMerge(t *testing.T) {
	logger := newTestLogger()
	inputFiles := map[string]string{
		"src/app.go":         "package main",   // KEEP
		"node_modules/d3.js": "minified code",  // DROP (Extension: node_modules/)
		"image.png":          "binary data",    // DROP (Extension: *.png)
		"dist/bundle.js":     "built code",     // DROP (User: dist/**)
		"secret.txt":         "sensitive info", // DROP (User: secret.txt)
	}
	dirPath := setupTempDir(t, inputFiles)
	inputPaths := []string{dirPath}

	t.Run("Verify user provided excludes", func(t *testing.T) {
		pipeline := NewPipeline(WithConcurrency(1))
		// These mimic the output of your buildExclusionGlobs function
		userExcludes := []string{
			"**/dist", "**/dist/**",
			"**/secret.txt", "**/secret.txt/**",
		}
		outChan := pipeline.Filter(t.Context(), inputPaths, userExcludes, &logger)
		results := chanToSlice(outChan)

		// We expect only one file: src/app.go
		assert.Equal(t, 1, len(results), "Only src/app.go should remain")
		for _, res := range results {
			assert.False(t, strings.Contains(res, "node_modules"), "Extension ignore failed")
			assert.False(t, strings.Contains(res, "image.png"), "Extension extension ignore failed")
			assert.False(t, strings.Contains(res, "dist"), "User directory ignore failed")
			assert.False(t, strings.Contains(res, "secret.txt"), "User file ignore failed")
			assert.True(t, strings.HasSuffix(filepath.ToSlash(res), "src/app.go"))
		}
	})
}

func newTestLogger() zerolog.Logger {
	return zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.Kitchen}).
		Level(zerolog.DebugLevel).
		With().
		Timestamp().
		Logger()
}
