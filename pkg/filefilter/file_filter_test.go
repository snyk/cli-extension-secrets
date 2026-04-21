//nolint:prealloc,testpackage // We cannot know the size of the channel stream in advance
package filefilter

import (
	"fmt"
	"os"
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

func (m *mockFilter) RecordMetrics(_ Analytics) {}

// mockAnalytics implements Analytics for testing purposes.
type mockAnalytics struct {
	sizeFilteredCount int
	filterTimeCalled  bool
}

func (m *mockAnalytics) RecordSizeFiltered(total int) {
	m.sizeFilteredCount += total
}

func (m *mockAnalytics) RecordFileFilterTimeMs(_ time.Time) {
	m.filterTimeCalled = true
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
		".gitignore":         "test content",
		".gitleaksignore":    "test content",
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
		fn: func(p string) bool {
			return strings.Contains(p, filepath.Join("drop_vendor", "lib.js"))
		},
	}

	t.Run("Single Filter", func(t *testing.T) {
		// Use Pipeline with 2 workers
		pipeline := NewPipeline(
			WithConcurrency(2),
			WithFilters(exeFilter),
			WithLogger(&logger),
		)

		outChan := pipeline.Filter(t.Context(), inputPaths)
		results := chanToSlice(outChan)

		// Sort results because concurrent workers do not guarantee order
		sortStrings(results)

		if len(results) != 3 {
			t.Fatalf("got %d files, want 3", len(results))
		}

		expected := []string{filepath.Join(dirPath, "drop_vendor", "lib.js"), filepath.Join(dirPath, "keep_me.txt"), filepath.Join(dirPath, "keep_me_too.go")}
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
			WithLogger(&logger),
		)

		outChan := pipeline.Filter(t.Context(), inputPaths)
		results := chanToSlice(outChan)

		sortStrings(results)

		if len(results) != 2 {
			t.Fatalf("got %d files, want 2", len(results))
		}

		expected := []string{filepath.Join(dirPath, "keep_me.txt"), filepath.Join(dirPath, "keep_me_too.go")}
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
			WithLogger(&logger),
		)

		outChan := pipeline.Filter(t.Context(), []string{})
		results := chanToSlice(outChan)

		if len(results) != 0 {
			t.Errorf("got %d files, want 0", len(results))
		}
	})

	t.Run("MustExcludeFiles", func(t *testing.T) {
		// No custom filters passed; testing default pipeline exclusion
		pipeline := NewPipeline(
			WithConcurrency(2),
			WithLogger(&logger),
		)

		outChan := pipeline.Filter(t.Context(), inputPaths)
		results := chanToSlice(outChan)

		sortStrings(results)

		// Expects 4 files (6 total inputs - 2 implicit drop)
		if len(results) != 4 {
			t.Fatalf("got %d files, want 4. Results: %v", len(results), results)
		}

		expected := []string{
			filepath.Join(dirPath, "drop_binary.exe"),
			filepath.Join(dirPath, "drop_vendor", "lib.js"),
			filepath.Join(dirPath, "keep_me.txt"),
			filepath.Join(dirPath, "keep_me_too.go"),
		}
		for i, want := range expected {
			if results[i] != want {
				t.Errorf("index %d: got path %q, want %q", i, results[i], want)
			}
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

	t.Run("WithExcludeGlobs", func(t *testing.T) {
		defaultGlobsLen := len(getCustomGlobIgnoreRules())
		userPatterns := []string{"node_modules/*,package.json"}

		p := NewPipeline(WithExcludeGlobs(userPatterns))
		expectedLen := defaultGlobsLen + len(userPatterns)

		if len(p.customGlobPatterns) != expectedLen {
			t.Errorf("expected custom patterns %d, got %d", expectedLen, len(p.customGlobPatterns))
		}

		// Check len with no excludes
		pDefault := NewPipeline()
		if len(pDefault.customGlobPatterns) != defaultGlobsLen {
			t.Errorf("default globs not initialized %d, got %d", expectedLen, len(pDefault.customGlobPatterns))
		}
	})
}

// TestFilter_ConcurrencyStress checks for race conditions and data loss.
// Run this with 'go test -race'.
func TestFilter_ConcurrencyStress(t *testing.T) {
	count := 1000
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
		WithLogger(&logger),
	)

	outChan := pipeline.Filter(t.Context(), inputPaths)

	// Collect results.
	results := chanToSlice(outChan)

	// Assert count match.
	if len(results) != count {
		t.Errorf("Stress test failed: Should return all files. Got %d, want %d", len(results), count)
	}
}

func newTestLogger() zerolog.Logger {
	return zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.Kitchen}).
		Level(zerolog.DebugLevel).
		With().
		Timestamp().
		Logger()
}

func TestFileSizeFilter_Metrics(t *testing.T) {
	logger := newTestLogger()

	tests := []struct {
		name          string
		setupFiles    func(dirPath string) []string
		nilAnalytics  bool
		expectedCount int
	}{
		{
			name: "All valid files, no metrics recorded",
			setupFiles: func(dirPath string) []string {
				valid1 := filepath.Join(dirPath, "valid1.txt")
				valid2 := filepath.Join(dirPath, "valid2.txt")
				_ = os.WriteFile(valid1, []byte("content"), 0o600)
				_ = os.WriteFile(valid2, []byte("content"), 0o600)
				return []string{valid1, valid2}
			},
			expectedCount: 0,
		},
		{
			name: "Mixed files, drops empty and missing",
			setupFiles: func(dirPath string) []string {
				valid := filepath.Join(dirPath, "valid.txt")
				empty := filepath.Join(dirPath, "empty.txt")
				// intentionally not created
				missing := filepath.Join(dirPath, "missing.txt")

				_ = os.WriteFile(valid, []byte("content"), 0o600)
				_ = os.WriteFile(empty, []byte(""), 0o600)
				return []string{valid, empty, missing}
			},
			expectedCount: 2,
		},
		{
			name: "Nil analytics",
			setupFiles: func(dirPath string) []string {
				empty := filepath.Join(dirPath, "empty.txt")
				_ = os.WriteFile(empty, []byte(""), 0o600)
				return []string{empty}
			},
			nilAnalytics: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dirPath := t.TempDir()
			paths := tt.setupFiles(dirPath)

			filter := &fileSizeFilter{logger: &logger}

			// Process files
			for _, p := range paths {
				filter.FilterOut(p)
			}

			// Setup analytics mock
			var analytics Analytics
			mock := &mockAnalytics{}
			if !tt.nilAnalytics {
				analytics = mock
			}

			// In case of nil analytics
			assert.NotPanics(t, func() {
				filter.RecordMetrics(analytics)
			})

			// Assert the final count
			if !tt.nilAnalytics {
				assert.Equal(t, tt.expectedCount, mock.sizeFilteredCount)
			}
		})
	}
}
