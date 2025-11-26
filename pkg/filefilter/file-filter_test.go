//nolint:prealloc,testpackage // We cannot know the size of the channel stream in advance
package filefilter

import (
	"fmt"
	"runtime"
	"sort"
	"testing"
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

// feeds a slice into a channel and closes it.
func sliceToChan(inputs []string) chan string {
	// Buffer size equals length to prevent blocking during setup.
	ch := make(chan string, len(inputs))
	for _, i := range inputs {
		ch <- i
	}
	close(ch)
	return ch
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
	// Setup standard input paths
	inputPaths := []string{
		"keep_me.txt",
		"drop_binary.exe",
		"drop_vendor/lib.js",
		"keep_me_too.go",
	}

	// Drops .exe files
	exeFilter := &mockFilter{
		fn: func(path string) bool {
			return path == "drop_binary.exe"
		},
	}

	// Drops vendor folder
	vendorFilter := &mockFilter{
		fn: func(path string) bool {
			return path == "drop_vendor/lib.js"
		},
	}

	t.Run("Single Filter", func(t *testing.T) {
		inputChan := sliceToChan(inputPaths)

		// Use Pipeline with 2 workers
		pipeline := NewPipeline(
			WithConcurrency(2),
			WithFilters(exeFilter),
		)

		outChan := pipeline.Filter(inputChan)
		results := chanToSlice(outChan)

		// Sort results because concurrent workers do not guarantee order
		sortStrings(results)

		if len(results) != 3 {
			t.Fatalf("got %d files, want 3", len(results))
		}

		expected := []string{"drop_vendor/lib.js", "keep_me.txt", "keep_me_too.go"}
		for i, want := range expected {
			if results[i] != want {
				t.Errorf("index %d: got path %q, want %q", i, results[i], want)
			}
		}
	})

	t.Run("Multiple Filters (Short Circuiting)", func(t *testing.T) {
		inputChan := sliceToChan(inputPaths)

		// Use Pipeline with 4 workers and multiple filters
		pipeline := NewPipeline(
			WithConcurrency(4),
			WithFilters(exeFilter, vendorFilter),
		)

		outChan := pipeline.Filter(inputChan)
		results := chanToSlice(outChan)

		sortStrings(results)

		if len(results) != 2 {
			t.Fatalf("got %d files, want 2", len(results))
		}

		expected := []string{"keep_me.txt", "keep_me_too.go"}
		for i, want := range expected {
			if results[i] != want {
				t.Errorf("index %d: got path %q, want %q", i, results[i], want)
			}
		}
	})

	t.Run("Empty Input", func(t *testing.T) {
		// Empty channel.
		inputChan := sliceToChan([]string{})

		pipeline := NewPipeline(
			WithConcurrency(1),
			WithFilters(exeFilter),
		)

		outChan := pipeline.Filter(inputChan)
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
	inputChan := make(chan string, count)

	// Generate massive input.
	for i := 0; i < count; i++ {
		inputChan <- fmt.Sprintf("file-%d", i)
	}
	close(inputChan)

	// A filter that keeps everything.
	passAllFilter := &mockFilter{
		fn: func(string) bool { return false },
	}

	// Use Pipeline with high concurrency
	pipeline := NewPipeline(
		WithConcurrency(10),
		WithFilters(passAllFilter),
	)

	outChan := pipeline.Filter(inputChan)

	// Collect results.
	results := chanToSlice(outChan)

	// Assert count match.
	if len(results) != count {
		t.Errorf("Stress test failed: Should return all files. Got %d, want %d", len(results), count)
	}
}
