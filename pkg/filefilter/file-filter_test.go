//nolint:prealloc // We cannot know the size of the channel stream in advance
package filefilter_test

import (
	"fmt"
	"sort"
	"testing"

	ff "github.com/snyk/cli-extension-secrets/pkg/filefilter"
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

		// Run with 2 workers
		outChan := ff.Filter(inputChan, 2, exeFilter)
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

		// Run with 4 workers. Should drop .exe and vendor/
		outChan := ff.Filter(inputChan, 4, exeFilter, vendorFilter)
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
		outChan := ff.Filter(inputChan, 1, exeFilter)
		results := chanToSlice(outChan)

		if len(results) != 0 {
			t.Errorf("got %d files, want 0", len(results))
		}
	})
}

// TestFilter_ConcurrencyStress checks for race conditions and deadlocks.
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

	// Use a high thread count to force context switching.
	outChan := ff.Filter(inputChan, 10, passAllFilter)

	// Collect results.
	results := chanToSlice(outChan)

	// Assert count match.
	if len(results) != count {
		t.Errorf("Race condition check: Should return all files without data loss. Got %d, want %d", len(results), count)
	}
}
