package filefilter_test

// import (
// 	"fmt"
// 	"sort"
// 	"testing"

// 	ff "github.com/snyk/cli-extension-secrets/pkg/filefilter"
// )

// type MockFilter struct {
// 	// Callback lets us define behavior per test case
// 	ShouldFilterOut func(f ff.File) bool
// }

// func (m MockFilter) FilterOut(f ff.File) bool {
// 	if m.ShouldFilterOut == nil {
// 		return false
// 	}
// 	return m.ShouldFilterOut(f)
// }

// // TestFilter_ConcurrencyStress verifies that the mutex properly protects the slice.
// // Important!!: Run this with 'go test -race' to catch synchronization bugs.
// func TestFilter_ConcurrencyStress(t *testing.T) {
// 	// Setup massive input to force goroutine overlap
// 	count := 10000
// 	files := make([]ff.File, count)
// 	for i := 0; i < count; i++ {
// 		files[i] = ff.NewLocalFile(fmt.Sprintf("file-%d", i), nil)
// 	}

// 	// This forces the workers to hit the 'results = append' critical section as frequently as possible.
// 	passAllFilter := MockFilter{
// 		ShouldFilterOut: func(_ ff.File) bool {
// 			return false
// 		},
// 	}

// 	results := ff.Filter(files, passAllFilter)

// 	if len(results) != count {
// 		t.Errorf("Race condition check: Should return all files without data loss. Got %d, want %d", len(results), count)
// 	}
// }

// func TestFilter_Logic(t *testing.T) {
// 	// Setup inputs
// 	files := []ff.File{
// 		ff.NewLocalFile("keep_me.txt", nil),
// 		ff.NewLocalFile("drop_binary.exe", nil),
// 		ff.NewLocalFile("drop_vendor/lib.js", nil),
// 		ff.NewLocalFile("keep_me_too.go", nil),
// 	}

// 	// Drops .exe files
// 	exeFilter := MockFilter{
// 		ShouldFilterOut: func(f ff.File) bool {
// 			return f.Path() == "drop_binary.exe"
// 		},
// 	}

// 	// Drops vendor folder
// 	vendorFilter := MockFilter{
// 		ShouldFilterOut: func(f ff.File) bool {
// 			return f.Path() == "drop_vendor/lib.js"
// 		},
// 	}

// 	t.Run("Single Filter", func(t *testing.T) {
// 		results := ff.Filter(files, exeFilter)

// 		// Sort results because concurrent workers do not guarantee order
// 		sortFiles(results)

// 		if len(results) != 3 {
// 			t.Fatalf("got %d files, want 3", len(results))
// 		}

// 		expected := []string{"drop_vendor/lib.js", "keep_me.txt", "keep_me_too.go"}
// 		for i, want := range expected {
// 			if results[i].Path() != want {
// 				t.Errorf("index %d: got path %q, want %q", i, results[i].Path(), want)
// 			}
// 		}
// 	})

// 	t.Run("Multiple Filters (Short Circuiting)", func(t *testing.T) {
// 		// Should drop BOTH .exe and vendor/
// 		results := ff.Filter(files, exeFilter, vendorFilter)

// 		sortFiles(results)

// 		if len(results) != 2 {
// 			t.Fatalf("got %d files, want 2", len(results))
// 		}

// 		expected := []string{"keep_me.txt", "keep_me_too.go"}
// 		for i, want := range expected {
// 			if results[i].Path() != want {
// 				t.Errorf("index %d: got path %q, want %q", i, results[i].Path(), want)
// 			}
// 		}
// 	})

// 	t.Run("Empty Input", func(t *testing.T) {
// 		results := ff.Filter([]ff.File{}, exeFilter)
// 		if len(results) != 0 {
// 			t.Errorf("got %d files, want 0", len(results))
// 		}
// 	})
// }

// // Helper to make tests deterministic since concurrency scrambles output order.
// func sortFiles(files []ff.File) {
// 	sort.Slice(files, func(i, j int) bool {
// 		return files[i].Path() < files[j].Path()
// 	})
// }
