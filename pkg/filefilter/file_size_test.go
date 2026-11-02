package filefilter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"

	ff "github.com/snyk/cli-extension-secrets/pkg/filefilter"
)

const maxSizeThreshold = 50 * 1000 * 1000 // 50MB

// createSizedFile creates a temporary file with a specific logical size.
// It uses file truncation to create sparse files, meaning it sets the
// metadata size without actually writing bytes to disk.
// This makes creating a 500MB test file instantaneous.
func createSizedFile(t *testing.T, size int64) string {
	t.Helper()

	// Create a temp file in a temp directory that cleans up automatically
	f, err := os.CreateTemp(t.TempDir(), "size-test-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer f.Close()

	// If size > 0, extend the file to that size
	if size > 0 {
		if err := f.Truncate(size); err != nil {
			t.Fatalf("failed to truncate file to size %d: %v", size, err)
		}
	}

	return f.Name()
}

func TestFileSizeFilter_FilterOut(t *testing.T) {
	logger := zerolog.Nop()
	filter := ff.FileSizeFilter(&logger)

	testCases := []struct {
		name        string
		size        int64
		nonExistent bool
		want        bool
	}{
		{
			name: "Empty file",
			size: 0,
			want: true,
		},
		{
			name: "Small file",
			size: 1,
			want: false,
		},
		{
			name: "Normal file",
			size: 1024,
			want: false,
		},
		{
			name: "File just under max size",
			size: maxSizeThreshold - 1,
			want: false,
		},
		{
			name: "File exactly at max size",
			size: maxSizeThreshold,
			want: false,
		},
		{
			name: "File just over max size",
			size: maxSizeThreshold + 1,
			want: true,
		},
		{
			name: "Very large file (10x max)",
			size: maxSizeThreshold * 10,
			want: true,
		},
		{
			name:        "File does not exist",
			nonExistent: true,
			// Error during stat = filter out.
			want: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			var path string

			if tt.nonExistent {
				// Point to a path that definitely doesn't exist.
				path = filepath.Join(t.TempDir(), "ghost-file")
			} else {
				path = createSizedFile(t, tt.size)
			}

			got := filter.FilterOut(path)
			if got != tt.want {
				t.Errorf("FilterOut() size=%d = %v, want %v", tt.size, got, tt.want)
			}
		})
	}
}
