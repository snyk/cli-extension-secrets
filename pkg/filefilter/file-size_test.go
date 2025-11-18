//nolint:testpackage // whitebox
package filefilter

import (
	"io/fs"
	"testing"
	"time"
)

// mockFileInfo is a simple implementation of fs.FileInfo for testing.
// It only implements the methods needed by the filter, primarily Size().
type mockFileInfo struct {
	fileSize int64
}

func (m mockFileInfo) Name() string       { return "mockfile" }
func (m mockFileInfo) Size() int64        { return m.fileSize }
func (m mockFileInfo) Mode() fs.FileMode  { return 0 }
func (m mockFileInfo) ModTime() time.Time { return time.Now() }
func (m mockFileInfo) IsDir() bool        { return false }
func (m mockFileInfo) Sys() interface{}   { return nil }

func TestFileSizeFilter_FilterOut(t *testing.T) {
	// Initialize the filter
	filter := FileSizeFilter()

	// Define test cases
	testCases := []struct {
		name string // Description of the test case
		size int64  // The file size to test
		want bool   // The expected result (true = filter out, false = keep)
	}{
		{
			name: "Empty file",
			size: 0,
			want: true,
		},
		{
			name: "File just over max size",
			size: _MaxFileSize + 1,
			want: true,
		},
		{
			name: "Very large file",
			size: _MaxFileSize * 10,
			want: true,
		},
		{
			name: "File exactly at max size",
			size: _MaxFileSize,
			want: false,
		},
		{
			name: "Normal file",
			size: 1024,
			want: false,
		},
		{
			name: "Small file",
			size: 1,
			want: false,
		},
		{
			name: "File just under max size",
			size: _MaxFileSize - 1,
			want: false,
		},
		{
			name: "File with no Info",
			size: -1, // Special case to test nil Info
			want: true,
		},
	}

	// Run tests
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			mockFile := NewLocalFile("testfile", mockFileInfo{fileSize: tt.size})

			// Test the nil Info case
			if tt.size == -1 {
				mockFile = NewLocalFile("nil-info-file", nil)
			}

			got := filter.FilterOut(mockFile)
			if got != tt.want {
				t.Errorf("FilterOut(size: %d) = %v, want %v", tt.size, got, tt.want)
			}
		})
	}
}
