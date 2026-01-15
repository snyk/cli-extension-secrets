//nolint:testpackage // whitebox
package filefilter

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
)

// createTempFile is a helper to write content to a temp file and return the path.
func createTempFile(t *testing.T, content []byte) string {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "testfile")

	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	return path
}

func TestTextFileOnlyFilter_FilterOut(t *testing.T) {
	// Use a Nop logger to suppress log output during tests
	logger := zerolog.Nop()
	filter := TextFileOnlyFilter(&logger)

	testCases := []struct {
		name          string
		fileContent   []byte
		nonExistent   bool // set true to simulate read error
		wantFilterOut bool
	}{
		{
			name:          "filter-in-text-file",
			fileContent:   []byte("This is a normal text file."),
			wantFilterOut: false,
		},
		{
			name:          "filter-out-binary-file",
			fileContent:   []byte{0x00, 'b', 0x00, 'i', 0x00, 'n', 0x00, 'a', 0x00, 'r', 0x00, 'y'},
			wantFilterOut: false, // UTF-16 heuristic passes this
		},
		{
			name:          "filter-in-empty-file",
			fileContent:   []byte{},
			wantFilterOut: false,
		},
		{
			name:          "filter-out-read-error",
			nonExistent:   true,
			wantFilterOut: true, // Failed read = filter out
		},
		{
			name:          "filter-in-utf16-bom",
			fileContent:   []byte{0xFF, 0xFE, 'h', 'i'},
			wantFilterOut: false,
		},
		{
			name: "filter-in-long-text-file",
			// Create a file larger than the header sample size
			fileContent:   bytes.Repeat([]byte("a"), _FileHeaderSampleSize+100),
			wantFilterOut: false,
		},
		{
			name: "filter-out-long-file-binary-header",
			fileContent: func() []byte {
				// Create data with nulls inside the sample area
				d := bytes.Repeat([]byte("a"), _FileHeaderSampleSize+100)
				d[100] = 0x00
				d[102] = 0x00
				d[104] = 0x00
				d[106] = 0x00
				d[107] = 0x00 // random null
				return d
			}(),
			wantFilterOut: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			var path string
			if tt.nonExistent {
				path = filepath.Join(t.TempDir(), "non-existent-file")
			} else {
				path = createTempFile(t, tt.fileContent)
			}

			if gotFilterOut := filter.FilterOut(path); gotFilterOut != tt.wantFilterOut {
				t.Errorf("FilterOut() = %v, want %v", gotFilterOut, tt.wantFilterOut)
			}
		})
	}
}

// TestIsTextContent tests the public logic function logic directly.
func TestIsTextContent(t *testing.T) {
	testCases := []struct {
		name    string
		data    []byte
		want    bool
		comment string
	}{
		{
			name:    "empty-file",
			data:    []byte{},
			want:    true,
			comment: "Empty files are text",
		},
		{
			name:    "ascii-no-nulls",
			data:    []byte("This is a plain ASCII file."),
			want:    true,
			comment: "Fast path: no nulls",
		},
		{
			name:    "utf8-no-nulls",
			data:    []byte("こんにちは, world!"),
			want:    true,
			comment: "Fast path: UTF-8 with no nulls",
		},
		{
			name:    "utf8-with-bom-no-nulls",
			data:    []byte{0xEF, 0xBB, 0xBF, 'h', 'i'},
			want:    true,
			comment: "Fast path: UTF-8 BOM is fine, no nulls",
		},
		{
			name:    "bom-utf16-le",
			data:    []byte{0xFF, 0xFE, 'h', 0x00, 'i', 0x00},
			want:    true,
			comment: "BOM check path",
		},
		{
			name:    "heuristic-utf16-le",
			data:    []byte{'h', 0x00, 'e', 0x00, 'l', 0x00, 'l', 0x00, 'o', 0x00},
			want:    true,
			comment: "Heuristic check path (strong odd pattern)",
		},
		{
			name:    "binary-random-nulls",
			data:    []byte{0x00, 'a', 0x00, 'b', 0x00, 'c', 'd', 0x00, 'e', 'f'},
			want:    false,
			comment: "Heuristic check path (4 nulls, 75% even, fails)",
		},
		{
			name:    "binary-all-nulls",
			data:    []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want:    false,
			comment: "Heuristic check path (50/50 pattern, fails)",
		},
		{
			name:    "binary-png-header",
			data:    []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 'I', 'H', 'D', 'R'},
			want:    false,
			comment: "Heuristic check path (sparse nulls, fails)",
		},
		{
			name: "true-random-binary",
			data: func() []byte {
				d := make([]byte, 512)
				for i := range d {
					d[i] = byte(i % 255)
				}
				// Insert Nulls randomly to force the heuristic check.
				d[10] = 0x00
				d[15] = 0x00
				d[50] = 0x00
				d[55] = 0x00
				return d
			}(),
			want:    false,
			comment: "High variance bytes with mixed nulls",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsTextContent(tt.data); got != tt.want {
				t.Errorf("IsTextContent() = %v, want %v (%s)", got, tt.want, tt.comment)
			}
		})
	}
}

// TestCheckBOM verifies the internal Byte Order Mark detection logic.
func TestCheckBOM(t *testing.T) {
	testCases := []struct {
		name       string
		header     []byte
		wantIsText bool
		wantReason string
	}{
		{
			name:       "utf-16-le-bom",
			header:     []byte{0xFF, 0xFE, 'h', 'e', 'l', 'l', 'o'},
			wantIsText: true,
			wantReason: "utf-16-le-bom",
		},
		{
			name:       "utf-16-be-bom",
			header:     []byte{0xFE, 0xFF, 'h', 'e', 'l', 'l', 'o'},
			wantIsText: true,
			wantReason: "utf-16-be-bom",
		},
		{
			name:       "no-bom-ascii",
			header:     []byte{'h', 'e', 'l', 'l', 'o'},
			wantIsText: false,
			wantReason: "",
		},
		{
			name:       "utf-8-bom", // Not detected by this specific function
			header:     []byte{0xEF, 0xBB, 0xBF, 'h', 'i'},
			wantIsText: false,
			wantReason: "",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			gotIsText, gotReason := checkBOM(tt.header)
			if gotIsText != tt.wantIsText {
				t.Errorf("checkBOM() gotIsText = %v, want %v", gotIsText, tt.wantIsText)
			}
			if gotReason != tt.wantReason {
				t.Errorf("checkBOM() gotReason = %v, want %v", gotReason, tt.wantReason)
			}
		})
	}
}

// TestCheckUTF16Heuristic verifies the internal null-pattern heuristic logic.
func TestCheckUTF16Heuristic(t *testing.T) {
	testCases := []struct {
		name       string
		header     []byte
		wantIsText bool
		wantReason string
	}{
		{
			name:       "strong-utf16-le-pattern",
			header:     []byte{'h', 0x00, 'e', 0x00, 'l', 0x00, 'l', 0x00, 'o', 0x00},
			wantIsText: true,
			wantReason: "utf-16-heuristic",
		},
		{
			name:       "no-nulls",
			header:     []byte{'h', 'e', 'l', 'l', 'o'},
			wantIsText: false,
			wantReason: "has-null-sparse",
		},
		{
			name:       "min-nulls-fail-random",
			header:     []byte{0x00, 'a', 0x00, 'b', 0x00, 'c', 'd', 0x00},
			wantIsText: false,
			wantReason: "has-null-random",
		},
		{
			name:       "borderline-pass-91-percent", // 10 odd, 1 even
			header:     []byte{'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 0x00, 'b'},
			wantIsText: true,
			wantReason: "utf-16-heuristic",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			gotIsText, gotReason := checkUTF16Heuristic(tt.header)
			if gotIsText != tt.wantIsText {
				t.Errorf("checkUTF16Heuristic() gotIsText = %v, want %v", gotIsText, tt.wantIsText)
			}
			if gotReason != tt.wantReason {
				t.Errorf("checkUTF16Heuristic() gotReason = %v, want %v", gotReason, tt.wantReason)
			}
		})
	}
}
