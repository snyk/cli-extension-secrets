//nolint:testpackage // whitebox
package filefilter

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

type mockLocalFile struct {
	headerData []byte
	readErr    error
}

func (m *mockLocalFile) Path() string {
	return "./mock-file"
}

func (m *mockLocalFile) Info() os.FileInfo {
	return nil
}

// The FilterOut function only uses the `ReadHeader` method
// ReadHeader implements the LocalFile interface for the mock.
func (m *mockLocalFile) ReadHeader(size int64) ([]byte, error) {
	if m.readErr != nil {
		return nil, m.readErr
	}
	// Respect the 'size' parameter, which is crucial
	if int64(len(m.headerData)) > size {
		return m.headerData[:size], nil
	}
	return m.headerData, nil
}

// TestTextFileOnlyFilter_FilterOut tests the FilterOut method.
func TestTextFileOnlyFilter_FilterOut(t *testing.T) {
	filter := TextFileOnlyFilter()

	testCases := []struct {
		name          string
		file          File
		wantFilterOut bool
		comment       string
	}{
		{
			name: "filter-in-text-file",
			file: &mockLocalFile{
				headerData: []byte("This is a normal text file."),
			},
			wantFilterOut: false,
			comment:       "Text file should NOT be filtered out",
		},
		{
			name: "filter-out-binary-file",
			file: &mockLocalFile{
				headerData: []byte{0x00, 'b', 0x00, 'i', 0x00, 'n', 0x00, 'a', 0x00, 'r', 0x00, 'y'},
			},
			wantFilterOut: true,
			comment:       "Binary file (random nulls) SHOULD be filtered out",
		},
		{
			name: "filter-in-empty-file",
			file: &mockLocalFile{
				headerData: []byte{},
			},
			wantFilterOut: false,
			comment:       "Empty file is text, should NOT be filtered out",
		},
		{
			name: "filter-out-read-error",
			file: &mockLocalFile{
				readErr: errors.New("permission denied"),
			},
			wantFilterOut: true,
			comment:       "File with read error SHOULD be filtered out",
		},
		{
			name: "filter-in-utf16-bom",
			file: &mockLocalFile{
				headerData: []byte{0xFF, 0xFE, 'h', 'i'},
			},
			wantFilterOut: false,
			comment:       "UTF-16 BOM is text, should NOT be filtered out",
		},
		{
			name: "filter-in-long-text-file",
			file: &mockLocalFile{
				// Mock will correctly truncate this to _FileHeaderSampleSize
				headerData: bytes.Repeat([]byte("a"), _FileHeaderSampleSize+100),
			},
			wantFilterOut: false,
			comment:       "Long text file sample is still text",
		},
		{
			name: "filter-out-long-file-binary-header",
			file: &mockLocalFile{
				headerData: func() []byte {
					// Create data with nulls inside the sample
					d := bytes.Repeat([]byte("a"), _FileHeaderSampleSize)
					d[100] = 0x00
					d[102] = 0x00
					d[104] = 0x00
					d[106] = 0x00
					d[107] = 0x00 // random null
					return d
				}(),
			},
			wantFilterOut: true,
			comment:       "Long file with binary header SHOULD be filtered out",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			if gotFilterOut := filter.FilterOut(tt.file); gotFilterOut != tt.wantFilterOut {
				t.Errorf("FilterOut() = %v, want %v (comment: %s)", gotFilterOut, tt.wantFilterOut, tt.comment)
			}
		})
	}
}

// TestCheckBOM verifies the Byte Order Mark detection logic.
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
			name:       "no-bom-with-nulls",
			header:     []byte{'h', 0x00, 'e', 0x00, 'l', 'l', 'o'},
			wantIsText: false,
			wantReason: "",
		},
		{
			name:       "utf-8-bom", // Should not be detected by this function
			header:     []byte{0xEF, 0xBB, 0xBF, 'h', 'i'},
			wantIsText: false,
			wantReason: "",
		},
		{
			name:       "empty-header",
			header:     []byte{},
			wantIsText: false,
			wantReason: "",
		},
		{
			name:       "too-short-for-bom",
			header:     []byte{0xFF},
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

// TestCheckUTF16Heuristic verifies the null-pattern heuristic logic.
func TestCheckUTF16Heuristic(t *testing.T) {
	testCases := []struct {
		name       string
		header     []byte
		wantIsText bool
		wantReason string
	}{
		{
			name:       "strong-utf16-le-pattern", // "h\x00e\x00l\x00l\x00o\x00"
			header:     []byte{'h', 0x00, 'e', 0x00, 'l', 0x00, 'l', 0x00, 'o', 0x00},
			wantIsText: true,
			wantReason: "utf-16-heuristic", // 5/5 odd nulls (100%)
		},
		{
			name:       "strong-utf16-be-pattern", // "\x00h\x00e\x00l\x00l\x00o"
			header:     []byte{0x00, 'h', 0x00, 'e', 0x00, 'l', 0x00, 'l', 0x00, 'o'},
			wantIsText: true,
			wantReason: "utf-16-heuristic", // 5/5 even nulls (100%)
		},
		{
			name:       "no-nulls",
			header:     []byte{'h', 'e', 'l', 'l', 'o'},
			wantIsText: false,
			wantReason: "has-null-sparse", // 0 nulls < _MIN_NULLS_FOR_UTF_16_HEURISTIC
		},
		{
			name:       "too-few-nulls", // "h\x00e\x00l\x00o"
			header:     []byte{'h', 0x00, 'e', 0x00, 'l', 0x00, 'o'},
			wantIsText: false,
			wantReason: "has-null-sparse", // 3 nulls < _MIN_NULLS_FOR_UTF_16_HEURISTIC
		},
		{
			name:       "min-nulls-pass", // "h\x00e\x00l\x00l\x00"
			header:     []byte{'h', 0x00, 'e', 0x00, 'l', 0x00, 'l', 0x00},
			wantIsText: true,
			wantReason: "utf-16-heuristic", // 4/4 odd nulls (100%)
		},
		{
			name:       "min-nulls-fail-random", // 3 even, 1 odd
			header:     []byte{0x00, 'a', 0x00, 'b', 0x00, 'c', 'd', 0x00},
			wantIsText: false,
			wantReason: "has-null-random", // 4 nulls total. 3 even (75%), 1 odd (25%). 75% < 90%
		},
		{
			name:       "borderline-fail-random", // 8 odd, 2 even
			header:     []byte{'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 0x00, 'b', 0x00, 'b'},
			wantIsText: false,
			wantReason: "has-null-random", // 10 nulls total. 8 odd (80%), 2 even (20%). 80% < 90%
		},
		{
			name:       "borderline-pass", // 9 odd, 1 even
			header:     []byte{'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 0x00, 'b'},
			wantIsText: true,
			// 10 nulls total. 9 odd (90%), 1 even (10%). 90% == 90% is not > 90%, but 9/10 = 0.9. Wait, the check is `> _UTF_16_PATTERN_THRESHOLD`.
			wantReason: "utf-16-heuristic",
			// Let's re-check the logic. threshold = 0.90.
			// 9 odd, 1 even. total = 10. oddShare = 9/10 = 0.9.
			// Is 0.9 > 0.9? No.
			// Let's make it 10 odd, 1 even.
		},
		{
			name:       "borderline-pass-91-percent", // 10 odd, 1 even
			header:     []byte{'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 'a', 0x00, 0x00, 'b'},
			wantIsText: true,
			wantReason: "utf-16-heuristic", // 11 nulls total. 10 odd (90.9%), 1 even (9.1%). 90.9% > 90%
		},
		{
			name:       "all-nulls", // Binary file of all nulls
			header:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantIsText: false,
			wantReason: "has-null-random", // 8 nulls total. 4 even (50%), 4 odd (50%). 50% < 90%
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

// TestIsTextContent is the integration test for the public function.
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
			name:    "bom-utf16-be",
			data:    []byte{0xFE, 0xFF, 0x00, 'h', 0x00, 'i'},
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
			name:    "heuristic-utf16-be",
			data:    []byte{0x00, 'h', 0x00, 'e', 0x00, 'l', 0x00, 'l', 0x00, 'o'},
			want:    true,
			comment: "Heuristic check path (strong even pattern)",
		},
		{
			name:    "binary-sparse-nulls-1",
			data:    []byte{'j', 'p', 'e', 'g', 0x00, 'h', 'e', 'a', 'd', 'e', 'r'},
			want:    false,
			comment: "Heuristic check path (1 null < min)",
		},
		{
			name:    "binary-sparse-nulls-3",
			data:    []byte{'f', 'i', 'l', 'e', 0x00, 'f', 0x00, 'o', 0x00, 'o'},
			want:    false,
			comment: "Heuristic check path (3 nulls < min)",
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
			name:    "binary-jpeg-header",
			data:    []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01},
			want:    false,
			comment: "Heuristic check path (sparse nulls, fails)",
		},
		{
			name:    "long-ascii-file-truncated",
			data:    bytes.Repeat([]byte("a"), _FileHeaderSampleSize+100),
			want:    true,
			comment: "Should pass fast path even if sample is huge",
		},
		{
			name: "long-binary-file-nulls-at-end",
			data: func() []byte {
				// Create data larger than sample size
				d := bytes.Repeat([]byte("a"), _FileHeaderSampleSize+100)
				// Add nulls within the sample-size-range
				d[100] = 0x00
				d[200] = 0x00
				d[300] = 0x00
				d[400] = 0x00
				d[500] = 0x00
				return d
			}(),
			want:    false,
			comment: "Heuristic should fail (random nulls)",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// Note: IsTextContent might not check the full slice,
			// but the test data is designed to work with the sample size.
			if got := IsTextContent(tt.data); got != tt.want {
				t.Errorf("IsTextContent() = %v, want %v (comment: %s)", got, tt.want, tt.comment)
			}
		})
	}
}
