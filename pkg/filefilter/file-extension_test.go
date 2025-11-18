//nolint:testpackage // whitebox
package filefilter

import "testing"

func TestFileExtensionFilter_FilterOut(t *testing.T) {
	filter := FileExtensionFilter()

	// Define test cases
	testCases := []struct {
		name string // Description
		path string // File path to test
		want bool   // Expected result
	}{
		// Cases that SHOULD be filtered out
		{
			name: "PNG file",
			path: "image.png",
			want: true,
		},
		{
			name: "JPG file",
			path: "path/to/photo.jpg",
			want: true,
		},
		{
			name: "JPEG file",
			path: "photo.jpeg",
			want: true,
		},
		{
			name: "SVG file",
			path: "assets/logo.svg",
			want: true,
		},
		{
			name: "RAW file",
			path: "camera/img_001.raw",
			want: true,
		},
		{
			name: "PIC file",
			path: "old_image.pic",
			want: true,
		},
		// Cases that SHOULD NOT be filtered out
		{
			name: "Go file",
			path: "main.go",
			want: false,
		},
		{
			name: "Text file",
			path: "notes.txt",
			want: false,
		},
		{
			name: "PDF file",
			path: "document.pdf",
			want: false,
		},
		{
			name: "No extension",
			path: "Dockerfile",
			want: false,
		},
		{
			name: "Dotfile",
			path: ".gitignore",
			want: false,
		},
		{
			name: "Uppercase extension (case-sensitive)",
			path: "image.PNG",
			want: false,
		},
		{
			name: "Uppercase extension 2 (case-sensitive)",
			path: "IMAGE.JPG",
			want: false,
		},
		{
			name: "Double extension",
			path: "archive.tar.gz",
			want: false,
		},
		{
			name: "Partial match",
			path: "not_a_pic.txt",
			want: false,
		},
	}

	// Run tests
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			file := NewLocalFile(tt.path, nil)
			got := filter.FilterOut(file)

			if got != tt.want {
				t.Errorf("FilterOut(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
