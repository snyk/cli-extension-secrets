package filefilter_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ff "github.com/snyk/cli-extension-secrets/pkg/filefilter"
)

func TestReadFileHeader(t *testing.T) {
	// Create a temporary directory for file operations to ensure isolation.
	tmpDir := t.TempDir()

	tests := []struct {
		name        string
		filename    string
		fileContent string
		// whether to actually create the file on disk.
		createFile    bool
		n             int64
		want          []byte
		expectError   bool
		errorContains string
	}{
		{
			name:        "Standard partial read",
			filename:    "standard.txt",
			fileContent: "Hello, World!",
			createFile:  true,
			n:           5,
			want:        []byte("Hello"),
			expectError: false,
		},
		{
			name:        "Read more than file size",
			filename:    "short.txt",
			fileContent: "Go",
			createFile:  true,
			n:           100,
			want:        []byte("Go"),
			expectError: false,
		},
		{
			name:        "Read exact size",
			filename:    "exact.txt",
			fileContent: "12345",
			createFile:  true,
			n:           5,
			want:        []byte("12345"),
			expectError: false,
		},
		{
			name:        "Read zero bytes",
			filename:    "zero_req.txt",
			fileContent: "Content exists",
			createFile:  true,
			n:           0,
			want:        []byte{},
			expectError: false,
		},
		{
			name:        "Read from empty file",
			filename:    "empty.txt",
			fileContent: "",
			createFile:  true,
			n:           10,
			want:        []byte{},
			expectError: false,
		},
		{
			name:          "File does not exist",
			filename:      "ghost.txt",
			createFile:    false,
			n:             10,
			want:          nil,
			expectError:   true,
			errorContains: "failed to open file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Construct the full path.
			path := filepath.Join(tmpDir, tt.filename)

			// Create the file if the test case requires it.
			if tt.createFile {
				err := os.WriteFile(path, []byte(tt.fileContent), 0o600)
				if err != nil {
					t.Fatalf("Failed to create test file %s: %v", path, err)
				}
			}

			got, err := ff.ReadFileHeader(path, tt.n)

			// Assert errors.
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected an error, but got nil")
				}
				// Assert error message substring.
				if tt.errorContains != "" && err != nil {
					if !strings.Contains(err.Error(), tt.errorContains) {
						t.Errorf("Expected error to contain '%s', got '%s'", tt.errorContains, err.Error())
					}
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Assert content.
			if !bytes.Equal(got, tt.want) {
				t.Errorf("Content mismatch.\nWant: %q\nGot:  %q", tt.want, got)
			}
		})
	}
}
