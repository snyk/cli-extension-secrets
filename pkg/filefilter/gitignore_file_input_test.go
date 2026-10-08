//nolint:testpackage,usetesting // shares helpers with the other filefilter tests
package filefilter

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func collect(ch chan string) []string {
	var out []string
	for p := range ch {
		out = append(out, p)
	}
	return out
}

func TestStreamAllowedFiles_fileInput(t *testing.T) {
	tests := []struct {
		name      string
		files     map[string]string
		inputFile string
		wantFile  bool
	}{
		{
			name: "gitignored file at root is excluded",
			files: map[string]string{
				".gitignore": ".env\n",
				".env":       "TOKEN=abc",
				"main.go":    "package main",
			},
			inputFile: ".env",
			wantFile:  false,
		},
		{
			name: "non-ignored file at root is included",
			files: map[string]string{
				".gitignore": ".env\n",
				".env":       "TOKEN=abc",
				"main.go":    "package main",
			},
			inputFile: "main.go",
			wantFile:  true,
		},
		{
			name: "gitignored file in subdirectory is excluded",
			files: map[string]string{
				".gitignore":    ".env\n",
				"sub/.env":      "TOKEN=abc",
				"sub/config.go": "package sub",
			},
			inputFile: "sub/.env",
			wantFile:  false,
		},
		{
			name: "non-ignored file in subdirectory is included",
			files: map[string]string{
				".gitignore":    ".env\n",
				"sub/config.go": "package sub",
			},
			inputFile: "sub/config.go",
			wantFile:  true,
		},
		{
			name: "dotsnyk global exclude is respected",
			files: map[string]string{
				".snyk":      "exclude:\n  global:\n    - secret.txt\n",
				"secret.txt": "s3cr3t",
			},
			inputFile: "secret.txt",
			wantFile:  false,
		},
		{
			name: "file not in any ignore list is included",
			files: map[string]string{
				".gitignore": ".env\n",
				".snyk":      "exclude:\n  global:\n    - secret.txt\n",
				"ok.txt":     "hello",
			},
			inputFile: "ok.txt",
			wantFile:  true,
		},
		{
			name: "wildcard gitignore pattern excludes file",
			files: map[string]string{
				".gitignore": "*.key\n",
				"server.key": "private-key-data",
			},
			inputFile: "server.key",
			wantFile:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zerolog.Nop()
			root := setupTempDir(t, tt.files)
			inputPath := filepath.Join(root, tt.inputFile)

			got := collect(streamAllowedFiles(
				context.Background(),
				[]string{inputPath},
				ignoreFiles,
				nil,
				getTestInvocationContext(t),
				&logger,
			))

			if tt.wantFile {
				require.Len(t, got, 1)
				assert.Equal(t, inputPath, got[0])
			} else {
				assert.NotContains(t, got, inputPath)
			}
		})
	}
}

// TestStreamAllowedFiles_folderInputUnchanged verifies that folder-based scans still work
// after the file-input fix.
func TestStreamAllowedFiles_folderInputUnchanged(t *testing.T) {
	logger := zerolog.Nop()
	root := setupTempDir(t, map[string]string{
		".gitignore": ".env\n",
		".env":       "TOKEN=abc",
		"main.go":    "package main",
		"sub/.env":   "TOKEN=def",
	})
	envPath := filepath.Join(root, ".env")
	subEnvPath := filepath.Join(root, "sub", ".env")
	mainPath := filepath.Join(root, "main.go")

	got := collect(streamAllowedFiles(
		context.Background(),
		[]string{root},
		ignoreFiles,
		nil,
		getTestInvocationContext(t),
		&logger,
	))

	assert.NotContains(t, got, envPath)
	assert.NotContains(t, got, subEnvPath)
	assert.Contains(t, got, mainPath)
}
