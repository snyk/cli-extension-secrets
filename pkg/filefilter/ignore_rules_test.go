//nolint:testpackage,usetesting // shares helpers with the other filefilter tests
package filefilter

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/utils"
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

func streamFile(t *testing.T, inputPath string) []string {
	t.Helper()
	logger := zerolog.Nop()
	return collect(streamAllowedFiles(context.Background(), []string{inputPath}, ignoreFiles, nil, getTestInvocationContext(t), &logger))
}

// TestStreamAllowedFiles_fileInput covers single-file scans (onChange events): the rules of every
// ancestor directory apply, and nothing else does.
func TestStreamAllowedFiles_fileInput(t *testing.T) {
	const (
		dotSnykExcludeFile     = "exclude:\n  global:\n    - secret.txt\n"
		dotSnykExcludeAnywhere = "exclude:\n  global:\n    - '**/secret.txt'\n"
	)

	tests := []struct {
		name      string
		files     map[string]string
		inputFile string
		wantFile  bool
	}{
		// .gitignore
		{
			name:      "gitignored file at root is excluded",
			files:     map[string]string{".gitignore": ".env\n", ".env": "x", "main.go": "x"},
			inputFile: ".env",
		},
		{
			name:      "non-ignored file at root is included",
			files:     map[string]string{".gitignore": ".env\n", ".env": "x", "main.go": "x"},
			inputFile: "main.go",
			wantFile:  true,
		},
		{
			name:      "gitignored file in subdirectory is excluded",
			files:     map[string]string{".gitignore": ".env\n", "sub/.env": "x", "sub/config.go": "x"},
			inputFile: "sub/.env",
		},
		{
			name:      "non-ignored file in subdirectory is included",
			files:     map[string]string{".gitignore": ".env\n", "sub/config.go": "x"},
			inputFile: "sub/config.go",
			wantFile:  true,
		},
		{
			name:      "wildcard gitignore pattern excludes file",
			files:     map[string]string{".gitignore": "*.key\n", "server.key": "x"},
			inputFile: "server.key",
		},
		{
			name:      "root gitignore applies through an empty nested gitignore",
			files:     map[string]string{".gitignore": ".env\n", "sub/.gitignore": "", "sub/.env": "x"},
			inputFile: "sub/.env",
		},
		{
			name:      "nested negation overrides the parent rule",
			files:     map[string]string{".gitignore": "*.env\n", "sub/.gitignore": "!keep.env\n", "sub/keep.env": "x"},
			inputFile: "sub/keep.env",
			wantFile:  true,
		},
		{
			name:      "rule of a sibling directory does not apply",
			files:     map[string]string{"other/.gitignore": "main.go\n", "sub/main.go": "x"},
			inputFile: "sub/main.go",
			wantFile:  true,
		},
		{
			name:      "rule anchored in a nested directory does not escape it",
			files:     map[string]string{"sub/.gitignore": "/main.go\n", "main.go": "x", "sub/deeper/main.go": "x"},
			inputFile: "sub/deeper/main.go",
			wantFile:  true,
		},
		{
			name:      "files under .git are excluded",
			files:     map[string]string{".git/config": "x"},
			inputFile: ".git/config",
		},
		{
			name:      "without a git repository every ancestor is considered",
			files:     map[string]string{".gitignore": "*.log\n", "a/.gitignore": "", "a/b/.gitignore": "", "a/b/c/debug.log": "x"},
			inputFile: "a/b/c/debug.log",
		},
		// .snyk
		{
			name:      "dotsnyk global exclude is respected",
			files:     map[string]string{".snyk": dotSnykExcludeFile, "secret.txt": "x"},
			inputFile: "secret.txt",
		},
		{
			name:      "file not in any ignore list is included",
			files:     map[string]string{".gitignore": ".env\n", ".snyk": dotSnykExcludeFile, "ok.txt": "x"},
			inputFile: "ok.txt",
			wantFile:  true,
		},
		{
			name:      "root dotsnyk exclude applies through a nested gitignore",
			files:     map[string]string{".snyk": dotSnykExcludeAnywhere, "a/b/.gitignore": "*.log\n", "a/b/secret.txt": "x"},
			inputFile: "a/b/secret.txt",
		},
		{
			name:      "root dotsnyk exclude applies without any other ignore file",
			files:     map[string]string{".snyk": dotSnykExcludeAnywhere, "a/b/c/secret.txt": "x"},
			inputFile: "a/b/c/secret.txt",
		},
		{
			name:      "nested dotsnyk exclude is relative to its own directory",
			files:     map[string]string{"sub/.snyk": dotSnykExcludeFile, "sub/secret.txt": "x"},
			inputFile: "sub/secret.txt",
		},
		{
			name:      "nested dotsnyk exclude does not apply outside its directory",
			files:     map[string]string{"sub/.snyk": dotSnykExcludeFile, "secret.txt": "x"},
			inputFile: "secret.txt",
			wantFile:  true,
		},
		{
			name:      "dotsnyk secrets section is respected",
			files:     map[string]string{".snyk": "exclude:\n  secrets:\n    - 'fixtures/**'\n", "fixtures/key.txt": "x"},
			inputFile: "fixtures/key.txt",
		},
		{
			name:      "dotsnyk code section does not apply",
			files:     map[string]string{".snyk": "exclude:\n  code:\n    - 'c.txt'\n", "c.txt": "x"},
			inputFile: "c.txt",
			wantFile:  true,
		},
		{
			name:      "expired dotsnyk exclude does not apply",
			files:     map[string]string{".snyk": "exclude:\n  global:\n    - old.txt:\n        expires: 2000-01-01\n", "old.txt": "x"},
			inputFile: "old.txt",
			wantFile:  true,
		},
		{
			name:      "unexpired dotsnyk exclude applies",
			files:     map[string]string{".snyk": "exclude:\n  global:\n    - new.txt:\n        expires: 2999-01-01\n", "new.txt": "x"},
			inputFile: "new.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := setupTempDir(t, tt.files)
			inputPath := filepath.Join(root, tt.inputFile)

			got := streamFile(t, inputPath)

			if tt.wantFile {
				assert.Equal(t, []string{inputPath}, got)
			} else {
				assert.Empty(t, got)
			}
		})
	}
}

// TestStreamAllowedFiles_folderInput covers directory scans, which discover ignore files by walking down.
func TestStreamAllowedFiles_folderInput(t *testing.T) {
	logger := zerolog.Nop()
	root := setupTempDir(t, map[string]string{
		".gitignore":                    ".env\n",
		".env":                          "x",
		"main.go":                       "x",
		"sub/.env":                      "x",
		"config/.snyk":                  "exclude:\n  global:\n    - nested/app-secrets.env\n",
		"config/nested/app.env":         "x",
		"config/nested/app-secrets.env": "x",
		"nested/app-secrets.env":        "x",
		"other/nested/app-secrets.env":  "x",
	})

	got := collect(streamAllowedFiles(context.Background(), []string{root}, ignoreFiles, nil, getTestInvocationContext(t), &logger))

	assert.NotContains(t, got, filepath.Join(root, ".env"))
	assert.NotContains(t, got, filepath.Join(root, "sub", ".env"))
	assert.Contains(t, got, filepath.Join(root, "main.go"))

	// A nested .snyk is relative to its own directory: it excludes only config/nested/app-secrets.env.
	assert.NotContains(t, got, filepath.Join(root, "config", "nested", "app-secrets.env"))
	assert.Contains(t, got, filepath.Join(root, "config", "nested", "app.env"))
	assert.Contains(t, got, filepath.Join(root, "nested", "app-secrets.env"))
	assert.Contains(t, got, filepath.Join(root, "other", "nested", "app-secrets.env"))
}

func TestStreamAllowedFiles_fileInputStopsAtGitRoot(t *testing.T) {
	outer := setupTempDir(t, map[string]string{
		".gitignore":        "main.go\n",
		"repo/.git/HEAD":    "ref: refs/heads/main",
		"repo/sub/main.go":  "x",
		"repo/.gitignore":   "*.log\n",
		"repo/sub/debug.go": "x",
	})

	assert.Equal(t, []string{filepath.Join(outer, "repo", "sub", "main.go")}, streamFile(t, filepath.Join(outer, "repo", "sub", "main.go")),
		"ignore files above the repository root must not apply")
}

func TestStreamAllowedFiles_fileInputThroughDirectorySymlink(t *testing.T) {
	root := setupTempDir(t, map[string]string{
		"real/.gitignore": "*.log\n",
		"real/main.go":    "package main",
		"real/debug.log":  "noise",
	})
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(filepath.Join(root, "real"), alias); err != nil {
		t.Skipf("symlinks are not supported: %v", err)
	}

	assert.Equal(t, []string{filepath.Join(alias, "main.go")}, streamFile(t, filepath.Join(alias, "main.go")))
	assert.Empty(t, streamFile(t, filepath.Join(alias, "debug.log")))
}

func TestStreamAllowedFiles_fileInputKeepsPathAsGiven(t *testing.T) {
	root := setupTempDir(t, map[string]string{"main.go": "package main"})
	t.Chdir(root)

	assert.Equal(t, []string{"main.go"}, streamFile(t, "main.go"))
}

// TestAncestorRulesMatchGAFRules guards the copied parsing against drifting from GAF: for each flag
// combination, the rules read from the ancestors of a file must equal what GAF discovers by walking.
func TestAncestorRulesMatchGAFRules(t *testing.T) {
	logger := zerolog.Nop()
	root := setupTempDir(t, map[string]string{
		".gitignore": "# comment\n.env\n/build/\n!keep.txt\n*.log\nweird (dir)/\ncost$\nfoo/**\n.\n",
		".snyk": "exclude:\n  global:\n    - '**/secret.txt'\n    - old/*.go:\n        expires: 2000-01-01\n" +
			"    - '/abs/ignored'\n  secrets:\n    - 'fixtures/**'\n  code:\n    - 'not-for-secrets'\n",
		"sub/.gitignore": "/local.txt\nbuild\n",
		"sub/.snyk":      "exclude:\n  global:\n    - nested.txt\n",
		"sub/leaf/a.txt": "x",
	})
	leafDir := filepath.Join(root, "sub", "leaf")

	for _, tc := range []struct{ metacharacterFix, trackedFiles bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
		config := configuration.NewWithOpts()
		config.Set(utils.FF_FILE_FILTER_METACHARACTER_FIX, tc.metacharacterFix)
		config.Set(utils.FF_GITIGNORE_RESPECT_TRACKED_FILES, tc.trackedFiles)

		ictx := mocks.NewMockInvocationContext(gomock.NewController(t))
		ictx.EXPECT().GetConfiguration().Return(config).AnyTimes()

		// The walk starts at the top, so it also sees ignore files below leafDir; there are none here.
		gafFilter := utils.NewFileFilter(root, &logger, utils.WithConfig(config), utils.WithDotSnykSections(dotSnykSections))
		want, err := gafFilter.GetRules(ignoreFiles)
		require.NoError(t, err)

		_, files := ancestorIgnoreFiles(leafDir, ignoreFiles)
		got, err := newRuleParser(ictx, &logger).parseFiles(files)
		require.NoError(t, err)

		assert.Equal(t, want, append([]string{defaultGitRule}, got...),
			"metacharacterFix=%v trackedFiles=%v", tc.metacharacterFix, tc.trackedFiles)
	}
}
