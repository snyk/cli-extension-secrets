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

func streamFile(t *testing.T, inputPath string) []string {
	t.Helper()
	logger := zerolog.Nop()
	return collect(streamAllowedFiles(context.Background(), []string{inputPath}, ignoreFiles, nil, getTestInvocationContext(t), &logger))
}

func TestStreamAllowedFiles_fileInputUsesAncestorRules(t *testing.T) {
	tests := []struct {
		name      string
		files     map[string]string
		inputFile string
		wantFile  bool
	}{
		{
			name:      "root gitignore applies through an empty nested gitignore",
			files:     map[string]string{".gitignore": ".env\n", "sub/.gitignore": "", "sub/.env": "x"},
			inputFile: "sub/.env",
		},
		{
			name:      "root dotsnyk exclude applies through a nested gitignore",
			files:     map[string]string{".snyk": "exclude:\n  global:\n    - '**/secret.txt'\n", "a/b/.gitignore": "*.log\n", "a/b/secret.txt": "x"},
			inputFile: "a/b/secret.txt",
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
