//go:build unix

package pathutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToRelativeUnixPathUnix(t *testing.T) {
	tests := []struct {
		name         string
		rootFolderID string
		absolutePath string
		expected     string
	}{
		{"file in src folder", `/home/dev/project`, `/home/dev/project/src/main.go`, `src/main.go`},
		{"file in config folder", `/home/dev/project`, `/home/dev/project/config/db.yml`, `config/db.yml`},
		{"file at root", `/home/dev/project`, `/home/dev/project/secrets.env`, `secrets.env`},
		{"deeply nested file", `/project`, `/project/a/b/c/d/file.txt`, `a/b/c/d/file.txt`},
		{"file in var folder", `/var/app`, `/var/app/src/index.js`, `src/index.js`},
		{"file in tmp folder", `/tmp/build`, `/tmp/build/output/file.go`, `output/file.go`},
		{"same as root", `/home/dev/project`, `/home/dev/project`, `.`},
		{"root with trailing slash", `/home/dev/project/`, `/home/dev/project/src/file.go`, `src/file.go`},
		{"relative base dir", `project`, `project/src/main.go`, `src/main.go`},
		{"relative base with dot prefix", `./project`, `./project/config/app.yml`, `config/app.yml`},
		{"relative deeply nested", `myapp/code`, `myapp/code/pkg/utils/file.go`, `pkg/utils/file.go`},
		{"relative same as root", `project`, `project`, `.`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ToRelativeUnixPath(tt.rootFolderID, tt.absolutePath)

			require.NoError(t, err, "unexpected error")
			assert.Equal(t, tt.expected, result)
		})
	}
}
